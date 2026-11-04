package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	goVersion      = "go1.27.3"
	maxHeaderBytes = 64 << 10
	maxInputBytes  = 250 << 20
)

type result struct {
	ID                  string   `json:"id"`
	Protocol            string   `json:"protocol"`
	Fixture             string   `json:"fixture"`
	Expected            string   `json:"expected"`
	ExpectedError       string   `json:"expected_error_contains,omitempty"`
	Actual              string   `json:"actual"`
	Passed              bool     `json:"passed"`
	Status              int      `json:"status"`
	Bytes               int64    `json:"bytes"`
	Error               string   `json:"error,omitempty"`
	ContentLength       int64    `json:"content_length"`
	ContentLengthHeader string   `json:"content_length_header,omitempty"`
	TransferEncoding    []string `json:"transfer_encoding,omitempty"`
	RequestIdentity     bool     `json:"request_identity"`
}

type fixture struct {
	id, wire, expected string
}

type observed struct {
	status   int
	proto    string
	bytes    int64
	cl       int64
	clHeader string
	te       []string
	err      error
	actual   string
}

// The guard inspects each HTTP/1 header block before net/http can normalize it.
type headerGuard struct {
	net.Conn
	reader      *bufio.Reader
	pending     *bytes.Reader
	headersDone bool
}

func (g *headerGuard) Read(p []byte) (int, error) {
	if g.pending != nil && g.pending.Len() > 0 {
		return g.pending.Read(p)
	}
	if g.headersDone {
		return g.reader.Read(p)
	}
	var raw bytes.Buffer
	for {
		line, err := g.reader.ReadSlice('\n')
		if err != nil {
			return 0, fmt.Errorf("header read: %w", err)
		}
		if raw.Len()+len(line) > maxHeaderBytes {
			return 0, errors.New("header limit")
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			return 0, errors.New("non-CRLF header")
		}
		raw.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	if err := inspectHeader(raw.Bytes()); err != nil {
		return 0, err
	}
	first := strings.SplitN(raw.String(), "\r\n", 2)[0]
	parts := strings.Split(first, " ")
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, errors.New("invalid response status")
	}
	g.headersDone = code < 100 || code >= 200 || code == 101
	g.pending = bytes.NewReader(raw.Bytes())
	return g.pending.Read(p)
}

func inspectHeader(raw []byte) error {
	lines := strings.Split(string(raw), "\r\n")
	status := strings.SplitN(lines[0], " ", 3)
	if len(status) < 2 || status[0] != "HTTP/1.1" && status[0] != "HTTP/1.0" {
		return errors.New("invalid response status")
	}
	cl, te := false, false
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return errors.New("invalid header field")
		}
		for _, c := range name {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return errors.New("invalid header field")
			}
		}
		cl = cl || strings.EqualFold(name, "content-length")
		te = te || strings.EqualFold(name, "transfer-encoding")
	}
	if cl && te {
		return errors.New("TE_CL_REJECTED_BEFORE_NORMALIZATION")
	}
	return nil
}

func transport(tlsConfig *tls.Config, guarded bool) *http.Transport {
	t := &http.Transport{TLSClientConfig: tlsConfig.Clone(), DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: maxHeaderBytes}
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	if guarded {
		t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := tls.Dialer{Config: t.TLSClientConfig}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &headerGuard{Conn: conn, reader: bufio.NewReaderSize(conn, maxHeaderBytes)}, nil
		}
	}
	return t
}

func fetch(client *http.Client, url string, enforce bool) observed {
	o := observed{cl: -1}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		o.err = err
		o.actual = "HOLD"
		return o
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		o.err = err
		o.actual = "HOLD"
		return o
	}
	defer response.Body.Close()
	o.status, o.proto, o.cl, o.clHeader, o.te = response.StatusCode, response.Proto, response.ContentLength, response.Header.Get("Content-Length"), response.TransferEncoding
	if enforce {
		_, hasContentRange := response.Header["Content-Range"]
		encodings := response.Header.Values("Content-Encoding")
		switch {
		case response.StatusCode != http.StatusOK:
			o.err = errors.New("DOWNLOAD_HTTP_STATUS")
		case hasContentRange:
			o.err = errors.New("DOWNLOAD_FRAMING_UNSUPPORTED: Content-Range")
		case len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(encodings[0], "identity"):
			o.err = errors.New("DOWNLOAD_FRAMING_UNSUPPORTED: Content-Encoding")
		case response.ContentLength > maxInputBytes:
			o.err = errors.New("LIMIT_EXCEEDED")
		case response.ProtoMajor == 1 && response.ContentLength < 0 && (len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked"):
			o.err = errors.New("DOWNLOAD_FRAMING_UNSUPPORTED: close-delimited")
		}
	}
	if o.err == nil {
		o.bytes, o.err = io.Copy(io.Discard, io.LimitReader(response.Body, maxInputBytes+1))
		if o.err == nil && o.bytes > maxInputBytes {
			o.err = errors.New("LIMIT_EXCEEDED")
		}
		if o.err == nil && response.ContentLength >= 0 && o.bytes != response.ContentLength {
			o.err = errors.New("DOWNLOAD_INCOMPLETE")
		}
	}
	o.actual = "RECEIVED_COMPLETE"
	if o.err != nil {
		o.actual = "HOLD"
	}
	return o
}

func rawServer(config *tls.Config, wire string) (string, <-chan bool, func(), error) {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		return "", nil, nil, err
	}
	identity := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			identity <- false
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			identity <- false
			return
		}
		identity <- request.Header.Get("Accept-Encoding") == "identity" && request.Header.Get("Range") == ""
		_, _ = io.WriteString(conn, wire)
	}()
	return "https://" + listener.Addr().String() + "/fixture", identity, func() { _ = listener.Close(); <-done }, nil
}

func makeResult(id, expected, fixturePath string, o observed, identity bool) result {
	r := result{ID: id, Protocol: o.proto, Fixture: fixturePath, Expected: expected, Actual: o.actual, Passed: expected == o.actual && identity, Status: o.status, Bytes: o.bytes, ContentLength: o.cl, ContentLengthHeader: o.clHeader, TransferEncoding: o.te, RequestIdentity: identity}
	if o.err != nil {
		r.Error = o.err.Error()
	}
	if expected == "HOLD" {
		r.ExpectedError = map[string]string{
			"truncated_content_length": "unexpected EOF", "truncated_chunked": "unexpected EOF", "invalid_chunk": "invalid byte in chunk length",
			"conflicting_content_length": "multiple Content-Length", "negative_content_length": "bad Content-Length",
			"te_and_cl": "TE_CL_REJECTED_BEFORE_NORMALIZATION", "te_and_cl_mixed_case": "TE_CL_REJECTED_BEFORE_NORMALIZATION",
			"close_delimited": "DOWNLOAD_FRAMING_UNSUPPORTED: close-delimited", "content_range": "DOWNLOAD_FRAMING_UNSUPPORTED: Content-Range",
			"encoded_body": "DOWNLOAD_FRAMING_UNSUPPORTED: Content-Encoding", "declared_oversize": "LIMIT_EXCEEDED", "folded_header": "invalid header field",
			"oversized_header": "header read: bufio: buffer full", "empty_content_range": "DOWNLOAD_FRAMING_UNSUPPORTED: Content-Range",
			"duplicate_encoding": "DOWNLOAD_FRAMING_UNSUPPORTED: Content-Encoding", "http2_reset": "stream error:", "http2_short_length": "unexpected EOF",
		}[id]
		if strings.HasPrefix(id, "status_") {
			r.ExpectedError = "DOWNLOAD_HTTP_STATUS"
		}
		r.Passed = r.Passed && r.ExpectedError != "" && strings.Contains(r.Error, r.ExpectedError)
	}
	return r
}

func shaFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func mustWrite(path string, content []byte) {
	if err := os.WriteFile(path, content, 0600); err != nil {
		panic(err)
	}
}

func main() {
	out := flag.String("out", "artifacts/local", "new local artifact directory")
	flag.Parse()
	if runtime.Version() != goVersion {
		log.Fatalf("requires %s, got %s", goVersion, runtime.Version())
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		log.Fatal("artifact directory must be new: ", err)
	}
	if err := os.Mkdir(filepath.Join(*out, "inputs"), 0700); err != nil {
		log.Fatal(err)
	}
	template := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := template.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(template.Certificate())
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	template.Close()
	fixtures := []fixture{
		{"content_length", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", "RECEIVED_COMPLETE"},
		{"content_length_zero", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "RECEIVED_COMPLETE"},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", "RECEIVED_COMPLETE"},
		{"early_hints_then_chunked", "HTTP/1.1 103 Early Hints\r\nLink: </fixture>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", "RECEIVED_COMPLETE"},
		{"truncated_content_length", "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabc", "HOLD"},
		{"truncated_chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n", "HOLD"},
		{"invalid_chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nx\r\nabc\r\n0\r\n\r\n", "HOLD"},
		{"conflicting_content_length", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc", "HOLD"},
		{"negative_content_length", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nabc", "HOLD"},
		{"te_and_cl", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n", "HOLD"},
		{"te_and_cl_mixed_case", "HTTP/1.1 200 OK\r\ntRaNsFeR-EnCoDiNg: chunked\r\ncOnTeNt-LeNgTh: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n", "HOLD"},
		{"close_delimited", "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc", "HOLD"},
		{"content_range", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Range: bytes 0-2/8\r\n\r\nabc", "HOLD"},
		{"encoded_body", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: gzip\r\n\r\nabc", "HOLD"},
		{"declared_oversize", "HTTP/1.1 200 OK\r\nContent-Length: 262144001\r\n\r\n", "HOLD"},
		{"folded_header", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n injected: value\r\n\r\nabc", "HOLD"},
		{"oversized_header", "HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", maxHeaderBytes) + "\r\nContent-Length: 3\r\n\r\nabc", "HOLD"},
		{"empty_content_range", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Range:\r\n\r\nabc", "HOLD"},
		{"duplicate_encoding", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\n\r\nabc", "HOLD"},
		{"identity_encoding", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: identity\r\n\r\nabc", "RECEIVED_COMPLETE"},
	}
	for _, status := range []int{201, 202, 204, 206, 304, 404, 500} {
		fixtures = append(fixtures, fixture{fmt.Sprintf("status_%d", status), fmt.Sprintf("HTTP/1.1 %d fixture\r\nContent-Length: 3\r\n\r\nabc", status), "HOLD"})
	}
	var results []result
	for _, f := range fixtures {
		path := filepath.Join("inputs", f.id+".http")
		mustWrite(filepath.Join(*out, path), []byte(f.wire))
		url, identity, closeServer, err := rawServer(serverTLS, f.wire)
		if err != nil {
			log.Fatal(err)
		}
		t := transport(clientTLS, true)
		o := fetch(&http.Client{Transport: t, Timeout: 5 * time.Second}, url, true)
		r := makeResult(f.id, f.expected, path, o, <-identity)
		closeServer()
		t.CloseIdleConnections()
		results = append(results, r)
	}
	baseline := fixtures[9]
	url, identity, closeServer, err := rawServer(serverTLS, baseline.wire)
	if err != nil {
		log.Fatal(err)
	}
	t := transport(clientTLS, false)
	o := fetch(&http.Client{Transport: t, Timeout: 5 * time.Second}, url, false)
	r := makeResult("baseline_te_cl_normalized", "RECEIVED_COMPLETE", "inputs/te_and_cl.http", o, <-identity)
	r.Passed = r.Passed && r.ContentLengthHeader == "" && r.ContentLength == -1 && len(r.TransferEncoding) == 1
	results = append(results, r)
	closeServer()
	t.CloseIdleConnections()
	for _, mode := range []string{"normal", "reset", "short_length"} {
		h2identity := make(chan bool, 1)
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			h2identity <- request.Header.Get("Accept-Encoding") == "identity" && request.Header.Get("Range") == ""
			if mode == "short_length" {
				w.Header().Set("Content-Length", "8")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "abc")
			w.(http.Flusher).Flush()
			if mode == "reset" {
				panic(http.ErrAbortHandler)
			}
		}))
		s.EnableHTTP2 = true
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.StartTLS()
		client := s.Client()
		client.Timeout = 5 * time.Second
		client.Transport.(*http.Transport).DisableCompression = true
		o := fetch(client, s.URL, true)
		expected := "HOLD"
		if mode == "normal" {
			expected = "RECEIVED_COMPLETE"
		}
		path := filepath.Join("inputs", "http2_"+mode+".json")
		input, _ := json.MarshalIndent(map[string]any{"server": "Go net/http TLS HTTP/2", "mode": mode, "body": "abc", "flush": true, "reset_after_flush": mode == "reset", "declared_content_length": map[string]int{"normal": -1, "reset": -1, "short_length": 8}[mode]}, "", "  ")
		mustWrite(filepath.Join(*out, path), append(input, '\n'))
		r := makeResult("http2_"+mode, expected, path, o, <-h2identity)
		r.Passed = r.Passed && r.Protocol == "HTTP/2.0"
		results = append(results, r)
		s.Close()
	}
	passed := true
	for _, r := range results {
		passed = passed && r.Passed
	}
	executable, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	buildSettings := map[string]string{}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "-buildmode", "-compiler", "-trimpath", "CGO_ENABLED", "GOARCH", "GOOS", "GOARM64", "GOEXPERIMENT":
				buildSettings[setting.Key] = setting.Value
			}
		}
	}
	for _, source := range []string{"main.go", "go.mod"} {
		content, err := os.ReadFile(source)
		if err != nil {
			log.Fatal(err)
		}
		mustWrite(filepath.Join(*out, source), content)
	}
	report := map[string]any{
		"schema_version": 1, "scope": "stage0 HTTP framing feasibility only; no product ingress enabled", "executed_at_utc": time.Now().UTC().Format(time.RFC3339Nano),
		"go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "executable_sha256": shaFile(executable),
		"build_settings": buildSettings,
		"source_sha256":  map[string]string{"main.go": shaFile("main.go"), "go.mod": shaFile("go.mod"), "net/http/transfer.go": shaFile(filepath.Join(runtime.GOROOT(), "src/net/http/transfer.go")), "net/http/transport.go": shaFile(filepath.Join(runtime.GOROOT(), "src/net/http/transport.go")), "net/http/http2.go": shaFile(filepath.Join(runtime.GOROOT(), "src/net/http/http2.go")), "net/http/internal/http2/transport.go": shaFile(filepath.Join(runtime.GOROOT(), "src/net/http/internal/http2/transport.go"))},
		"parameters":     map[string]any{"max_header_bytes": maxHeaderBytes, "max_input_bytes": maxInputBytes, "fixture_request_timeout_seconds": 5, "tls_verification": "ephemeral fixture certificate trusted explicitly; verification enabled", "listeners": "127.0.0.1 ephemeral ports", "external_requests": 0},
		"all_passed":     passed, "results": results,
		"not_demonstrated": []string{"production 30s idle/120s total deadlines", "SSRF/DNS/redirect policies", "250 MiB actual-body boundary", "expected_type identification inside VM", "initial URL expected_sha256", "upload replay/body drain and reservation (stage1)"},
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	mustWrite(filepath.Join(*out, "results.json"), append(encoded, '\n'))
	fmt.Printf("%d cases; all_passed=%t; %s\n", len(results), passed, filepath.Join(*out, "results.json"))
	if !passed {
		os.Exit(1)
	}
}
