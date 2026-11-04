//go:build filegate_e2e

package acquire

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixtureRoot = flag.String("fixture-root", "", "existing HTTP fixture artifacts")
var acquisitionOut = flag.String("acquisition-out", "", "new external artifact directory")

type acquisitionResult struct {
	Name     string         `json:"name"`
	Passed   bool           `json:"passed"`
	Expected string         `json:"expected"`
	Actual   string         `json:"actual"`
	Bytes    int64          `json:"bytes"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

type requestObservation struct {
	Protocol string `json:"protocol"`
	Identity bool   `json:"identity_encoding"`
	Clean    bool   `json:"no_implicit_headers"`
}

type zeroBody struct{}

func (zeroBody) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func observe(request *http.Request) requestObservation {
	return requestObservation{request.Proto, request.Header.Get("Accept-Encoding") == "identity",
		request.Header.Get("Range") == "" && request.Header.Get("Cookie") == "" &&
			request.Header.Get("Authorization") == "" && request.Header.Get("Referer") == ""}
}

type networkFixture struct {
	mu        sync.Mutex
	address   string
	answers   [][]netip.Addr
	hosts     []string
	dials     []string
	deadlines []float64
}

func (f *networkFixture) lookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts = append(f.hosts, host)
	if deadline, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, time.Until(deadline).Seconds())
	}
	if network != "ip" || len(f.hosts) > len(f.answers) {
		return nil, Error("FIXTURE_UNEXPECTED_LOOKUP")
	}
	return f.answers[len(f.hosts)-1], nil
}

func (f *networkFixture) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, address)
	f.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, f.address)
}

func (f *networkFixture) evidence() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]any{"dns_hosts": append([]string{}, f.hosts...), "checked_ip_dials": append([]string{}, f.dials...),
		"dns_deadline_seconds": append([]float64{}, f.deadlines...)}
}

func addresses(values ...string) []netip.Addr {
	var result []netip.Addr
	for _, value := range values {
		result = append(result, netip.MustParseAddr(value))
	}
	return result
}

func consume(ctx context.Context, target string, transport *http.Transport) (int64, string) {
	body, err := open(ctx, target, transport)
	if err != nil {
		return 0, err.Error()
	}
	n, err := io.Copy(io.Discard, body)
	closed := body.Close()
	if err != nil {
		return n, err.Error()
	}
	if closed != nil {
		return n, closed.Error()
	}
	return n, "RECEIVED_COMPLETE"
}

func rawFixture(t *testing.T, config *tls.Config, wire []byte) (string, <-chan requestObservation, func()) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	observations := make(chan requestObservation, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		observations <- observe(request)
		conn.Write(wire)
	}()
	return listener.Addr().String(), observations, func() { listener.Close(); <-done }
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAcquisitionE2E(t *testing.T) {
	if *fixtureRoot == "" || *acquisitionOut == "" {
		t.Fatal("explicit fixture and output paths are required")
	}
	if err := os.Mkdir(*acquisitionOut, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(*acquisitionOut, "inputs"), 0700); err != nil {
		t.Fatal(err)
	}
	template := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := template.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(template.Certificate())
	clientTLS := &tls.Config{RootCAs: roots}
	template.Close()
	var results []acquisitionResult
	add := func(name, expected, actual string, n int64, condition bool, evidence map[string]any) {
		passed := expected == actual && condition
		results = append(results, acquisitionResult{name, passed, expected, actual, n, evidence})
		if !passed {
			t.Errorf("%s: expected %s, got %s; checks=%t", name, expected, actual, condition)
		}
	}
	defer func() {
		writeJSON(t, filepath.Join(*acquisitionOut, "results.json"), map[string]any{
			"schema": 1, "scope": "product acquisition with real verified TLS HTTP/1 and HTTP/2; fixture-only DNS and dial routing",
			"passed": !t.Failed(), "results": results, "stage0_passed": false, "pass_enabled": false,
			"tls_verification":  "ephemeral fixture certificate trusted explicitly; hostname verification enabled",
			"external_requests": 0, "not_demonstrated": []string{"broker URL intake and VM integration", "120-second total deadline"}})
	}()
	var previous struct {
		Results []struct{ ID, Fixture, Expected string } `json:"results"`
	}
	manifest, err := os.ReadFile(filepath.Join(*fixtureRoot, "results.json"))
	if err != nil || json.Unmarshal(manifest, &previous) != nil {
		t.Fatal("existing fixture manifest unavailable")
	}
	expectedErrors := map[string]string{
		"truncated_content_length": "DOWNLOAD_INCOMPLETE", "truncated_chunked": "DOWNLOAD_INCOMPLETE", "invalid_chunk": "DOWNLOAD_INCOMPLETE",
		"conflicting_content_length": "DOWNLOAD_INCOMPLETE", "negative_content_length": "DOWNLOAD_INCOMPLETE", "oversized_header": "DOWNLOAD_INCOMPLETE",
		"te_and_cl": "DOWNLOAD_FRAMING_UNSUPPORTED", "te_and_cl_mixed_case": "DOWNLOAD_FRAMING_UNSUPPORTED",
		"close_delimited": "DOWNLOAD_FRAMING_UNSUPPORTED", "content_range": "DOWNLOAD_FRAMING_UNSUPPORTED",
		"empty_content_range": "DOWNLOAD_FRAMING_UNSUPPORTED", "encoded_body": "DOWNLOAD_FRAMING_UNSUPPORTED",
		"duplicate_encoding": "DOWNLOAD_FRAMING_UNSUPPORTED", "folded_header": "DOWNLOAD_FRAMING_UNSUPPORTED", "declared_oversize": "LIMIT_EXCEEDED",
	}
	for _, fixture := range previous.Results {
		if !strings.HasSuffix(fixture.Fixture, ".http") || fixture.ID == "baseline_te_cl_normalized" {
			continue
		}
		wire, err := os.ReadFile(filepath.Join(*fixtureRoot, fixture.Fixture))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(*acquisitionOut, fixture.Fixture), wire, 0600)
		address, requests, stop := rawFixture(t, serverTLS, wire)
		network := &networkFixture{address: address, answers: [][]netip.Addr{addresses("93.184.216.34")}}
		n, actual := consume(context.Background(), "https://example.com/fixture", newTransport(network.lookup, network.dial, clientTLS))
		stop()
		var request requestObservation
		select {
		case request = <-requests:
		default:
		}
		expected := "RECEIVED_COMPLETE"
		if fixture.Expected == "HOLD" {
			expected = expectedErrors[fixture.ID]
			if strings.HasPrefix(fixture.ID, "status_") {
				expected = "DOWNLOAD_HTTP_STATUS"
			}
		}
		evidence := network.evidence()
		evidence["request"], evidence["fixture"] = request, fixture.Fixture
		digest := sha256.Sum256(wire)
		evidence["fixture_sha256"] = hex.EncodeToString(digest[:])
		add(fixture.ID, expected, actual, n, request.Protocol == "HTTP/1.1" && request.Identity && request.Clean &&
			reflect.DeepEqual(network.dials, []string{"93.184.216.34:443"}), evidence)
	}
	for _, mode := range []string{"normal", "reset", "short_length"} {
		var input struct {
			Body                  string `json:"body"`
			DeclaredContentLength int    `json:"declared_content_length"`
		}
		path := filepath.Join("inputs", "http2_"+mode+".json")
		raw, err := os.ReadFile(filepath.Join(*fixtureRoot, path))
		if err != nil || json.Unmarshal(raw, &input) != nil {
			t.Fatal("HTTP/2 fixture unavailable")
		}
		os.WriteFile(filepath.Join(*acquisitionOut, path), raw, 0600)
		requests := make(chan requestObservation, 1)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			requests <- observe(request)
			if input.DeclaredContentLength >= 0 {
				w.Header().Set("Content-Length", "8")
			}
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, input.Body)
			w.(http.Flusher).Flush()
			if mode == "reset" {
				panic(http.ErrAbortHandler)
			}
		}))
		server.TLS = serverTLS.Clone()
		server.TLS.NextProtos = nil
		server.EnableHTTP2 = true
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		network := &networkFixture{address: server.Listener.Addr().String(), answers: [][]netip.Addr{addresses("93.184.216.34")}}
		n, actual := consume(context.Background(), "https://example.com/fixture", newTransport(network.lookup, network.dial, clientTLS))
		server.Close()
		var request requestObservation
		select {
		case request = <-requests:
		default:
		}
		expected := "DOWNLOAD_INCOMPLETE"
		if mode == "normal" {
			expected = "RECEIVED_COMPLETE"
		}
		add("http2_"+mode, expected, actual, n, request.Protocol == "HTTP/2.0" && request.Identity && request.Clean,
			map[string]any{"request": request, "fixture": path, "network": network.evidence()})
	}
	for _, values := range [][]string{{"93.184.216.34", "127.0.0.1"}, {"93.184.216.34", "::ffff:10.0.0.1"}, {"2606:4700:4700::1111", "fe80::1"}} {
		network := &networkFixture{answers: [][]netip.Addr{addresses(values...)}}
		n, actual := consume(context.Background(), "https://example.com/fixture", newTransport(network.lookup, network.dial, clientTLS))
		add("dns_all_answers_"+values[1], "DOWNLOAD_DESTINATION_DENIED", actual, n, len(network.dials) == 0, network.evidence())
	}
	for _, mode := range []string{"valid", "rebinding", "downgrade", "limit", "untrusted_certificate", "wrong_hostname"} {
		requests := make(chan requestObservation, 8)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			requests <- observe(request)
			if strings.HasPrefix(mode, "untrusted") || mode == "wrong_hostname" || mode != "limit" && request.URL.Path == "/final" {
				w.Header().Set("Content-Length", "3")
				io.WriteString(w, "abc")
				return
			}
			target := "https://example.com/final"
			if mode == "downgrade" {
				target = "http://example.com/final"
			}
			http.Redirect(w, request, target, http.StatusFound)
		}))
		server.TLS = serverTLS.Clone()
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		answers := [][]netip.Addr{addresses("93.184.216.34"), addresses("93.184.216.35")}
		if mode == "rebinding" {
			answers[1] = addresses("127.0.0.1")
		}
		if mode == "limit" {
			for len(answers) < 7 {
				answers = append(answers, addresses("93.184.216.34"))
			}
		}
		network := &networkFixture{address: server.Listener.Addr().String(), answers: answers}
		config, target := clientTLS, "https://example.com/start?synthetic=private-marker"
		if mode == "untrusted_certificate" {
			config = &tls.Config{RootCAs: x509.NewCertPool()}
		}
		if mode == "wrong_hostname" {
			target = "https://wrong.example/start"
		}
		n, actual := consume(context.Background(), target, newTransport(network.lookup, network.dial, config))
		server.Close()
		close(requests)
		var seen []requestObservation
		clean := true
		for request := range requests {
			seen = append(seen, request)
			clean = clean && request.Identity && request.Clean
		}
		expected := map[string]string{"valid": "RECEIVED_COMPLETE", "rebinding": "DOWNLOAD_DESTINATION_DENIED", "downgrade": "INVALID_URL",
			"limit": "DOWNLOAD_REDIRECT_LIMIT", "untrusted_certificate": "DOWNLOAD_TLS_FAILED", "wrong_hostname": "DOWNLOAD_TLS_FAILED"}[mode]
		counts := map[string]int{"valid": 2, "rebinding": 1, "downgrade": 1, "limit": 6, "untrusted_certificate": 0, "wrong_hostname": 0}
		clean = clean && len(seen) == counts[mode]
		if mode == "valid" {
			clean = clean && reflect.DeepEqual(network.dials, []string{"93.184.216.34:443", "93.184.216.35:443"})
		}
		if mode == "rebinding" {
			clean = clean && len(network.hosts) == 2 && len(network.dials) == 1
		}
		add("redirect_tls_"+mode, expected, actual, n, clean, map[string]any{"requests": seen, "network": network.evidence()})
	}
	for _, count := range []int64{MaxBytes, MaxBytes + 1} {
		requests := make(chan requestObservation, 1)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			requests <- observe(request)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			io.CopyN(w, zeroBody{}, count)
		}))
		server.TLS = serverTLS.Clone()
		server.TLS.NextProtos = nil
		server.EnableHTTP2 = true
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		network := &networkFixture{address: server.Listener.Addr().String(), answers: [][]netip.Addr{addresses("93.184.216.34")}}
		n, actual := consume(context.Background(), "https://example.com/fixture", newTransport(network.lookup, network.dial, clientTLS))
		server.Close()
		request := <-requests
		name, expected := "body_250_mib", "RECEIVED_COMPLETE"
		if count > MaxBytes {
			name, expected = "body_250_mib_plus_one", "LIMIT_EXCEEDED"
		}
		evidence := map[string]any{"request": request, "body": "repeated zero byte", "byte_count": count, "declared_length": false}
		writeJSON(t, filepath.Join(*acquisitionOut, "inputs", name+".json"), evidence)
		add(name, expected, actual, n, n == count && request.Protocol == "HTTP/2.0" && request.Identity && request.Clean, evidence)
	}
	ctx, cancel := context.WithCancel(context.Background())
	lookupStarted, lookupStopped := make(chan struct{}), make(chan struct{})
	cancelLookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		close(lookupStarted)
		<-ctx.Done()
		close(lookupStopped)
		return nil, ctx.Err()
	}
	cancelNetwork := &networkFixture{}
	cancelResult := make(chan string, 1)
	go func() {
		_, actual := consume(ctx, "https://example.com/fixture", newTransport(cancelLookup, cancelNetwork.dial, clientTLS))
		cancelResult <- actual
	}()
	<-lookupStarted
	cancelStarted := time.Now()
	cancel()
	cancelActual := <-cancelResult
	stopped := false
	select {
	case <-lookupStopped:
		stopped = true
	case <-time.After(time.Second):
	}
	add("cancel_stops_pending_dns", "DOWNLOAD_CANCELLED", cancelActual, 0, stopped && len(cancelNetwork.dials) == 0,
		map[string]any{"lookup_stopped": stopped, "elapsed_seconds": time.Since(cancelStarted).Seconds(), "dial_count": len(cancelNetwork.dials)})
	started := time.Now()
	var deadlineSeconds float64
	lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		deadline, bounded := ctx.Deadline()
		if !bounded {
			return nil, Error("FIXTURE_DNS_DEADLINE_ABSENT")
		}
		deadlineSeconds = time.Until(deadline).Seconds()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	network := &networkFixture{}
	n, actual := consume(context.Background(), "https://example.com/fixture", newTransport(lookup, network.dial, clientTLS))
	elapsed := time.Since(started).Seconds()
	add("dns_stall_30_seconds", "DOWNLOAD_TIMEOUT", actual, n,
		deadlineSeconds > 29 && deadlineSeconds <= 30 && elapsed >= 29 && elapsed < 35 && len(network.dials) == 0,
		map[string]any{"deadline_seconds": deadlineSeconds, "elapsed_seconds": elapsed, "dial_count": len(network.dials)})
}

func TestTotalDeadlineE2E(t *testing.T) {
	verifyBodyDeadline(t, false)
}

func TestIdleBodyDeadlineE2E(t *testing.T) {
	verifyBodyDeadline(t, true)
}

func verifyBodyDeadline(t *testing.T, idle bool) {
	if *acquisitionOut == "" {
		t.Fatal("explicit output path is required")
	}
	if err := os.MkdirAll(*acquisitionOut, 0700); err != nil {
		t.Fatal(err)
	}
	requests := make(chan requestObservation, 1)
	var sentAt []float64
	serverStarted := time.Now()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- observe(request)
		w.WriteHeader(http.StatusOK)
		if idle {
			w.(http.Flusher).Flush()
			<-request.Context().Done()
			return
		}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if _, err := io.WriteString(w, "a"); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			sentAt = append(sentAt, time.Since(serverStarted).Seconds())
			select {
			case <-request.Context().Done():
				return
			case <-ticker.C:
			}
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	network := &networkFixture{address: server.Listener.Addr().String(), answers: [][]netip.Addr{addresses("93.184.216.34")}}
	started := time.Now()
	n, actual := consume(context.Background(), "https://example.com/fixture", newTransport(network.lookup, network.dial, &tls.Config{RootCAs: roots}))
	elapsed := time.Since(started).Seconds()
	server.Close()
	request := <-requests
	maxGap := 0.0
	for i := 1; i < len(sentAt); i++ {
		maxGap = max(maxGap, sentAt[i]-sentAt[i-1])
	}
	passed := actual == "DOWNLOAD_TIMEOUT" && elapsed >= 119 && elapsed < 125 && n >= 20 &&
		maxGap < 15 && request.Protocol == "HTTP/2.0" && request.Identity && request.Clean
	id, body := "total_deadline_120_seconds", "one ASCII byte every 5 seconds until cancellation"
	if idle {
		id, body = "body_idle_deadline_30_seconds", "headers then no body bytes until cancellation"
		passed = actual == "DOWNLOAD_TIMEOUT" && elapsed >= 29 && elapsed < 35 && n == 0 &&
			request.Protocol == "HTTP/2.0" && request.Identity && request.Clean
	}
	if !passed {
		t.Errorf("%s: code=%s seconds=%.3f bytes=%d maxGap=%.3f", id, actual, elapsed, n, maxGap)
	}
	path := filepath.Join(*acquisitionOut, "results.json")
	record := map[string]any{"schema": 1, "scope": "product acquisition deadline under real verified TLS HTTP/2 traffic",
		"passed": true, "results": []any{}, "stage0_passed": false, "pass_enabled": false, "external_requests": 0}
	if raw, err := os.ReadFile(path); err == nil {
		if err = json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
	}
	record["results"] = append(record["results"].([]any), acquisitionResult{id, passed,
		"DOWNLOAD_TIMEOUT", actual, n, map[string]any{"request": request, "elapsed_seconds": elapsed,
			"body": body, "response_write_seconds": sentAt,
			"max_response_gap_seconds": maxGap}})
	record["passed"] = record["passed"].(bool) && passed
	record["not_demonstrated"] = []string{"broker URL intake and VM integration"}
	writeJSON(t, path, record)
}
