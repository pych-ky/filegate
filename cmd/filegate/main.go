package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"filegate.local/filegate/internal/api"
	"filegate.local/filegate/internal/broker"
	"filegate.local/filegate/internal/webui"
)

type rootsFlag map[string]string

func (r rootsFlag) String() string { return "" }
func (r rootsFlag) Set(value string) error {
	id, path, ok := strings.Cut(value, "=")
	if !ok || id == "" || path == "" {
		return errors.New("INVALID_INPUT_ROOT")
	}
	if _, exists := r[id]; exists {
		return errors.New("DUPLICATE_INPUT_ROOT")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return errors.New("INVALID_INPUT_ROOT")
	}
	r[id] = abs
	return nil
}

type clientConfig struct {
	InputRoots map[string]string `json:"input_roots"`
}

func main() {
	if disableCoreDumps() != nil {
		os.Exit(failure("CORE_DUMP_POLICY_FAILED"))
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	base, err := os.UserConfigDir()
	if err != nil {
		return failure("CONFIGURATION_ERROR")
	}
	flags := flag.NewFlagSet("filegate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	data := flags.String("data-dir", filepath.Join(base, "FileGate", "app"), "")
	if flags.Parse(args) != nil {
		return failure("INVALID_ARGUMENT")
	}
	args = flags.Args()
	if len(args) == 0 {
		return failure("COMMAND_REQUIRED")
	}
	abs, err := filepath.Abs(*data)
	if err != nil {
		return failure("CONFIGURATION_ERROR")
	}
	if args[0] == "serve" {
		return serve(abs, args[1:])
	}
	if args[0] == "runtime-replace" {
		return replaceRuntime(abs, args[1:])
	}
	client := newClient(abs)
	defer client.CloseIdleConnections()
	if args[0] == "mcp" {
		return mcp(client, abs)
	}
	if args[0] == "ui" {
		return runUI(client, args[1:])
	}
	return command(client, abs, args)
}

func failure(code string) int {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version": "4", "error": code})
	return 2
}

func serve(data string, args []string) (exitCode int) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	roots := rootsFlag{}
	flags.Var(roots, "input-root", "")
	destinations := rootsFlag{}
	flags.Var(destinations, "release-destination", "")
	vmRunner := flags.String("vm-runner", "", "")
	vmWorkspace := flags.String("vm-workspace", "", "")
	vmProof := flags.String("vm-proof", "", "")
	updateLibrary := flags.String("update-library-sha256", "", "")
	shareNames := flags.Bool("share-names", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return failure("INVALID_ARGUMENT")
	}
	config := broker.Config{DataDir: data, InputRoots: roots, ReleaseDestinations: destinations, ShareNames: *shareNames}
	if *vmRunner != "" || *vmWorkspace != "" || *vmProof != "" {
		config.VM = &broker.VMConfig{RunnerPath: *vmRunner, Workspace: *vmWorkspace, Proof: *vmProof}
	}
	if *updateLibrary != "" {
		config.Update = &broker.UpdateConfig{LibrarySHA256: *updateLibrary}
	}
	b, err := broker.Open(config)
	if err != nil {
		return failure(errorCode(err))
	}
	var closeErr error
	defer func() {
		if err := b.Close(); err != nil {
			closeErr = err
		}
		if closeErr != nil {
			exitCode = failure(errorCode(closeErr))
		}
	}()
	if err := writeClientConfig(data, clientConfig{InputRoots: roots}); err != nil {
		return failure("CONFIGURATION_ERROR")
	}
	socket := filepath.Join(data, "filegate.sock")
	if st, err := os.Lstat(socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return failure("SOCKET_PATH_CONFLICT")
		}
		if err := os.Remove(socket); err != nil {
			return failure("SOCKET_PATH_CONFLICT")
		}
	} else if !os.IsNotExist(err) {
		return failure("SOCKET_PATH_CONFLICT")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return failure("SERVICE_START_FAILED")
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return failure("SERVICE_START_FAILED")
	}
	ui, err := webui.Start(api.New(b), b.DeleteOriginal)
	if err != nil {
		return failure("UI_START_FAILED")
	}
	defer func() {
		if err := ui.Close(); err != nil {
			exitCode = failure("UI_STOP_FAILED")
		}
	}()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Protocols: protocols, HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 20, MaxReadFrameSize: 16 << 10,
		MaxReceiveBufferPerConnection: 64 << 10, MaxReceiveBufferPerStream: 4 << 10}, Handler: ui.LocalHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 120 * time.Second,
		WriteTimeout: 125 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		closeErr = b.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
		close(stopped)
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		stop()
		<-stopped
		return failure("SERVICE_FAILED")
	}
	stop()
	<-stopped
	return 0
}

func writeClientConfig(data string, config clientConfig) error {
	body, err := json.Marshal(config)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(data, ".client-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err = temporary.Write(body); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temporary.Name(), filepath.Join(data, "client.json")); err != nil {
		return err
	}
	directory, err := os.Open(data)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func localInput(data, path string) (string, string, error) {
	file, err := os.OpenFile(filepath.Join(data, "client.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", "", errors.New("CONFIGURATION_ERROR")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 || info.Mode().Perm()&0077 != 0 {
		return "", "", errors.New("CONFIGURATION_ERROR")
	}
	body, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	var config clientConfig
	if err != nil || len(body) > 64<<10 || strictDecode(body, &config) != nil {
		return "", "", errors.New("CONFIGURATION_ERROR")
	}
	input, err := filepath.Abs(path)
	if err != nil || path == "" {
		return "", "", errors.New("INVALID_INPUT_PATH")
	}
	best, rootID, source := 0, "", ""
	for id, root := range config.InputRoots {
		rel, err := filepath.Rel(root, input)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) &&
			(len(root) > best || len(root) == best && (rootID == "" || id < rootID)) {
			rootID, source, best = id, rel, len(root)
		}
	}
	if rootID == "" {
		return "", "", errors.New("INPUT_ROOT_NOT_ALLOWED")
	}
	return rootID, source, nil
}

func errorCode(err error) string {
	var e *broker.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "INTERNAL_ERROR"
}

func newClient(data string) *http.Client {
	socket := filepath.Join(data, "filegate.sock")
	transport := &http.Transport{DisableKeepAlives: true, Proxy: nil, ExpectContinueTimeout: 130 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
		}}
	return &http.Client{Transport: transport, Timeout: 130 * time.Second}
}

func call(ctx context.Context, c *http.Client, method, path string, value any) (json.RawMessage, int, error) {
	var input io.Reader
	if value != nil {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, 0, err
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://filegate"+path, input)
	if err != nil {
		return nil, 0, err
	}
	if value != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if path == "/v1/jobs/url" {
		if intake, ok := value.(broker.Request); ok {
			req.Header.Set("Idempotency-Key", intake.IdempotencyKey)
		}
	}
	return receive(c, req)
}

func receive(c *http.Client, req *http.Request) (json.RawMessage, int, error) {
	response, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 || !json.Valid(body) {
		return nil, 0, errors.New("INVALID_RESPONSE")
	}
	return json.RawMessage(body), response.StatusCode, nil
}

func emit(raw json.RawMessage, status int, err error) int {
	if err != nil {
		return failure("SERVICE_UNAVAILABLE")
	}
	_, _ = fmt.Fprintln(os.Stdout, string(raw))
	if status >= 400 {
		return 2
	}
	return 0
}

func command(c *http.Client, data string, args []string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	args, metadataFromFD, err := metadataArguments(ctx, args)
	if err != nil {
		return failure(err.Error())
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	key := flags.String("idempotency-key", "", "")
	expected := flags.String("expected-type", "", "")
	hash := flags.String("expected-sha256", "", "")
	destination := flags.String("destination", "default", "")
	timeout := flags.Int("timeout", 600, "")
	requirePass := flags.Bool("require-pass", false, "")
	urlStdin := flags.Bool("url-stdin", false, "")
	cursor := flags.String("cursor", "", "")
	state := flags.String("state", "all", "")
	limit := flags.Int("limit", 100, "")
	_ = flags.Bool("json", false, "")
	positionals, options, err := splitOptions(args[1:], map[string]bool{"json": true, "require-pass": true, "url-stdin": true})
	if err != nil || flags.Parse(options) != nil {
		return failure("INVALID_ARGUMENT")
	}
	seen := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if (seen["cursor"] || seen["limit"] || seen["state"]) && args[0] != "list" {
		return failure("INVALID_ARGUMENT")
	}
	if *urlStdin && (args[0] != "submit" || len(positionals) != 1 || positionals[0] != "url") {
		return failure("INVALID_ARGUMENT")
	}
	optional := func(name string, value *string) *string {
		if seen[name] {
			return value
		}
		return nil
	}
	switch args[0] {
	case "health", "list":
		if len(positionals) != 0 {
			return failure("INVALID_ARGUMENT")
		}
		path := "/v1/jobs"
		if args[0] == "health" {
			path = "/v1/health"
		} else {
			path, err = listPath(*cursor, *limit, *state)
			if err != nil {
				return failure("INVALID_ARGUMENT")
			}
		}
		return emit(call(ctx, c, "GET", path, nil))
	case "inspect", "cancel", "rescan":
		if len(positionals) != 1 || !validID(positionals[0]) {
			return failure("INVALID_ARGUMENT")
		}
		path := "/v1/jobs/" + positionals[0]
		method := "GET"
		var body any
		if args[0] != "inspect" {
			path += "/" + args[0]
			method = "POST"
			body = struct{}{}
		}
		return emit(call(ctx, c, method, path, body))
	case "submit":
		if (!metadataFromFD && !*urlStdin) || (len(positionals) != 2 && !*urlStdin) || *key == "" {
			return failure("INVALID_ARGUMENT")
		}
		r := broker.Request{IdempotencyKey: *key, ExpectedType: optional("expected-type", expected), ExpectedSHA256: optional("expected-sha256", hash)}
		switch positionals[0] {
		case "url":
			if r.ExpectedType == nil || *r.ExpectedType == "" {
				return failure("EXPECTED_TYPE_REQUIRED")
			}
			r.SourceKind = "url"
			if *urlStdin {
				r.URL, err = readURL(ctx, os.Stdin)
				if err != nil {
					return failure(err.Error())
				}
			} else {
				r.URL = positionals[1]
			}
			return emit(call(ctx, c, "POST", "/v1/jobs/url", r))
		case "file":
			r.SourceKind = "local"
			r.RootID, r.Source, err = localInput(data, positionals[1])
			if err != nil {
				return failure(err.Error())
			}
			return emit(call(ctx, c, "POST", "/v1/jobs", r))
		case "upload":
			// stdin はメタデータ再送時に開き直すファイルを持たない。
			r.SourceKind = "upload"
			r.DisplayName = &positionals[1]
			metadata, _ := json.Marshal(r)
			req, err := http.NewRequestWithContext(ctx, "POST", "http://filegate/v1/uploads", os.Stdin)
			if err != nil {
				return failure("INVALID_ARGUMENT")
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Expect", "100-continue")
			req.Header.Set("FileGate-Metadata", base64.RawURLEncoding.EncodeToString(metadata))
			return emit(receive(c, req))
		default:
			return failure("UNSUPPORTED_INTAKE")
		}
	case "release":
		if len(positionals) != 1 || !validID(positionals[0]) || *key == "" {
			return failure("INVALID_ARGUMENT")
		}
		return emit(call(ctx, c, "POST", "/v1/releases", map[string]string{"job_id": positionals[0], "destination": *destination, "idempotency_key": *key}))
	case "release-status", "release-abort":
		if len(positionals) != 1 || !validReleaseID(positionals[0]) {
			return failure("INVALID_ARGUMENT")
		}
		path := "/v1/releases/" + positionals[0]
		if args[0] == "release-abort" {
			return emit(call(ctx, c, "POST", path+"/abort", struct{}{}))
		}
		return emit(call(ctx, c, "GET", path, nil))
	case "destinations":
		if len(positionals) != 0 {
			return failure("INVALID_ARGUMENT")
		}
		return emit(call(ctx, c, "GET", "/v1/release-destinations", nil))
	case "destination-disable":
		if len(positionals) != 1 || !validDestinationID(positionals[0]) {
			return failure("INVALID_ARGUMENT")
		}
		return emit(call(ctx, c, "POST", "/v1/release-destinations/"+positionals[0]+"/disable", struct{}{}))
	case "prune":
		if len(positionals) != 0 {
			return failure("INVALID_ARGUMENT")
		}
		return emit(call(ctx, c, "POST", "/v1/prune", struct{}{}))
	case "wait":
		if len(positionals) != 1 || !validID(positionals[0]) || *timeout < 0 || *timeout > 86400 {
			return failure("INVALID_ARGUMENT")
		}
		raw, status, err := waitJob(ctx, c, positionals[0], time.Duration(*timeout)*time.Second)
		if err != nil {
			return failure(err.Error())
		}
		if status >= 400 {
			return emit(raw, status, nil)
		}
		var result struct {
			broker.Job
			WaitTimedOut bool `json:"wait_timed_out"`
		}
		if json.Unmarshal(raw, &result) != nil {
			return failure("INVALID_RESPONSE")
		}
		_ = emit(raw, status, nil)
		if result.WaitTimedOut {
			return 40
		}
		if !*requirePass {
			return 0
		}
		if result.Verdict == "BLOCK" {
			return 20
		}
		if result.Phase != "FINISHED" {
			return 30
		}
		if result.Verdict == "PASS" {
			return 0
		}
		return 10
	default:
		return failure("UNKNOWN_COMMAND")
	}
}

func listPath(cursor string, limit int, state string) (string, error) {
	if len(cursor) > 256 || limit < 1 || limit > 100 || !broker.ValidListState(state) {
		return "", errors.New("INVALID_ARGUMENT")
	}
	query := url.Values{}
	if state != "all" {
		query.Set("state", state)
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if limit != 100 {
		query.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/jobs"
	if len(query) != 0 {
		path += "?" + query.Encode()
	}
	return path, nil
}

func readURL(ctx context.Context, input io.ReadCloser) (string, error) {
	type result struct {
		body []byte
		err  error
	}
	received := make(chan result, 1)
	go func() { body, err := io.ReadAll(io.LimitReader(input, 8195)); received <- result{body, err} }()
	select {
	case <-ctx.Done():
		input.Close()
		return "", errors.New("INPUT_INTERRUPTED")
	case value := <-received:
		if value.err != nil || len(value.body) > 8194 || !utf8.Valid(value.body) {
			return "", errors.New("INVALID_URL")
		}
		raw := strings.TrimSuffix(strings.TrimSuffix(string(value.body), "\n"), "\r")
		if len(raw) == 0 || len(raw) > 8192 || strings.ContainsAny(raw, "\r\n") {
			return "", errors.New("INVALID_URL")
		}
		return raw, nil
	}
}

func terminal(phase string) bool {
	return phase == "FINISHED" || phase == "FAILED" || phase == "CANCELLED"
}

func waitJob(ctx context.Context, client *http.Client, id string, timeout time.Duration) (json.RawMessage, int, error) {
	deadline := time.Now().Add(timeout)
	if timeout == 0 {
		deadline = time.Now().Add(time.Second)
	}
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	var last json.RawMessage
	for {
		requestContext, cancel := context.WithDeadline(ctx, deadline)
		raw, status, err := call(requestContext, client, "GET", "/v1/jobs/"+id, nil)
		cancel()
		if ctx.Err() != nil {
			return interruptedWait(ctx, last)
		}
		if err != nil {
			if len(last) != 0 && !time.Now().Before(deadline) {
				return timedOutJob(last)
			}
			return nil, 0, errors.New("WAIT_STATUS_UNAVAILABLE")
		}
		if status >= 400 {
			return raw, status, nil
		}
		var job broker.Job
		if json.Unmarshal(raw, &job) != nil || job.JobID != id || job.Phase == "" {
			return nil, 0, errors.New("INVALID_RESPONSE")
		}
		if terminal(job.Phase) {
			return raw, status, nil
		}
		last = raw
		if timeout == 0 || !time.Now().Before(deadline) {
			return timedOutJob(last)
		}
		timer := time.NewTimer(min(100*time.Millisecond, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return interruptedWait(ctx, last)
		case <-timer.C:
		}
		if !time.Now().Before(deadline) {
			return timedOutJob(last)
		}
	}
}

func interruptedWait(ctx context.Context, last json.RawMessage) (json.RawMessage, int, error) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if len(last) != 0 {
			return timedOutJob(last)
		}
		return nil, 0, errors.New("WAIT_STATUS_UNAVAILABLE")
	}
	return nil, 0, errors.New("WAIT_INTERRUPTED")
}

func timedOutJob(raw json.RawMessage) (json.RawMessage, int, error) {
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		return nil, 0, errors.New("INVALID_RESPONSE")
	}
	result["wait_timed_out"], result["job_continues"] = true, true
	result["next_action"] = "WAIT_SAME_JOB"
	reasons, _ := result["reason_codes"].([]any)
	result["reason_codes"] = append(reasons, "WAIT_TIMEOUT")
	body, err := json.Marshal(result)
	return body, http.StatusOK, err
}

func validID(id string) bool {
	return strings.HasPrefix(id, "job_") && !strings.ContainsAny(id, "/?#%\\") && len(id) <= 100
}

func validReleaseID(id string) bool {
	return strings.HasPrefix(id, "release_") && validDestinationID(id)
}

func validDestinationID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func splitOptions(args []string, boolean map[string]bool) ([]string, []string, error) {
	var positionals, options []string
	for i := 0; i < len(args); i++ {
		v := args[i]
		if v == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(v, "--") {
			positionals = append(positionals, v)
			continue
		}
		options = append(options, v)
		name := strings.TrimPrefix(v, "--")
		if strings.Contains(name, "=") || boolean[name] {
			continue
		}
		i++
		if i >= len(args) {
			return nil, nil, errors.New("INVALID_ARGUMENT")
		}
		options = append(options, args[i])
	}
	return positionals, options, nil
}

// MCP は固定ツールだけを同じ Unix API へ転送する。
func mcp(c *http.Client, data string) int {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	output := json.NewEncoder(os.Stdout)
	initialized, ready := false, false
	for scanner.Scan() {
		var r struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &r) != nil || r.JSONRPC != "2.0" {
			_ = output.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "INVALID_REQUEST"}})
			continue
		}
		if len(r.ID) == 0 {
			if r.Method == "notifications/initialized" && initialized {
				ready = true
			}
			continue
		}
		response := map[string]any{"jsonrpc": "2.0", "id": r.ID}
		if r.Method != "initialize" && r.Method != "ping" && !ready {
			response["error"] = map[string]any{"code": -32000, "message": "NOT_INITIALIZED"}
			_ = output.Encode(response)
			continue
		}
		switch r.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string         `json:"protocolVersion"`
				Capabilities    map[string]any `json:"capabilities"`
				ClientInfo      map[string]any `json:"clientInfo"`
			}
			if initialized || json.Unmarshal(r.Params, &p) != nil || p.ProtocolVersion == "" || p.Capabilities == nil || p.ClientInfo == nil {
				response["error"] = map[string]any{"code": -32602, "message": "INVALID_INITIALIZE"}
				break
			}
			initialized = true
			response["result"] = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "filegate", "version": "0.1.0-dev"}}
		case "ping":
			response["result"] = map[string]any{}
		case "tools/list":
			response["result"] = map[string]any{"tools": mcpTools()}
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
				Meta      json.RawMessage `json:"_meta"`
			}
			var meta map[string]any
			if strictDecode(r.Params, &p) != nil || len(p.Meta) != 0 && strictDecode(p.Meta, &meta) != nil {
				response["error"] = map[string]any{"code": -32602, "message": "INVALID_ARGUMENT"}
				break
			}
			if len(p.Arguments) == 0 {
				p.Arguments = json.RawMessage(`{}`)
			}
			body, status, err := mcpCall(c, data, p.Name, p.Arguments)
			if err != nil {
				code := "INVALID_ARGUMENT"
				switch err.Error() {
				case "WAIT_STATUS_UNAVAILABLE", "WAIT_INTERRUPTED", "SERVICE_UNAVAILABLE", "INVALID_RESPONSE", "CONFIGURATION_ERROR", "INVALID_INPUT_PATH", "INPUT_ROOT_NOT_ALLOWED":
					code = err.Error()
				}
				body, _ = json.Marshal(map[string]string{"error": code})
				status = 400
			}
			response["result"] = map[string]any{"content": []any{map[string]any{"type": "text", "text": string(body)}}, "isError": status >= 400}
		default:
			response["error"] = map[string]any{"code": -32601, "message": "METHOD_NOT_FOUND"}
		}
		if output.Encode(response) != nil {
			return 2
		}
	}
	if scanner.Err() != nil {
		return 2
	}
	return 0
}

func strictDecode(raw []byte, v any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' || !utf8.Valid(raw) {
		return errors.New("INVALID_ARGUMENT")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("INVALID_ARGUMENT")
	}
	return nil
}

func mcpTools() []any {
	var tools []any
	for _, name := range []string{"list_jobs", "get_job", "wait_job", "cancel_job", "rescan_job", "release_file", "get_release", "abort_release", "submit_file", "submit_url"} {
		properties := map[string]any{}
		required := []string{}
		if name != "list_jobs" && name != "submit_file" && name != "submit_url" && name != "get_release" && name != "abort_release" {
			properties["job_id"] = map[string]string{"type": "string"}
			required = append(required, "job_id")
		}
		if name == "release_file" {
			for _, field := range []string{"destination_id", "idempotency_key"} {
				properties[field] = map[string]string{"type": "string"}
				required = append(required, field)
			}
		}
		if name == "get_release" || name == "abort_release" {
			properties["release_id"] = map[string]string{"type": "string"}
			required = []string{"release_id"}
		}
		if name == "submit_file" {
			for _, field := range []string{"path", "idempotency_key", "expected_type", "expected_sha256"} {
				properties[field] = map[string]string{"type": "string"}
			}
			required = []string{"path", "idempotency_key"}
		}
		if name == "submit_url" {
			for _, field := range []string{"url", "idempotency_key", "expected_type", "expected_sha256"} {
				properties[field] = map[string]string{"type": "string"}
			}
			required = []string{"url", "expected_type", "idempotency_key"}
		}
		if name == "wait_job" {
			properties["timeout"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 30, "default": 30}
		}
		if name == "list_jobs" {
			properties["state"] = map[string]any{"type": "string", "enum": []string{"all", "active", "PASS", "HOLD", "BLOCK", "stale"}, "default": "all"}
			properties["cursor"] = map[string]any{"type": "string", "maxLength": 256}
			properties["limit"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 100}
		}
		tools = append(tools, map[string]any{"name": name, "description": name, "inputSchema": map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}})
	}
	return tools
}

func mcpCall(c *http.Client, data, name string, args json.RawMessage) (json.RawMessage, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var values map[string]json.RawMessage
	if strictDecode(args, &values) != nil {
		return nil, 0, errors.New("INVALID_ARGUMENT")
	}
	for _, value := range values {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, 0, errors.New("INVALID_ARGUMENT")
		}
	}
	if name == "submit_url" {
		var p struct {
			URL          string  `json:"url"`
			Key          string  `json:"idempotency_key"`
			ExpectedType string  `json:"expected_type"`
			Hash         *string `json:"expected_sha256"`
		}
		if strictDecode(args, &p) != nil || p.URL == "" || p.Key == "" || p.ExpectedType == "" {
			return nil, 0, errors.New("INVALID_ARGUMENT")
		}
		return call(ctx, c, "POST", "/v1/jobs/url", broker.Request{SourceKind: "url", URL: p.URL, IdempotencyKey: p.Key, ExpectedType: &p.ExpectedType, ExpectedSHA256: p.Hash})
	}
	if name == "submit_file" {
		var p struct {
			Path         string  `json:"path"`
			Key          string  `json:"idempotency_key"`
			ExpectedType *string `json:"expected_type"`
			Hash         *string `json:"expected_sha256"`
		}
		if err := strictDecode(args, &p); err != nil {
			return nil, 0, err
		}
		if p.Path == "" || p.Key == "" {
			return nil, 0, errors.New("INVALID_ARGUMENT")
		}
		rootID, source, err := localInput(data, p.Path)
		if err != nil {
			return nil, 0, err
		}
		return call(ctx, c, "POST", "/v1/jobs", broker.Request{SourceKind: "local", RootID: rootID, Source: source, IdempotencyKey: p.Key, ExpectedType: p.ExpectedType, ExpectedSHA256: p.Hash})
	}
	if name == "wait_job" {
		var p struct {
			JobID   string `json:"job_id"`
			Timeout *int   `json:"timeout"`
		}
		if strictDecode(args, &p) != nil || !validID(p.JobID) {
			return nil, 0, errors.New("INVALID_ARGUMENT")
		}
		timeout := 30
		if p.Timeout != nil {
			timeout = *p.Timeout
		}
		if timeout < 0 || timeout > 30 {
			return nil, 0, errors.New("INVALID_ARGUMENT")
		}
		return waitJob(ctx, c, p.JobID, time.Duration(timeout)*time.Second)
	}
	if name == "get_release" || name == "abort_release" {
		var p struct {
			ReleaseID string `json:"release_id"`
		}
		if strictDecode(args, &p) != nil || !validReleaseID(p.ReleaseID) {
			return nil, 0, errors.New("INVALID_ARGUMENT")
		}
		path := "/v1/releases/" + p.ReleaseID
		if name == "abort_release" {
			return call(ctx, c, "POST", path+"/abort", struct{}{})
		}
		return call(ctx, c, "GET", path, nil)
	}
	if name == "release_file" {
		var p struct {
			JobID       string `json:"job_id"`
			Destination string `json:"destination_id"`
			Key         string `json:"idempotency_key"`
		}
		if err := strictDecode(args, &p); err != nil {
			return nil, 0, err
		}
		return call(ctx, c, "POST", "/v1/releases", map[string]string{"job_id": p.JobID, "destination": p.Destination, "idempotency_key": p.Key})
	}
	if name == "list_jobs" {
		var p struct {
			Cursor string  `json:"cursor"`
			Limit  *int    `json:"limit"`
			State  *string `json:"state"`
		}
		if err := strictDecode(args, &p); err != nil {
			return nil, 0, err
		}
		limit := 100
		if p.Limit != nil {
			limit = *p.Limit
		}
		state := "all"
		if p.State != nil {
			state = *p.State
		}
		path, err := listPath(p.Cursor, limit, state)
		if err != nil {
			return nil, 0, err
		}
		return call(ctx, c, "GET", path, nil)
	}
	var p struct {
		JobID string `json:"job_id"`
	}
	if err := strictDecode(args, &p); err != nil || !validID(p.JobID) {
		return nil, 0, errors.New("INVALID_ARGUMENT")
	}
	path := "/v1/jobs/" + p.JobID
	switch name {
	case "get_job":
		return call(ctx, c, "GET", path, nil)
	case "cancel_job":
		return call(ctx, c, "POST", path+"/cancel", struct{}{})
	case "rescan_job":
		return call(ctx, c, "POST", path+"/rescan", struct{}{})
	}
	return nil, 0, errors.New("UNKNOWN_TOOL")
}
