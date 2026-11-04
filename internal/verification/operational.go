package verification

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var privateMarkers = map[string]string{"body": "FG_SYNTHETIC_PRIVATE_BODY_20261029", "filename": "FG_SYNTHETIC_PRIVATE_FILENAME_20261029", "entry": "FG_SYNTHETIC_PRIVATE_ENTRY_20261029", "path": "FG_SYNTHETIC_PRIVATE_PATH_20261029", "password": "FG_SYNTHETIC_PRIVATE_PASSWORD_20261029", "query": "FG_SYNTHETIC_PRIVATE_QUERY_20261029", "token": "FG_SYNTHETIC_PRIVATE_TOKEN_20261029", "http_error_body": "synthetic error body must not become an original"}
var privateBody = []byte(privateMarkers["body"] + "\n" + privateMarkers["password"] + "\n")

func init() {
	Register("operational", runOperational)
	Register("privacy", func(h *Harness) { h.Mode = "privacy"; runOperational(h) })
	Register("privacy-api", func(h *Harness) { h.Mode = "privacy-api"; runOperational(h) })
	Register("install", func(h *Harness) { h.Mode = "install"; runOperational(h) })
}
func NetworkFactory(info Object) string {
	return `package acquire
import ("context"; "crypto/tls"; "crypto/x509"; "fmt"; "net"; "net/http"; "net/netip")
func transport() *http.Transport {
 roots := x509.NewCertPool()
 if !roots.AppendCertsFromPEM([]byte(` + string(Encoded(Str(info, "certificate"))) + `)) { panic("fixture certificate invalid") }
 lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
  if network != "ip" || host != "example.com" { return nil, fmt.Errorf("fixture host invalid") }
  return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
 }
 dial := func(ctx context.Context, network, address string) (net.Conn, error) {
  if network != "tcp" || address != "93.184.216.34:443" { return nil, fmt.Errorf("fixture dial invalid") }
  return (&net.Dialer{}).DialContext(ctx, network, ` + string(Encoded(Str(info, "address"))) + `)
 }
 return newTransport(lookup, dial, &tls.Config{RootCAs: roots})
}
`
}
func StartNetworkFixture(h *Harness) (Object, func()) {
	binary := filepath.Join(h.Out, "tls-fixture")
	result := Execute(h.Root, []string{"go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./experiments/product/url_fixture"}, nil, 3*time.Minute)
	Write(filepath.Join(h.Out, "tls-fixture-build.log"), append(result.Stdout, result.Stderr...))
	h.Check("tls_fixture_build", result.ExitCode == 0)
	h.Record["fixture_binary_sha256"] = FileDigest(binary)
	cmd := exec.Command(binary)
	stdout, err := cmd.StdoutPipe()
	Must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	Must(cmd.Start())
	reader := bufio.NewReader(stdout)
	type lineResult struct {
		body []byte
		err  error
	}
	first := make(chan lineResult, 1)
	go func() { line, err := reader.ReadBytes('\n'); first <- lineResult{line, err} }()
	var info Object
	select {
	case line := <-first:
		Must(line.err)
		info = Decode(line.body)
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		panic(Failure{"tls_fixture_start_timeout"})
	}
	return info, func() {
		Must(cmd.Process.Signal(syscall.SIGTERM))
		finished := make(chan lineResult, 1)
		go func() {
			line, err := io.ReadAll(reader)
			if err == nil {
				err = cmd.Wait()
			}
			finished <- lineResult{line, err}
		}()
		select {
		case line := <-finished:
			h.Record["tls_fixture_stopped"] = line.err == nil && stderr.Len() == 0
			h.Check("tls_fixture_stopped", line.err == nil && stderr.Len() == 0)
			h.Record["tls_fixture_counts"] = Decode(bytes.TrimSpace(line.body))["counts"]
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-finished
			h.Record["tls_fixture_stopped"] = false
			panic(Failure{"tls_fixture_stop_timeout"})
		}
	}
}

type operational struct {
	h                  *Harness
	observations, argv []Object
	ui                 *UIClient
}

func (s *operational) observe(name string, status int, value any) {
	body := string(Encoded(value))
	if s.ui != nil {
		for _, token := range []string{s.ui.bootstrap, s.ui.session} {
			if token != "" {
				body = strings.ReplaceAll(body, token, "[REDACTED_UI_AUTH]")
			}
		}
	}
	s.observations = append(s.observations, Object{"name": name, "status": status, "response": Decode([]byte(`{"value":` + body + `}`))["value"]})
	WriteJSON(filepath.Join(s.h.Out, "observations.json"), s.observations)
}
func (s *operational) argvObserve(cmd *exec.Cmd, name string) {
	r := Execute(s.h.Root, []string{"/bin/ps", "-p", fmt.Sprint(cmd.Process.Pid), "-o", "command="}, nil, 5*time.Second)
	s.h.Check(name+"_argv_available", r.ExitCode == 0 && len(bytes.TrimSpace(r.Stdout)) > 0)
	matches := []string{}
	for label, marker := range privateMarkers {
		if bytes.Contains(r.Stdout, []byte(marker)) {
			matches = append(matches, label)
		}
	}
	s.argv = append(s.argv, Object{"name": name, "pid": cmd.Process.Pid, "bytes": len(r.Stdout), "sha256": Digest(r.Stdout), "marker_matches": matches})
	WriteJSON(filepath.Join(s.h.Out, "argv-observations.json"), s.argv)
	s.h.Check(name+"_argv_has_no_synthetic_secrets", len(matches) == 0)
}

func (s *operational) mcpObserved(messages []Object) (int, map[int64]Object) {
	cmd := exec.Command(s.h.Binary, "--data-dir", s.h.Data, "mcp")
	stdin, err := cmd.StdinPipe()
	Must(err)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	Must(cmd.Start())
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	s.argvObserve(cmd, "mcp")
	for _, message := range messages {
		_, err = stdin.Write(append(Encoded(message), '\n'))
		Must(err)
	}
	Must(stdin.Close())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		waited = true
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		waited = true
		panic(Failure{"mcp_timeout"})
	}
	s.h.Responses = append(s.h.Responses, stdout.Bytes(), stderr.Bytes())
	replies := map[int64]Object{}
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte{'\n'}) {
		if len(line) > 0 {
			reply := Decode(line)
			replies[Int(reply, "id")] = reply
		}
	}
	return cmd.ProcessState.ExitCode(), replies
}
func (s *operational) metadata(kind string, metadata Object, body []byte, observe bool) (int, Object) {
	if !observe {
		source := Str(metadata, "source")
		copy := Object{}
		for k, v := range metadata {
			if k != "source" {
				copy[k] = v
			}
		}
		code, value := s.h.Submit(kind, source, copy, body)
		s.observe(fmt.Sprint("cli_", kind, "_", len(s.observations)), code, value)
		return code, value
	}
	file, err := os.CreateTemp(s.h.Out, "metadata-*.json")
	Must(err)
	defer os.Remove(file.Name())
	defer file.Close()
	_, err = file.Write(Encoded(metadata))
	Must(err)
	_, err = file.Seek(0, 0)
	Must(err)
	Must(s.h.Process.Process.Signal(syscall.SIGSTOP))
	resumed := false
	defer func() {
		if !resumed {
			_ = s.h.Process.Process.Signal(syscall.SIGCONT)
		}
	}()
	cmd := exec.Command(s.h.Binary, "--data-dir", s.h.Data, "submit", kind, "--metadata-fd", "3")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	Must(cmd.Start())
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	s.argvObserve(cmd, "cli_"+kind)
	Must(s.h.Process.Process.Signal(syscall.SIGCONT))
	resumed = true
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		waited = true
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		waited = true
		panic(Failure{"metadata_cli_timeout"})
	}
	s.h.Responses = append(s.h.Responses, stdout.Bytes(), stderr.Bytes())
	code := cmd.ProcessState.ExitCode()
	value := Decode(stdout.Bytes())
	s.observe(fmt.Sprint("cli_", kind, "_", len(s.observations)), code, value)
	return code, value
}
func (s *operational) apiErrors() {
	cases := []struct {
		path  string
		value Object
		code  string
	}{{"/v1/jobs", Object{"source_kind": "local", "root_id": "fixture", "source": "../" + privateMarkers["path"], "idempotency_key": "privacy-traversal"}, "INVALID_INPUT_PATH"}, {"/v1/jobs/url", Object{"source_kind": "url", "url": "https://user:" + privateMarkers["password"] + "@example.com/a?" + privateMarkers["query"], "expected_type": "txt", "idempotency_key": "privacy-api-invalid"}, "INVALID_URL"}}
	requests := []Object{}
	for _, test := range cases {
		headers := map[string]string{"Idempotency-Key": Str(test.value, "idempotency_key")}
		requests = append(requests, Object{"method": "POST", "path": test.path, "headers": headers, "body": test.value, "expected_status": 400, "expected_error": test.code})
		WriteJSON(filepath.Join(s.h.Out, "api-requests.json"), requests)
		status, value := s.h.Request("POST", test.path, test.value, headers, nil)
		s.observe("api_"+strings.ToLower(test.code), status, value)
		s.h.Check("api_rejects_"+strings.ToLower(test.code), status == 400 && ErrorCode(value) == test.code)
	}
}
func (s *operational) noMarkers(name string) {
	matches := []string{}
	combined := bytesJoin(s.h.Logs, s.h.Responses)
	for label, marker := range privateMarkers {
		if bytes.Contains(combined, []byte(marker)) {
			matches = append(matches, label)
		}
	}
	s.h.Check(name, len(matches) == 0, Object{"matched_labels": matches})
	Write(filepath.Join(s.h.Out, "service-output.bin"), bytesJoin(s.h.Logs))
}
func runOperational(h *Harness) {
	h.Record["mode"] = h.Mode
	h.Record["vm_executed"] = false
	h.Record["gui_executed"] = false
	h.Check("operational_mode", h.Mode == "privacy" || h.Mode == "privacy-api" || h.Mode == "install")
	s := &operational{h: h}
	if h.Mode == "install" {
		runInstall(s)
		return
	}
	WriteJSON(filepath.Join(h.Out, "synthetic-markers.json"), privateMarkers)
	if h.Mode == "privacy" {
		info, close := StartNetworkFixture(h)
		defer close()
		h.Binary = filepath.Join(h.Out, "filegate-private-fixture")
		path := filepath.Join(h.Root, "internal/acquire/network.go")
		BuildOverlay(h, "network", h.Binary, map[string]string{path: NetworkFactory(info)})
		h.Record["network_scope"] = "test-only lookup/dial/root CA; production validation and TLS retained; no Internet request"
	} else {
		h.Record["network_scope"] = "URL rejected during validation before intake; no network fixture or transport override"
	}
	if h.Mode == "privacy-api" {
		health := h.Start()
		h.Check("gates_closed", GatesClosed(health))
		s.apiErrors()
		status, jobs := h.Request("GET", "/v1/jobs", nil, nil, nil)
		counts := Object{}
		empty := true
		for _, table := range []string{"jobs", "objects", "reservations"} {
			count := h.Query("SELECT count(*) FROM " + table)[0][0]
			counts[table] = count
			empty = empty && count == int64(0)
		}
		partial, err := os.ReadDir(filepath.Join(h.Data, "partial"))
		Must(err)
		objects, err := os.ReadDir(filepath.Join(h.Data, "objects"))
		Must(err)
		counts["partial_files"] = len(partial)
		counts["original_files"] = len(objects)
		s.observe("rejected_requests_leave_no_input", status, counts)
		h.Check("rejected_requests_leave_no_input", status == 200 && len(List(jobs, "jobs")) == 0 && empty && len(partial) == 0 && len(objects) == 0)
		h.Stop(false)
		s.noMarkers("synthetic_secrets_absent_from_api_responses_and_logs")
		return
	}
	s.privacy()
}
func (s *operational) privacy() {
	h := s.h
	fixture := filepath.Join(h.InputDirectory, privateMarkers["path"]+".txt")
	Write(fixture, privateBody)
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	entry, err := z.CreateHeader(&zip.FileHeader{Name: privateMarkers["entry"] + ".txt", Method: zip.Store})
	Must(err)
	_, err = entry.Write(privateBody)
	Must(err)
	Must(z.Close())
	Write(filepath.Join(h.Out, "synthetic.zip"), archive.Bytes())
	Write(filepath.Join(h.Out, "synthetic.txt"), privateBody)
	health := h.Start()
	h.Check("gates_closed", GatesClosed(health))
	s.argvObserve(h.Process, "broker")
	code, receipt := s.metadata("file", Object{"source": fixture, "idempotency_key": "privacy-cli-file", "expected_type": "txt"}, nil, true)
	id := Str(receipt, "job_id")
	h.Check("cli_file_committed_without_argv_path", code == 0 && Str(receipt, "input_receipt", "sha256") == Digest(privateBody))
	code, receipt = s.metadata("upload", Object{"source": privateMarkers["filename"] + ".zip", "idempotency_key": "privacy-cli-upload", "expected_type": "zip"}, archive.Bytes(), true)
	h.Check("cli_upload_committed_without_argv_name", code == 0 && Str(receipt, "input_receipt", "sha256") == Digest(archive.Bytes()))
	code, value := s.metadata("file", Object{"source": fixture, "idempotency_key": "privacy-invalid", "unexpected": privateMarkers["token"]}, nil, false)
	h.Check("cli_metadata_rejects_unknown_fields", code == 2 && ErrorCode(value) == "INVALID_ARGUMENT")
	code, _ = s.metadata("file", Object{"source": filepath.Join(h.InputDirectory, privateMarkers["filename"]+".missing"), "idempotency_key": "privacy-missing"}, nil, false)
	h.Check("cli_missing_file_has_normalized_error", code != 0)
	code, value = h.CLIInput(Encoded(Object{"source": fixture, "idempotency_key": "privacy-stdin-file"}), "submit", "file", "--metadata-fd", "0")
	s.observe("cli_metadata_stdin", code, value)
	h.Check("cli_metadata_stdin_supported", code == 0 && Str(value, "input_receipt", "sha256") == Digest(privateBody))
	targetURL := "https://example.com/status?signature=" + privateMarkers["query"]
	code, receipt = s.metadata("url", Object{"source": targetURL, "idempotency_key": "privacy-url-error", "expected_type": "txt"}, nil, true)
	h.Check("url_error_fixture_accepted", code == 0)
	job := h.WaitJob(Str(receipt, "job_id"), true)
	s.observe("url_error_terminal", 200, job)
	h.Check("http_error_body_not_an_original", Str(job, "phase") == "FAILED" && Get(job, "input_receipt") == nil && Contains(Get(job, "execution_errors"), "DOWNLOAD_HTTP_STATUS"))
	code, replay := h.CLIInput([]byte(targetURL+"\n"), "submit", "url", "--url-stdin", "--expected-type", "txt", "--idempotency-key", "privacy-url-error")
	s.observe("url_stdin_replay", code, replay)
	replayID := Str(replay, "job_id")
	if replayID == "" {
		replayID = Str(replay, "error", "receipt", "job_id")
	}
	h.Check("legacy_url_stdin_retains_same_job", replayID == Str(receipt, "job_id"))
	messages := append(MCPInit(), MCPCall(2, "submit_file", Object{"path": fixture, "idempotency_key": "privacy-mcp"}), MCPCall(3, "submit_url", Object{"url": "https://user:" + privateMarkers["password"] + "@example.com/a?" + privateMarkers["query"], "expected_type": "txt", "idempotency_key": "privacy-mcp-invalid"}), MCPCall(4, "get_job", Object{"job_id": id, "unexpected": privateMarkers["token"]}))
	code, replies := s.mcpObserved(messages)
	s.observe("mcp", code, replies)
	h.Check("mcp_success_and_normalized_errors", code == 0 && Get(replies[2], "result", "isError") == false && Bool(replies[3], "result", "isError") && Bool(replies[4], "result", "isError"))
	s.apiErrors()
	status, bootstrap := h.Request("POST", "/v1/ui/bootstrap", Object{}, nil, nil)
	target, err := url.Parse(Str(bootstrap, "url"))
	Must(err)
	s.ui = &UIClient{H: h, Origin: "http://" + target.Host, bootstrap: target.Fragment}
	s.ui.Authenticate()
	h.Check("ui_internal_authentication", status == 200 && s.ui.session != "")
	uiRequest := func(method, path string, body []byte, headers map[string]string, auth bool) (int, Object) {
		status, _, raw := s.ui.Request(method, path, body, headers, auth, true, true)
		h.Responses = append(h.Responses, raw)
		value := Decode(raw)
		s.observe(fmt.Sprint("ui_", len(s.observations)), status, value)
		return status, value
	}
	metadata := Object{"source_kind": "upload", "display_name": privateMarkers["filename"] + ".txt", "expected_type": "txt", "idempotency_key": "privacy-ui"}
	status, value = uiRequest("POST", "/v1/jobs/file", privateBody, map[string]string{"Content-Type": "application/octet-stream", "Idempotency-Key": "privacy-ui", "X-FileGate-Metadata": base64Raw(metadata)}, true)
	h.Check("ui_file_committed", status == 202 && Str(value, "input_receipt", "sha256") == Digest(privateBody))
	status, _ = uiRequest("GET", "/v1/jobs", nil, map[string]string{"Authorization": "Bearer " + privateMarkers["token"]}, false)
	h.Check("ui_invalid_auth_normalized", status == 401)
	status, _ = uiRequest("POST", "/v1/jobs/url", Encoded(Object{"source_kind": "url", "url": "file:///" + privateMarkers["path"], "expected_type": "txt", "idempotency_key": "privacy-ui-invalid"}), map[string]string{"Content-Type": "application/json", "Idempotency-Key": "privacy-ui-invalid"}, true)
	h.Check("ui_url_error_normalized", status == 400)
	for _, path := range []string{"/v1/health", "/v1/jobs", "/v1/jobs/" + id} {
		uiRequest("GET", path, nil, nil, true)
	}
	h.CLI("health")
	h.CLI("list")
	h.CLI("inspect", id)
	uiRequest("POST", "/ui/logout", nil, nil, true)
	h.Stop(false)
	s.noMarkers("synthetic_secrets_absent_from_logs_responses_diagnostics")
	s.ui.CheckLogs()
}
func base64Raw(value any) string { return base64.RawURLEncoding.EncodeToString(Encoded(value)) }
func runInstall(s *operational) {
	h := s.h
	second, installer := filepath.Join(h.Out, "filegate-update"), filepath.Join(h.Out, "filegate-install")
	for _, build := range []struct{ target, pkg, ld string }{{installer, "./cmd/filegate-install", ""}, {second, "./cmd/filegate", "-ldflags=-buildid=filegate-local-update-fixture"}} {
		args := []string{"go", "build", "-trimpath", "-buildvcs=false"}
		if build.ld != "" {
			args = append(args, build.ld)
		}
		args = append(args, "-o", build.target, build.pkg)
		result := Execute(h.Root, args, nil, 3*time.Minute)
		Write(build.target+".build.log", append(result.Stdout, result.Stderr...))
		h.Check("install_fixture_build_"+filepath.Base(build.target), result.ExitCode == 0)
	}
	first := h.Binary
	hashes := []string{FileDigest(first), FileDigest(second)}
	h.Check("update_uses_a_distinct_binary", hashes[0] != hashes[1])
	prefix := filepath.Join(h.Temporary, "installed")
	invoke := func(binary, expected string, success bool) {
		r := Execute(h.Root, []string{installer, "--source", binary, "--sha256", expected, "--prefix", prefix}, nil, 20*time.Second)
		value := Decode(r.Stdout)
		s.observe(fmt.Sprint("install_", len(s.observations)), r.ExitCode, value)
		h.Check(fmt.Sprint("install_result_", len(s.observations)), (r.ExitCode == 0) == success && Get(value, "installed") == success && len(r.Stderr) == 0)
	}
	invoke(first, hashes[0], true)
	installed := filepath.Join(prefix, "current/filegate")
	info, err := os.Stat(installed)
	Must(err)
	h.Check("initial_install_hash_and_permissions", FileDigest(installed) == hashes[0] && info.Mode().Perm() == 0500)
	h.Binary = installed
	health := h.Start()
	h.Check("installed_service_gates_closed", Get(health, "pass_enabled") == false && Get(health, "release_enabled") == false)
	input := filepath.Join(h.InputDirectory, "synthetic.txt")
	Write(input, privateBody)
	code, receipt := s.metadata("file", Object{"source": input, "idempotency_key": "install-state"}, nil, false)
	h.Check("installed_service_commits_input", code == 0)
	invoke(first, hashes[0], true)
	invoke(second, hashes[1], true)
	link, err := os.Readlink(filepath.Join(prefix, "current"))
	Must(err)
	h.Check("atomic_update_retains_previous_binary", link == "versions/"+hashes[1] && FileDigest(filepath.Join(prefix, "versions", hashes[0], "filegate")) == hashes[0] && h.ServiceAlive())
	code, value := h.CLI("health")
	h.Check("updated_cli_connects_existing_service", code == 0 && Get(value, "release_enabled") == false)
	h.Stop(false)
	h.Start()
	code, replay := s.metadata("file", Object{"source": input, "idempotency_key": "install-state"}, nil, false)
	h.Check("updated_service_preserves_original_receipt", code == 0 && Bool(replay, "replayed") && Str(replay, "job_id") == Str(receipt, "job_id") && Equal(replay["input_receipt"], receipt["input_receipt"]))
	invoke(first, strings.Repeat("0", 64), false)
	link, err = os.Readlink(filepath.Join(prefix, "current"))
	Must(err)
	h.Check("hash_failure_does_not_change_current", link == "versions/"+hashes[1])
	binaryLink := filepath.Join(h.Temporary, "binary-link")
	Must(os.Symlink(first, binaryLink))
	invoke(binaryLink, hashes[0], false)
	link, err = os.Readlink(filepath.Join(prefix, "current"))
	Must(err)
	h.Check("symlink_rejection_does_not_change_current", link == "versions/"+hashes[1])
	invoke(first, hashes[0], true)
	link, err = os.Readlink(filepath.Join(prefix, "current"))
	Must(err)
	h.Check("explicit_local_rollback", link == "versions/"+hashes[0])
	h.Stop(false)
}
