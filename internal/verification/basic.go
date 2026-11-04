package verification

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var InputA = []byte("FileGate synthetic PRIVATE_BODY_MARKER_A.\n")
var InputB = []byte("FileGate synthetic PRIVATE_BODY_MARKER_B.\n")

const InputURL = "https://example.invalid/synthetic.zip?receipt=PRIVATE_URL_QUERY_MARKER"

func init() { Register("basic", runBasic) }
func GatesClosed(health Object) bool {
	for _, key := range []string{"stage0_passed", "customer_operation_enabled", "pass_enabled", "release_enabled"} {
		if health[key] != false {
			return false
		}
	}
	return true
}
func (h *Harness) StalledWait(id string, snapshot bool) (bool, int, Object, time.Duration) {
	if !snapshot {
		Must(h.Process.Process.Signal(syscall.SIGSTOP))
	}
	defer func() { Must(h.Process.Process.Signal(syscall.SIGCONT)) }()
	started := time.Now()
	cmd := exec.Command(h.Binary, "--data-dir", h.Data, "wait", id, "--require-pass", "--timeout", "1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	Must(cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if snapshot {
		time.Sleep(200 * time.Millisecond)
		Must(h.Process.Process.Signal(syscall.SIGSTOP))
	}
	completed := true
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		completed = false
		Must(cmd.Process.Kill())
		<-done
	}
	code := cmd.ProcessState.ExitCode()
	h.Responses = append(h.Responses, stdout.Bytes(), stderr.Bytes())
	h.Commands = append(h.Commands, Object{"operation": "wait", "exit_code": code})
	value := Object{}
	if stdout.Len() > 0 {
		value = Decode(stdout.Bytes())
	}
	return completed, code, value, time.Since(started)
}
func runBasic(h *Harness) {
	h.Record["scope"] = "synthetic CLI/UDS/MCP intake and HOLD gate; no scanner or VM execution"
	h.Record["stage1_completed"] = false
	h.Record["inputs"] = Object{"a.txt": Object{"bytes": len(InputA), "sha256": Digest(InputA)}, "b.txt": Object{"bytes": len(InputB), "sha256": Digest(InputB)}}
	Write(filepath.Join(h.Out, "inputs/a.txt"), InputA)
	Write(filepath.Join(h.Out, "inputs/b.txt"), InputB)
	WriteJSON(filepath.Join(h.Out, "inputs/url.json"), Object{"url": InputURL, "expected_type": "zip", "expected_sha256": Digest(InputA), "execution": "queued behind a stalled upload, then cancelled or interrupted before acquisition"})
	Must(os.Mkdir(h.Data, 0700))
	sentinel := filepath.Join(h.InputDirectory, "configuration-sentinel.txt")
	sentinelBody := []byte("FileGate synthetic configuration sentinel.\n")
	Write(sentinel, sentinelBody)
	Must(os.Symlink(sentinel, filepath.Join(h.Data, "client.json")))
	health := h.Start()
	clientInfo, err := os.Lstat(filepath.Join(h.Data, "client.json"))
	Must(err)
	h.Check("client_config_symlink_replaced_without_target_write", bytes.Equal(Read(sentinel), sentinelBody) && clientInfo.Mode()&os.ModeSymlink == 0 && clientInfo.Mode().Perm() == 0600)
	h.Check("health_gate_closed", Str(health, "schema_version") == "4" && Equal(health["supported_intake"], []string{"local", "upload", "url"}) && GatesClosed(health))
	socket, err := os.Stat(h.Socket)
	Must(err)
	h.Check("socket_owner_only", socket.Mode().Perm() == 0600)
	code, duplicate := h.CLI("serve", "--input-root", "fixture="+h.InputDirectory)
	h.Check("duplicate_service_rejected", code == 2 && ErrorCode(duplicate) == "RESOURCE_BUSY")
	source := filepath.Join(h.InputDirectory, "PRIVATE_FILENAME_MARKER.txt")
	Write(source, InputA)
	metadata := Object{"idempotency_key": "local-first", "expected_type": "txt", "expected_sha256": Digest(InputA)}
	code, first := h.Submit("file", source, metadata, nil)
	jobID := Str(first, "job_id")
	h.Check("local_first_committed_hold", code == 0 && Bool(first, "current_input_checked") && Get(first, "replayed") == false && Str(first, "input_receipt", "sha256") == Digest(InputA) && Int(first, "input_receipt", "byte_size") == int64(len(InputA)) && Str(first, "job", "verdict") == "HOLD" && Get(first, "job", "release", "eligible") == false)
	objectPath := filepath.Join(h.Data, "objects", Str(first, "input_receipt", "object_id"))
	info, err := os.Stat(objectPath)
	Must(err)
	h.Check("original_stored_readonly", bytes.Equal(Read(objectPath), InputA) && info.Mode().Perm() == 0400)
	canonical := Object{"source_kind": "local", "root_id": "alias", "source": filepath.Base(source), "idempotency_key": "local-first", "expected_type": "txt", "expected_sha256": Digest(InputA)}
	status, alias := h.Request("POST", "/v1/jobs", canonical, nil, nil)
	stable := status == 200 && Str(alias, "job_id") == jobID
	for i := 0; i < 24; i++ {
		code, alias = h.Submit("file", source, metadata, nil)
		stable = stable && code == 0 && Str(alias, "job_id") == jobID && Bool(alias, "replayed")
	}
	h.Check("duplicate_input_root_alias_replay_stable", stable)
	completed, code, unavailable, duration := h.StalledWait(jobID, false)
	h.Check("wait_http_deadline_without_snapshot", completed && code == 2 && ErrorCode(unavailable) == "WAIT_STATUS_UNAVAILABLE" && unavailable["phase"] == nil && duration < 2500*time.Millisecond, Object{"elapsed_seconds": duration.Seconds()})
	Write(source, InputB)
	code, replay := h.Submit("file", source, metadata, nil)
	h.Check("local_replaced_source_replay", code == 0 && Str(replay, "job_id") == jobID && Equal(replay["input_receipt"], first["input_receipt"]) && Bool(replay, "replayed") && Get(replay, "current_input_checked") == false && Get(replay, "body_consumed") == false)
	Must(os.Remove(source))
	code, replay = h.Submit("file", source, metadata, nil)
	h.Check("local_missing_source_replay", code == 0 && Str(replay, "job_id") == jobID && Equal(replay["input_receipt"], first["input_receipt"]))
	conflict := Object{"source_kind": "local", "root_id": "fixture", "source": filepath.Base(source), "idempotency_key": "local-first", "expected_type": "zip", "expected_sha256": Digest(InputA)}
	status, value := h.Request("POST", "/v1/jobs", conflict, nil, nil)
	h.Check("fingerprint_conflict", status == 409 && ErrorCode(value) == "IDEMPOTENCY_CONFLICT" && Str(value, "error", "receipt", "job_id") == jobID && bytes.Equal(Read(objectPath), InputA))
	Write(source, InputB)
	bad := Object{"idempotency_key": "wrong-hash", "expected_sha256": Digest(InputA)}
	code, mismatch := h.Submit("file", source, bad, nil)
	failedID := Str(mismatch, "error", "receipt", "job_id")
	h.Check("first_hash_mismatch", code == 2 && ErrorCode(mismatch) == "INPUT_HASH_MISMATCH" && Get(mismatch, "error", "receipt", "input_receipt") == nil)
	Write(source, InputA)
	code, retry := h.Submit("file", source, bad, nil)
	h.Check("failed_key_not_reused", code == 2 && ErrorCode(retry) == "INTAKE_TERMINAL_WITHOUT_INPUT" && Str(retry, "error", "receipt", "job_id") == failedID)
	code, waited := h.CLI("wait", jobID, "--require-pass", "--timeout", "0")
	h.Check("wait_hold_exit10", code == 10 && Str(waited, "verdict") == "HOLD")
	code, waited = h.CLI("wait", failedID, "--require-pass", "--timeout", "0")
	h.Check("wait_failed_exit30", code == 30 && Str(waited, "verdict") == "HOLD")
	uploadMetadata := Object{"source_kind": "upload", "idempotency_key": "upload-first", "display_name": "synthetic.txt", "expected_sha256": Digest(InputA)}
	headers := map[string]string{"Content-Type": "application/octet-stream", "FileGate-Metadata": base64.RawURLEncoding.EncodeToString(Encoded(uploadMetadata))}
	status, uploaded := h.Request("POST", "/v1/uploads", nil, headers, InputA)
	h.Check("upload_committed_hold", status == 202 && Str(uploaded, "input_receipt", "sha256") == Digest(InputA) && Str(uploaded, "job", "verdict") == "HOLD")
	for _, framing := range []string{"length", "chunked"} {
		status, replay, closed, elapsed := h.UnreadUpload(uploadMetadata, framing)
		h.Check("upload_replay_unread_"+framing, status == 200 && Str(replay, "job_id") == Str(uploaded, "job_id") && Get(replay, "body_consumed") == false && Get(replay, "current_input_checked") == false && closed && elapsed < 1500*time.Millisecond, Object{"response_and_close_seconds": elapsed.Seconds()})
	}
	code, stdinUpload := h.Submit("upload", "stdin.txt", Object{"idempotency_key": "stdin-upload"}, InputA)
	h.Check("cli_stdin_upload", code == 0 && Str(stdinUpload, "input_receipt", "sha256") == Digest(InputA))
	pendingMetadata, connection, pendingID := h.BeginPartial("concurrent-key")
	status, pendingReplay, closed, _ := h.UnreadUpload(pendingMetadata, "chunked")
	h.Check("concurrent_same_key_202", status == 202 && Str(pendingReplay, "job_id") == pendingID && Get(pendingReplay, "input_receipt") == nil && Get(pendingReplay, "body_consumed") == false && closed)
	other := Object{}
	for k, v := range pendingMetadata {
		other[k] = v
	}
	other["idempotency_key"] = "busy-key"
	status, busy, closed, duration := h.UnreadUpload(other, "length")
	h.Check("concurrent_other_key_busy", status == 429 && ErrorCode(busy) == "RESOURCE_BUSY" && closed && duration < 1500*time.Millisecond)
	code, waiting := h.CLI("wait", pendingID, "--require-pass", "--timeout", "0")
	h.Check("wait_timeout_does_not_cancel", code == 40 && Bool(waiting, "job_continues") && Equal(waiting["reason_codes"], []string{"WAIT_TIMEOUT"}))
	completed, code, waiting, duration = h.StalledWait(pendingID, true)
	h.Check("wait_http_deadline_keeps_snapshot", completed && code == 40 && Str(waiting, "job_id") == pendingID && Str(waiting, "phase") == "ACQUIRING" && Bool(waiting, "job_continues") && Bool(waiting, "wait_timed_out") && duration < 2500*time.Millisecond, Object{"elapsed_seconds": duration.Seconds()})
	messages := append(MCPInit(), MCPCall(2, "wait_job", Object{"job_id": pendingID, "timeout": 0}))
	code, replies := h.MCP(messages)
	waited = MCPValue(replies[2])
	h.Check("mcp_wait_timeout_preserves_pending_job", code == 0 && Get(replies[2], "result", "isError") == false && Str(waited, "job_id") == pendingID && Str(waited, "phase") == "ACQUIRING" && Bool(waited, "wait_timed_out") && Bool(waited, "job_continues"))
	Must(connection.Close())
	failed := h.WaitJob(pendingID, true)
	h.Check("partial_upload_not_committed", (Str(failed, "phase") == "FAILED" || Str(failed, "phase") == "CANCELLED") && Get(failed, "input_receipt") == nil && Str(failed, "verdict") == "HOLD")
	status, old, closed, _ := h.UnreadUpload(pendingMetadata, "chunked")
	h.Check("partial_upload_key_fixed", status == 409 && ErrorCode(old) == "INTAKE_TERMINAL_WITHOUT_INPUT" && closed)
	_, cancelConnection, cancelID := h.BeginPartial("cancel-key")
	started := time.Now()
	status, _ = h.Request("POST", "/v1/jobs/"+cancelID+"/cancel", Object{}, nil, nil)
	cancelled := h.WaitJob(cancelID, true)
	duration = time.Since(started)
	Must(cancelConnection.Close())
	h.Check("cancel_stalled_upload", status == 200 && Str(cancelled, "phase") == "CANCELLED" && duration < 2*time.Second, Object{"cancellation_seconds": duration.Seconds()})
	link := filepath.Join(h.InputDirectory, "link.txt")
	Must(os.Symlink(source, link))
	code, rejected := h.Submit("file", link, Object{"idempotency_key": "symlink"}, nil)
	h.Check("symlink_rejected", code == 2 && Get(rejected, "error", "receipt", "input_receipt") == nil)
	special := filepath.Join(h.InputDirectory, "pipe.txt")
	Must(unix.Mkfifo(special, 0600))
	code, rejected = h.Submit("file", special, Object{"idempotency_key": "fifo"}, nil)
	h.Check("fifo_rejected_without_blocking", code == 2 && Get(rejected, "error", "receipt", "input_receipt") == nil)
	status, released := h.Request("POST", "/v1/releases", Object{"job_id": jobID, "destination": "default", "idempotency_key": "release-key"}, nil, nil)
	h.Check("release_gate_closed", status == 409 && ErrorCode(released) == "INCOMPLETE_REQUIRED_CHECKS")
	_, beforeRescan := h.Request("GET", "/v1/jobs/"+jobID, nil, nil, nil)
	status, rescanned := h.Request("POST", "/v1/jobs/"+jobID+"/rescan", Object{}, nil, nil)
	h.Check("rescan_new_attempt_hold", status == 200 && Str(rescanned, "attempt_id") != Str(beforeRescan, "attempt_id") && Str(rescanned, "verdict") == "HOLD" && Get(rescanned, "release", "eligible") == false)
	status, pruned := h.Request("POST", "/v1/prune", Object{}, nil, nil)
	h.Check("prune_preserves_fresh_originals", status == 200 && Str(pruned, "schema_version") == "4" && Int(pruned, "objects_removed") == 0 && Exists(objectPath))
	for _, test := range []struct {
		name string
		body []byte
	}{{"unknown_field", []byte(`{"unknown":1}`)}, {"trailing_json", []byte(`{}{}`)}, {"null", []byte(`null`)}, {"invalid_utf8", []byte{'{', '"', 's', 'o', 'u', 'r', 'c', 'e', '"', ':', '"', 255, '"', '}'}}} {
		status, invalid := h.Request("POST", "/v1/jobs", nil, map[string]string{"Content-Type": "application/json"}, test.body)
		h.Check("strict_json_"+test.name, status == 400 && ErrorCode(invalid) == "INVALID_REQUEST")
	}
	status, invalid := h.Request("POST", "/v1/jobs", nil, map[string]string{"Content-Type": "application/json"}, bytes.Repeat([]byte{' '}, 65537))
	h.Check("json_body_limit", status == 413 && ErrorCode(invalid) == "REQUEST_TOO_LARGE")
	status, invalid = h.Request("GET", "/v1/health", nil, map[string]string{"Host": "untrusted"}, nil)
	h.Check("host_rejected", status == 400 && ErrorCode(invalid) == "INVALID_HOST")
	status, invalid = h.Request("PUT", "/v1/jobs", Object{}, nil, nil)
	h.Check("method_rejected", status == 405 && ErrorCode(invalid) == "METHOD_NOT_ALLOWED")
	status, invalid = h.Request("POST", "/v1/jobs", nil, map[string]string{"Content-Type": "text/plain"}, []byte("{}"))
	h.Check("content_type_rejected", status == 415 && ErrorCode(invalid) == "UNSUPPORTED_MEDIA_TYPE")
	h.Stop(false)
	h.Start()
	code, restarted := h.Submit("file", source, metadata, nil)
	h.Check("receipt_survives_service_restart", code == 0 && Str(restarted, "job_id") == jobID && Equal(restarted["input_receipt"], first["input_receipt"]))
	crashMetadata, crashConnection, crashID := h.BeginPartial("crash-key")
	h.Stop(true)
	Must(crashConnection.Close())
	h.Start()
	recovered := h.WaitJob(crashID, true)
	h.Check("crashed_partial_recovers_hold", Str(recovered, "phase") == "FAILED" && Str(recovered, "verdict") == "HOLD" && Get(recovered, "input_receipt") == nil && Contains(Get(recovered, "reason_codes"), "INTERRUPTED"))
	status, old, closed, _ = h.UnreadUpload(crashMetadata, "length")
	h.Check("crashed_intake_key_fixed", status == 409 && ErrorCode(old) == "INTAKE_TERMINAL_WITHOUT_INPUT" && closed)
	rows := h.Query("SELECT count(*) FROM reservations")
	partial, err := os.ReadDir(filepath.Join(h.Data, "partial"))
	Must(err)
	h.Check("reservations_and_partial_reclaimed", len(rows) == 1 && rows[0][0] == int64(0) && len(partial) == 0)
	basicURLQueue(h)
	basicMCP(h, source, jobID)
	basicPagination(h)
	h.Stop(false)
	combined := bytes.Join(append(append([][]byte{}, h.Logs...), h.Responses...), []byte{'\n'})
	privacy := true
	for _, marker := range [][]byte{[]byte("PRIVATE_BODY_MARKER"), []byte("PRIVATE_FILENAME_MARKER"), []byte("PRIVATE_URL_QUERY_MARKER"), []byte(h.InputDirectory)} {
		privacy = privacy && !bytes.Contains(combined, marker)
	}
	h.Check("privacy_no_body_or_source_path_in_output", privacy)
	h.Check("no_pass_returned", !bytes.Contains(bytes.Join(h.Responses, []byte{'\n'}), []byte(`"verdict":"PASS"`)))
}

func basicPagination(h *Harness) {
	source := filepath.Join(h.InputDirectory, "pages.txt")
	Write(source, InputA)
	for field, maximum := range map[string]int{"declared_media_type": 256, "expected_type": 32} {
		metadata := Object{"source_kind": "upload", "idempotency_key": "boundary-" + field, field: string(bytes.Repeat([]byte{'a'}, maximum+1))}
		status, rejected, closed, _ := h.UnreadUpload(metadata, "length")
		h.Check("metadata_"+field+"_rejected_before_body", status == 400 && closed && ErrorCode(rejected) == "INVALID_REQUEST")
		metadata[field] = string(bytes.Repeat([]byte{'a'}, maximum))
		status, accepted := h.Request("POST", "/v1/uploads", nil, map[string]string{"Content-Type": "application/octet-stream", "FileGate-Metadata": base64.RawURLEncoding.EncodeToString(Encoded(metadata))}, InputA)
		h.Check("metadata_"+field+"_boundary_reuses_unconsumed_key", status == 202 && Bool(accepted, "current_input_checked") && Str(accepted, "input_receipt", "sha256") == Digest(InputA))
	}
	created := map[string]bool{}
	for i := 0; i < 105; i++ {
		status, receipt := h.Request("POST", "/v1/jobs", Object{"source_kind": "local", "root_id": "fixture", "source": "pages.txt", "idempotency_key": fmt.Sprint("page-", i)}, nil, nil)
		if status != 202 {
			panic(Failure{"pagination_input_creation"})
		}
		created[Str(receipt, "job_id")] = true
	}
	status, first := h.Request("GET", "/v1/jobs", nil, nil, nil)
	h.Check("list_default_page_is_bounded", status == 200 && len(List(first, "jobs")) == 100 && Str(first, "next_cursor") != "")
	cursor := ""
	actual := []string{}
	pages := 0
	for {
		path := "/v1/jobs?limit=17"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		status, page := h.Request("GET", path, nil, nil, nil)
		if status != 200 || len(List(page, "jobs")) > 17 {
			panic(Failure{"pagination_page_bound"})
		}
		for _, job := range List(page, "jobs") {
			actual = append(actual, Str(job, "job_id"))
		}
		pages++
		if page["next_cursor"] == nil {
			break
		}
		cursor = Str(page, "next_cursor")
		if pages > 30 {
			panic(Failure{"pagination_no_progress"})
		}
	}
	rows := h.Query("SELECT id FROM jobs ORDER BY created DESC,id DESC")
	expected := []string{}
	seen := map[string]bool{}
	duplicates := false
	for _, id := range actual {
		if seen[id] {
			duplicates = true
		}
		seen[id] = true
	}
	for _, row := range rows {
		expected = append(expected, row[0].(string))
	}
	allCreated := true
	for id := range created {
		allCreated = allCreated && seen[id]
	}
	h.Check("list_cursor_has_no_duplicates_or_omissions", Equal(actual, expected) && !duplicates && allCreated, Object{"jobs": len(actual), "pages": pages})
	code, cli := h.CLI("list", "--cursor", Str(first, "next_cursor"), "--limit", "11")
	ids := []string{}
	for _, job := range List(cli, "jobs") {
		ids = append(ids, Str(job, "job_id"))
	}
	h.Check("list_cli_cursor", code == 0 && Equal(ids, expected[100:111]))
	code, replies := h.MCP(append(MCPInit(), MCPCall(2, "list_jobs", Object{"cursor": Str(first, "next_cursor"), "limit": 11})))
	page := MCPValue(replies[2])
	ids = nil
	for _, job := range List(page, "jobs") {
		ids = append(ids, Str(job, "job_id"))
	}
	h.Check("list_mcp_cursor", code == 0 && Get(replies[2], "result", "isError") == false && Equal(ids, expected[100:111]))
	for name, query := range map[string]string{"unknown": "unknown=1", "duplicate": "limit=1&limit=2", "zero": "limit=0", "large": "limit=101", "empty": "cursor=", "invalid": "cursor=not-a-cursor"} {
		status, value := h.Request("GET", "/v1/jobs?"+query, nil, nil, nil)
		h.Check("list_query_rejects_"+name, status == 400 && (ErrorCode(value) == "INVALID_REQUEST" || ErrorCode(value) == "INVALID_CURSOR"))
	}
}

func basicMCP(h *Harness, source, jobID string) {
	messages := []Object{{"jsonrpc": "2.0", "id": 0, "method": "tools/list"}}
	messages = append(messages, MCPInit()...)
	messages = append(messages, Object{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, MCPCall(3, "get_job", Object{"job_id": jobID}), MCPCall(4, "release_file", Object{"job_id": jobID, "destination_id": "default", "idempotency_key": "mcp-release"}), MCPCall(5, "submit_file", Object{"path": source, "idempotency_key": "mcp-submit", "expected_sha256": Digest(InputA)}), MCPCall(6, "list_jobs", nil), MCPCall(7, "wait_job", Object{"job_id": jobID}), MCPCall(8, "wait_job", Object{"job_id": jobID, "timeout": 31}), MCPCall(9, "get_job", Object{"job_id": jobID, "unknown": true}))
	Map(messages[4], "params")["_meta"] = Object{"progressToken": "synthetic"}
	Map(messages[7], "params")["_meta"] = Object{"progressToken": 1}
	delete(Map(messages[7], "params"), "arguments")
	code, replies := h.MCP(messages)
	job := MCPValue(replies[3])
	released := MCPValue(replies[4])
	submitted := MCPValue(replies[5])
	tools := map[string]any{}
	for _, tool := range List(replies[2], "result", "tools") {
		tools[Str(tool, "name")] = tool
	}
	h.Check("mcp_handshake_and_tools", code == 0 && Str(replies[0], "error", "message") == "NOT_INITIALIZED" && Str(replies[1], "result", "protocolVersion") == "2025-06-18" && len(tools) == 10 && Equal(Get(tools["get_release"], "inputSchema", "required"), []string{"release_id"}) && Equal(Get(tools["abort_release"], "inputSchema", "required"), []string{"release_id"}) && Int(tools["wait_job"], "inputSchema", "properties", "timeout", "maximum") == 30 && Equal(Get(tools["submit_file"], "inputSchema", "required"), []string{"path", "idempotency_key"}))
	h.Check("mcp_product_flow_hold", Str(job, "verdict") == "HOLD" && Get(job, "release", "eligible") == false && Bool(replies[4], "result", "isError") && ErrorCode(released) == "INCOMPLETE_REQUIRED_CHECKS" && Str(submitted, "input_receipt", "sha256") == Digest(InputA) && Str(submitted, "job", "verdict") == "HOLD")
	listed := MCPValue(replies[6])
	waited := MCPValue(replies[7])
	found := false
	for _, job := range List(listed, "jobs") {
		found = found || Str(job, "job_id") == jobID
	}
	h.Check("mcp_optional_arguments_and_meta", Get(replies[6], "result", "isError") == false && found && Get(replies[3], "result", "isError") == false)
	h.Check("mcp_wait_default_and_upper_bound", Get(replies[7], "result", "isError") == false && Str(waited, "job_id") == jobID && Str(waited, "verdict") == "HOLD" && Bool(replies[8], "result", "isError"))
	h.Check("mcp_unknown_tool_arguments_rejected", Bool(replies[9], "result", "isError"))
}

func basicURLQueue(h *Harness) {
	_, connection, activeID := h.BeginPartial("url-ingest-owner")
	request := Object{"url": InputURL, "expected_type": "zip", "expected_sha256": Digest(InputA)}
	status, rejected := h.Request("POST", "/v1/jobs/url", request, nil, nil)
	h.Check("url_key_required", status == 400 && ErrorCode(rejected) == "INVALID_IDEMPOTENCY_KEY")
	status, rejected = h.Request("POST", "/v1/jobs/url", Object{"url": "https://127.0.0.1/fixture", "expected_type": "zip"}, map[string]string{"Idempotency-Key": "url-private"}, nil)
	h.Check("url_private_destination", status == 400 && ErrorCode(rejected) == "DOWNLOAD_DESTINATION_DENIED")
	status, first := h.Request("POST", "/v1/jobs/url", request, map[string]string{"Idempotency-Key": "url-first"}, nil)
	h.Check("url_initial_reservation", status == 202 && Str(first, "intake_status") == "RESERVED" && Str(first, "job", "phase") == "QUEUED" && Get(first, "input_receipt") == nil && Get(first, "replayed") == false && Get(first, "current_input_checked") == false && Get(first, "body_consumed") == false)
	ids := []string{Str(first, "job_id")}
	status, replay := h.Request("POST", "/v1/jobs/url", request, map[string]string{"Idempotency-Key": "url-first"}, nil)
	h.Check("url_reserved_replay_without_reacquisition", status == 202 && Bool(replay, "replayed") && Str(replay, "job_id") == ids[0] && Str(replay, "job", "phase") == "QUEUED" && Get(replay, "input_receipt") == nil && Get(replay, "current_input_checked") == false && Get(replay, "body_consumed") == false)
	status, conflict := h.Request("POST", "/v1/jobs/url", Object{"url": InputURL + "-changed", "expected_type": "zip", "expected_sha256": Digest(InputA)}, map[string]string{"Idempotency-Key": "url-first"}, nil)
	h.Check("url_query_fingerprint_conflict", status == 409 && ErrorCode(conflict) == "IDEMPOTENCY_CONFLICT" && Str(conflict, "error", "receipt", "job_id") == ids[0])
	code, cli := h.CLIInput([]byte(InputURL+"\n"), "submit", "url", "--url-stdin", "--idempotency-key", "url-stdin", "--expected-type", "zip", "--expected-sha256", Digest(InputA))
	h.Check("url_stdin_reserves_without_echo", code == 0 && Str(cli, "job", "phase") == "QUEUED" && Get(cli, "input_receipt") == nil)
	ids = append(ids, Str(cli, "job_id"))
	code, replies := h.MCP(append(MCPInit(), MCPCall(2, "submit_url", Object{"url": InputURL, "expected_type": "zip", "expected_sha256": Digest(InputA), "idempotency_key": "url-mcp"})))
	mcp := MCPValue(replies[2])
	h.Check("url_mcp_reserves_without_fetch", code == 0 && Get(replies[2], "result", "isError") == false && Str(mcp, "job", "phase") == "QUEUED" && Get(mcp, "input_receipt") == nil)
	ids = append(ids, Str(mcp, "job_id"))
	for i := 0; i < 16; i++ {
		status, receipt := h.Request("POST", "/v1/jobs/url", request, map[string]string{"Idempotency-Key": fmt.Sprint("url-queue-", i)}, nil)
		if status != 202 || Str(receipt, "job", "phase") != "QUEUED" {
			panic(Failure{"url_queue_fill"})
		}
		ids = append(ids, Str(receipt, "job_id"))
	}
	status, limited := h.Request("POST", "/v1/jobs/url", request, map[string]string{"Idempotency-Key": "url-over-capacity"}, nil)
	pending := h.Query("SELECT count(*) FROM reservations")
	_, listed := h.Request("GET", "/v1/jobs", nil, nil, nil)
	idSet := map[string]bool{}
	for _, id := range ids {
		idSet[id] = true
	}
	queued := 0
	allQueued := true
	active := []string{}
	for _, job := range List(listed, "jobs") {
		if idSet[Str(job, "job_id")] {
			queued++
			allQueued = allQueued && Str(job, "phase") == "QUEUED" && Get(job, "input_receipt") == nil
		}
		if Str(job, "phase") == "ACQUIRING" {
			active = append(active, Str(job, "job_id"))
		}
	}
	h.Check("url_queue_limit_and_single_ingest", status == 429 && ErrorCode(limited) == "RESOURCE_BUSY" && pending[0][0] == int64(20) && queued == 19 && allQueued && Equal(active, []string{activeID}), Object{"queued_job_ids": ids})
	allCancelled := true
	for _, id := range ids {
		status, job := h.Request("POST", "/v1/jobs/"+id+"/cancel", Object{}, nil, nil)
		allCancelled = allCancelled && status == 200 && Str(job, "phase") == "CANCELLED" && Str(job, "verdict") == "HOLD" && Get(job, "input_receipt") == nil
	}
	h.Check("url_queued_cancel_before_ingest_release", allCancelled)
	status, old := h.Request("POST", "/v1/jobs/url", request, map[string]string{"Idempotency-Key": "url-first"}, nil)
	h.Check("url_cancelled_key_fixed", status == 409 && ErrorCode(old) == "INTAKE_TERMINAL_WITHOUT_INPUT" && Str(old, "error", "receipt", "job_id") == ids[0])
	Must(connection.Close())
	h.WaitJob(activeID, true)
	_, connection, _ = h.BeginPartial("url-crash-ingest-owner")
	status, crash := h.Request("POST", "/v1/jobs/url", request, map[string]string{"Idempotency-Key": "url-crash"}, nil)
	h.Check("url_before_crash_still_queued", status == 202 && Str(crash, "job", "phase") == "QUEUED")
	h.Stop(true)
	Must(connection.Close())
	h.Start()
	recovered := h.WaitJob(Str(crash, "job_id"), true)
	h.Check("url_crash_recovers_without_fetch", Str(recovered, "phase") == "FAILED" && Str(recovered, "verdict") == "HOLD" && Get(recovered, "input_receipt") == nil && Contains(Get(recovered, "execution_errors"), "INTERRUPTED"))
	status, old = h.Request("POST", "/v1/jobs/url", request, map[string]string{"Idempotency-Key": "url-crash"}, nil)
	pending = h.Query("SELECT count(*) FROM reservations")
	h.Check("url_crash_key_and_reservation_recovery", status == 409 && ErrorCode(old) == "INTAKE_TERMINAL_WITHOUT_INPUT" && Str(old, "error", "receipt", "job_id") == Str(crash, "job_id") && pending[0][0] == int64(0))
}
