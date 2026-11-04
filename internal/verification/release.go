package verification

import (
	"fmt"
	"path/filepath"
)

func init() { Register("release", runRelease) }
func QueryObjects(h *Harness, query string, args ...any) []any {
	values := []any{}
	for _, row := range h.Query(query, args...) {
		switch body := row[0].(type) {
		case []byte:
			values = append(values, Decode(body))
		case string:
			values = append(values, Decode([]byte(body)))
		default:
			panic(Failure{"DATABASE_JSON_TYPE_INVALID"})
		}
	}
	return values
}
func runRelease(h *Harness) {
	h.Record["scope"] = "release_gate_and_destination_control_no_publication"
	destination := filepath.Join(h.Temporary, "output-not-created")
	observations := []Object{}
	observe := func(name string, status int, response any) {
		observations = append(observations, Object{"name": name, "status": status, "response": response})
		WriteJSON(filepath.Join(h.Out, "observations.json"), observations)
	}
	snapshot := func(name string) Object {
		value := Object{}
		for _, table := range []string{"releases", "release_publication_attempts", "release_authorizations", "release_reservations", "release_tombstones"} {
			value[table] = h.Query("SELECT count(*) FROM " + table)[0][0]
		}
		value["release_pins"] = h.Query("SELECT count(*) FROM resource_pins WHERE owner_id LIKE 'release_%'")[0][0]
		value["destinations"] = QueryObjects(h, "SELECT data FROM release_destinations ORDER BY id")
		value["jobs"] = QueryObjects(h, "SELECT data FROM jobs ORDER BY id")
		value["attempts"] = QueryObjects(h, "SELECT data FROM attempts ORDER BY id")
		value["integrity"] = h.Query("PRAGMA integrity_check")[0][0]
		value["output_directory_exists"] = Exists(destination)
		WriteJSON(filepath.Join(h.Out, name+".json"), value)
		return value
	}
	start := func() Object {
		health := h.Start("--release-destination", "fixture="+destination)
		observe("health", 200, health)
		return health
	}
	fixture := []byte("FileGate release gate synthetic text.\n")
	Write(filepath.Join(h.InputDirectory, "synthetic.txt"), fixture)
	Write(filepath.Join(h.Out, "synthetic.txt"), fixture)
	health := start()
	h.Check("all_product_gates_closed", GatesClosed(health))
	status, receipt := h.Request("POST", "/v1/jobs", Object{"source_kind": "local", "root_id": "fixture", "source": "synthetic.txt", "idempotency_key": "release-gate-input"}, nil, nil)
	observe("intake", status, receipt)
	h.Check("synthetic_input_committed_hold", status == 202 && Str(receipt, "job", "verdict") == "HOLD" && Get(receipt, "job", "release", "eligible") == false)
	job := Map(receipt, "job")
	id := Str(job, "job_id")
	original := filepath.Join(h.Data, "objects", Str(receipt, "input_receipt", "object_id"))
	status, projected := h.Request("GET", "/v1/jobs/"+id, nil, nil, nil)
	observe("job_before", status, projected)
	h.Check("read_projection_keeps_intake_identity", status == 200 && Str(projected, "job_id") == id && Equal(projected["input_receipt"], job["input_receipt"]) && Str(projected, "attempt_id") == Str(job, "attempt_id") && Str(projected, "verdict") == "HOLD" && Get(projected, "release", "eligible") == false && Equal(Get(projected, "release", "reason_codes"), []string{"INCOMPLETE_REQUIRED_CHECKS"}))
	job = projected
	before := snapshot("before")
	tests := []struct {
		name, path string
		body       Object
		headers    map[string]string
		status     int
		code       string
	}{{"legacy_reject", "/v1/releases", Object{"job_id": id, "destination": "fixture", "idempotency_key": "fixed-release-key"}, nil, 409, "INCOMPLETE_REQUIRED_CHECKS"}, {"legacy_replay_reject", "/v1/releases", Object{"job_id": id, "destination": "fixture", "idempotency_key": "fixed-release-key"}, nil, 409, "INCOMPLETE_REQUIRED_CHECKS"}, {"canonical_reject", "/v1/jobs/" + id + "/release", Object{"destination_id": "fixture"}, map[string]string{"Idempotency-Key": "fixed-release-key"}, 409, "INCOMPLETE_REQUIRED_CHECKS"}, {"canonical_key_required", "/v1/jobs/" + id + "/release", Object{"destination_id": "fixture"}, nil, 400, "INVALID_IDEMPOTENCY_KEY"}, {"legacy_key_required", "/v1/releases", Object{"job_id": id, "destination": "fixture"}, nil, 400, "INVALID_REQUEST"}, {"destination_is_id", "/v1/releases", Object{"job_id": id, "destination": destination, "idempotency_key": "path-rejected"}, nil, 400, "INVALID_REQUEST"}, {"canonical_unknown_field", "/v1/jobs/" + id + "/release", Object{"destination_id": "fixture", "force": true}, map[string]string{"Idempotency-Key": "override-rejected"}, 400, "INVALID_REQUEST"}, {"canonical_empty_destination", "/v1/jobs/" + id + "/release", Object{"destination_id": ""}, map[string]string{"Idempotency-Key": "empty-destination"}, 400, "INVALID_REQUEST"}}
	for _, test := range tests {
		status, value := h.Request("POST", test.path, test.body, test.headers, nil)
		observe(test.name, status, value)
		h.Check(test.name, status == test.status && ErrorCode(value) == test.code)
	}
	for _, test := range []struct {
		method, path string
		body         any
	}{{"GET", "/v1/releases/release_unknown", nil}, {"POST", "/v1/releases/release_unknown/abort", Object{}}} {
		status, value := h.Request(test.method, test.path, test.body, nil, nil)
		observe("unknown_release_"+test.method, status, value)
		h.Check("unknown_release_"+test.method, status == 404 && ErrorCode(value) == "NOT_FOUND")
	}
	for _, command := range [][]string{{"release", id, "--destination", "fixture", "--idempotency-key", "cli-release"}, {"release-status", "release_unknown"}, {"release-abort", "release_unknown"}} {
		code, value := h.CLI(command...)
		observe("cli_"+command[0], code, value)
		expected := "NOT_FOUND"
		if command[0] == "release" {
			expected = "INCOMPLETE_REQUIRED_CHECKS"
		}
		h.Check("cli_"+command[0], code == 2 && ErrorCode(value) == expected)
	}
	calls := []struct {
		name     string
		args     Object
		expected string
	}{{"release_file", Object{"job_id": id, "destination_id": "fixture", "idempotency_key": "mcp-release"}, "INCOMPLETE_REQUIRED_CHECKS"}, {"get_release", Object{"release_id": "release_unknown"}, "NOT_FOUND"}, {"abort_release", Object{"release_id": "release_unknown"}, "NOT_FOUND"}, {"abort_release", Object{"release_id": "release_unknown", "force": true}, "INVALID_ARGUMENT"}}
	messages := append(MCPInit(), Object{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	for i, call := range calls {
		messages = append(messages, MCPCall(i+3, call.name, call.args))
	}
	code, replies := h.MCP(messages)
	observe("mcp", code, replies)
	tools := map[string]any{}
	for _, tool := range List(replies[2], "result", "tools") {
		tools[Str(tool, "name")] = tool
	}
	h.Check("mcp_release_id_contract", code == 0 && Equal(Get(tools["get_release"], "inputSchema", "required"), []string{"release_id"}) && Equal(Get(tools["abort_release"], "inputSchema", "required"), []string{"release_id"}))
	for i, call := range calls {
		value := MCPValue(replies[int64(i+3)])
		h.Check(fmt.Sprint("mcp_", i+3, "_", call.name), Bool(replies[int64(i+3)], "result", "isError") && ErrorCode(value) == call.expected)
	}
	status, destinations := h.Request("GET", "/v1/release-destinations", nil, nil, nil)
	observe("destinations_initial", status, destinations)
	h.Check("only_configured_destination_id_exposed", status == 200 && Equal(destinations["destinations"], []Object{{"destination_id": "fixture", "enabled": true}}))
	code, listed := h.CLI("destinations")
	observe("cli_destinations", code, listed)
	h.Check("cli_destinations_match", code == 0 && Equal(listed, destinations))
	for i := 0; i < 2; i++ {
		status, value := h.Request("POST", "/v1/release-destinations/fixture/disable", Object{}, nil, nil)
		observe(fmt.Sprint("disable_", i), status, value)
		h.Check(fmt.Sprint("disable_monotonic_", i), status == 200 && Equal(value["destination"], Object{"destination_id": "fixture", "enabled": false}))
	}
	code, value := h.CLI("destination-disable", "fixture")
	observe("cli_disable", code, value)
	h.Check("cli_disable_idempotent", code == 0 && Get(value, "destination", "enabled") == false)
	h.Stop(false)
	start()
	status, value = h.Request("GET", "/v1/release-destinations", nil, nil, nil)
	observe("destinations_restart", status, value)
	h.Check("disabled_destination_not_reenabled_by_config", status == 200 && Equal(value["destinations"], []Object{{"destination_id": "fixture", "enabled": false}}))
	status, value = h.Request("POST", "/v1/releases", Object{"job_id": id, "destination": "fixture", "idempotency_key": "fixed-release-key"}, nil, nil)
	observe("restart_reject", status, value)
	h.Check("restart_never_enables_release", status == 409 && ErrorCode(value) == "INCOMPLETE_REQUIRED_CHECKS")
	status, afterJob := h.Request("GET", "/v1/jobs/"+id, nil, nil, nil)
	observe("job_after", status, afterJob)
	h.Check("job_attempt_and_input_unchanged", status == 200 && Equal(afterJob, job) && FileDigest(original) == Digest(fixture))
	h.Stop(false)
	after := snapshot("after")
	empty := true
	for _, name := range []string{"releases", "release_publication_attempts", "release_authorizations", "release_reservations", "release_tombstones", "release_pins"} {
		empty = empty && Int(after, name) == 0
	}
	h.Check("no_release_intent_authorization_or_reservation", empty)
	h.Check("no_output_or_staging_created", Get(after, "output_directory_exists") == false)
	h.Check("jobs_and_attempts_not_mutated", Equal(before["jobs"], after["jobs"]) && Equal(before["attempts"], after["attempts"]) && Str(after, "integrity") == "ok")
}
