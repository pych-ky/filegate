package verification

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const fixtureBoot = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const fixtureBootB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const fixtureUTC int64 = 1800000000

var fixtureLibrary = strings.Repeat("a", 64)

type controlSuite struct {
	h      *Harness
	serial int
}

func init() { Register("update-control", runUpdateControl) }
func (s *controlSuite) check(name string, actual, expected any) {
	s.h.Checks = append(s.h.Checks, Object{"name": name, "actual": actual, "expected": expected, "passed": Equal(actual, expected)})
}
func (s *controlSuite) invoke(name, operation string, extra Object) Object {
	request := Object{"op": operation, "clock": Object{"boot": fixtureBoot, "utc": fixtureUTC, "continuous_ns": int64(100000000000)}}
	if clock := Map(extra, "clock"); clock != nil {
		request["clock"] = clock
	}
	for key, value := range extra {
		if key != "raw_report" {
			request[key] = value
		}
	}
	data := Encoded(request)
	if raw, ok := extra["raw_report"].([]byte); ok {
		data = append(append(append(data[:len(data)-1], []byte(`,"report":`)...), raw...), '}')
	}
	result := Execute(s.h.Root, []string{s.h.Driver, "--fixture-db", filepath.Join(s.h.Out, "stores", name+".sqlite")}, data, 15*time.Second)
	actual := Object{}
	if result.ExitCode == 0 {
		actual = Decode(result.Stdout)
	} else {
		actual["driver_error"] = strings.TrimSpace(string(result.Stderr))
	}
	s.serial++
	WriteJSON(filepath.Join(s.h.Out, "steps", fmt.Sprintf("%04d.json", s.serial)), Object{"input_utf8": string(data), "exit_code": result.ExitCode, "stdout_sha256": Digest(result.Stdout), "stderr_bytes": len(result.Stderr), "actual": actual})
	return actual
}
func elapsed(seconds int64, extra Object) Object {
	value := Object{"clock": Object{"boot": fixtureBoot, "utc": fixtureUTC + seconds, "continuous_ns": (100 + seconds) * 1000000000}}
	for key, item := range extra {
		value[key] = item
	}
	return value
}
func fixtureClock(utc, continuous int64, boot string) Object {
	return Object{"boot": boot, "utc": utc, "continuous_ns": continuous}
}
func (s *controlSuite) fresh(name string) Object {
	v := s.invoke(name, "initialize", Object{"library_sha256": fixtureLibrary})
	if v["reason"] != nil || Map(v, "control", "snapshot") == nil {
		panic(Failure{"fixture_initialization_failed"})
	}
	s.invoke(name, "start", Object{"update_id": "update_a"})
	return Map(v, "control", "snapshot")
}
func finalReport(snapshot Object, parameters Object) Object {
	status, raw, wait, kind, date, guest := int64(429), "7200", int64(7200), "delta_seconds", "", fixtureUTC+10
	if parameters != nil {
		if value, ok := parameters["status"]; ok {
			status = Int(Object{"v": value}, "v")
		}
		if value, ok := parameters["raw"].(string); ok {
			raw = value
		}
		if value, ok := parameters["wait"]; ok {
			wait = Int(Object{"v": value}, "v")
		}
		if value, ok := parameters["kind"].(string); ok {
			kind = value
		}
		if value, ok := parameters["date"].(string); ok {
			date = value
		}
		if value, ok := parameters["guest"]; ok {
			guest = Int(Object{"v": value}, "v")
		}
	}
	state := Object{}
	for key, value := range snapshot {
		state[key] = value
	}
	state["retry_after_utc"] = guest + wait
	state["max_retry_after_utc"] = guest + wait
	definitions := []any{}
	for i := 0; i < 3; i++ {
		definitions = append(definitions, Object{"definition": fmt.Sprint("fixture_", i), "status": "not_requested_cooldown_or_invalid", "origin_confirmed": false, "artifact_verified": false})
	}
	return Object{"schema_version": 1, "update_id": "update_a", "base_generation": 0, "engine": "1.4.6", "adapter": "filegate-freshclam-1.4.6-v1", "final": true, "all_network_requests_finished": true, "control_complete": true, "control_snapshot": state, "reason_code": "UPDATE_COOLDOWN", "snapshot_sha256": Digest(Encoded(state)), "request_count": 1, "response_count": 1, "dat_save_attempts": 1, "dat_save_failures": 0, "response": Object{"http_status": status, "guest_utc": guest, "retry_after_kind": kind, "retry_after_raw": raw, "date_raw": date, "wait_seconds": wait}, "definitions": definitions, "all_required_origin_confirmations": false, "all_required_artifacts_verified": false, "fixture_only": true, "host_deadline_and_adoption_not_evaluated": true, "adapter_library_sha256": fixtureLibrary}
}
func runUpdateControl(h *Harness) {
	Must(os.Mkdir(filepath.Join(h.Out, "steps"), 0700))
	Must(os.Mkdir(filepath.Join(h.Out, "stores"), 0700))
	if h.Driver == "" {
		h.Driver = filepath.Join(h.Out, "update-driver")
		r := Execute(h.Root, []string{"go", "build", "-trimpath", "-buildvcs=false", "-o", h.Driver, "./experiments/product/update_driver"}, nil, 3*time.Minute)
		Write(filepath.Join(h.Out, "driver-build.log"), append(r.Stdout, r.Stderr...))
		h.Check("driver_build", r.ExitCode == 0)
	}
	h.Record["scope"] = "Go fixed-adapter control/SQLite/process/clock synthetic E2E; no VM, network or product adoption"
	h.Record["driver_sha256"] = FileDigest(h.Driver)
	h.Record["network_requests"] = 0
	h.Record["not_proven"] = []string{"real update VM 600 seconds", "real OS restart/sleep", "candidate verification/adoption", "broker update waiter E2E"}
	s := controlSuite{h: h}
	defer func() { h.Record["steps"] = s.serial }()
	seed := s.fresh("coalesce")
	joined := s.invoke("coalesce", "start", Object{"update_id": "update_b"})
	s.check("concurrent_requests_share_attempt", []any{Get(joined, "attempt", "update_id"), Get(joined, "control", "generation")}, []any{"update_a", 1})
	restored := s.invoke("coalesce", "restore", Object{"update_id": "update_a"})
	s.check("restoration_preserves_snapshot", Get(restored, "restore_request", "control_snapshot"), seed)
	s.check("restoration_generation", Get(restored, "restore_request", "base_generation"), 0)
	cooldowns := []struct {
		name       string
		parameters Object
		expected   int64
	}{{"delta", nil, 7200}, {"fallback429", Object{"raw": "", "wait": 14400, "kind": "fallback"}, 14400}, {"fallback403", Object{"status": 403, "raw": "", "wait": 86400, "kind": "fallback"}, 86400}, {"long403", Object{"status": 403, "raw": "172800", "wait": 172800}, 172800}, {"long429", Object{"raw": "864000", "wait": 864000}, 864000}, {"guest_ahead", Object{"guest": fixtureUTC + 864000}, 7200}, {"guest_behind", Object{"guest": fixtureUTC - 864000}, 7200}, {"http_date", Object{"raw": "Fri, 15 Jan 2027 10:00:00 GMT", "wait": 7200, "kind": "http_date", "date": "Fri, 15 Jan 2027 08:00:00 GMT"}, 7200}}
	for _, test := range cooldowns {
		payload := finalReport(s.fresh(test.name), test.parameters)
		value := s.invoke(test.name, "final", elapsed(10, Object{"update_id": "update_a", "report": payload}))
		s.check(test.name+"_host_wait", []any{value["reason"], Get(value, "control", "remaining_seconds"), Get(value, "control", "active_update_id")}, []any{nil, test.expected, "update_a"})
		s.invoke(test.name, "stopped", elapsed(10, Object{"update_id": "update_a", "cleaned": true}))
		s.check(test.name+"_next_attempt_blocked", s.invoke(test.name, "start", elapsed(11, Object{"update_id": "update_b"}))["reason"], "UPDATE_COOLDOWN")
	}
	mutations := []struct {
		name     string
		path     []string
		value    any
		expected string
	}{{"wrong_library", []string{"adapter_library_sha256"}, strings.Repeat("b", 64), "UPDATE_CONTROL_INVALID"}, {"wrong_engine", []string{"engine"}, "1.4.3", "UPDATE_CONTROL_INVALID"}, {"schema_boolean", []string{"schema_version"}, true, "UPDATE_CONTROL_INVALID"}, {"missing_final", []string{"final"}, false, "UPDATE_STATE_UNKNOWN"}, {"incomplete_control", []string{"control_complete"}, false, "UPDATE_STATE_UNKNOWN"}, {"network_not_final", []string{"all_network_requests_finished"}, false, "UPDATE_CONTROL_INVALID"}, {"snapshot_hash", []string{"snapshot_sha256"}, strings.Repeat("b", 64), "UPDATE_CONTROL_INVALID"}, {"wrong_wait", []string{"response", "wait_seconds"}, 3600, "UPDATE_CLOCK_UNCERTAIN"}, {"overflow_delta", []string{"response", "retry_after_raw"}, "99999999999999999999999", "UPDATE_CLOCK_UNCERTAIN"}, {"false_freshness", []string{"all_required_origin_confirmations"}, true, "UPDATE_CONTROL_INVALID"}, {"fixture_to_official", []string{"fixture_only"}, false, "UPDATE_CONTROL_INVALID"}, {"missing_response", []string{"response", "guest_utc"}, 0, "UPDATE_STATE_UNKNOWN"}, {"request_count_gap", []string{"request_count"}, 2, "UPDATE_CONTROL_INVALID"}, {"unknown_retry_kind", []string{"response", "retry_after_kind"}, "unknown", "UPDATE_CLOCK_UNCERTAIN"}}
	for _, test := range mutations {
		payload := finalReport(s.fresh(test.name), nil)
		target := payload
		for _, key := range test.path[:len(test.path)-1] {
			target = Map(target, key)
		}
		target[test.path[len(test.path)-1]] = test.value
		v := s.invoke(test.name, "final", elapsed(10, Object{"update_id": "update_a", "report": payload}))
		s.check(test.name+"_unknown", []any{v["reason"], Get(v, "control", "state")}, []any{test.expected, "UNKNOWN"})
		s.invoke(test.name, "stopped", elapsed(11, Object{"update_id": "update_a", "cleaned": true}))
		s.check(test.name+"_does_not_retry", s.invoke(test.name, "start", elapsed(100000, Object{"update_id": "update_b"}))["reason"], "UPDATE_STATE_UNKNOWN")
	}
	duplicate := Encoded(finalReport(s.fresh("duplicate"), nil))
	duplicate = append(duplicate[:len(duplicate)-1], []byte(`,"final":true}`)...)
	s.check("duplicate_report_field_rejected", s.invoke("duplicate", "final", elapsed(10, Object{"update_id": "update_a", "raw_report": duplicate}))["reason"], "UPDATE_CONTROL_INVALID")
	seed = s.fresh("fraction_poll")
	s.invoke("fraction_poll", "final", elapsed(10, Object{"update_id": "update_a", "report": finalReport(seed, nil)}))
	var v Object
	for i := int64(1); i <= 8; i++ {
		v = s.invoke("fraction_poll", "read", Object{"clock": fixtureClock(fixtureUTC+10+i/2, 110000000000+i*500000000, fixtureBoot)})
	}
	s.check("subsecond_polling_preserves_elapsed_fraction", []any{Get(v, "control", "remaining_seconds"), Get(v, "control", "wait_fraction_ns")}, []any{7196, 0})
	seed = s.fresh("phase_poll")
	s.invoke("phase_poll", "final", Object{"clock": fixtureClock(fixtureUTC+10, 110900000000, fixtureBoot), "update_id": "update_a", "report": finalReport(seed, nil)})
	s.invoke("phase_poll", "stopped", Object{"clock": fixtureClock(fixtureUTC+10, 110900000000, fixtureBoot), "update_id": "update_a", "cleaned": true})
	for i := int64(1); i <= 8; i++ {
		v = s.invoke("phase_poll", "read", Object{"clock": fixtureClock(fixtureUTC+10+(9+i*5)/10, 110900000000+i*500000000, fixtureBoot)})
	}
	s.check("different_clock_phase_does_not_extend_wait", []any{Get(v, "control", "remaining_seconds"), Get(v, "control", "wait_fraction_ns"), Get(v, "control", "next_allowed_utc")}, []any{7196, 0, fixtureUTC + 7210})
	v = s.invoke("phase_poll", "start", Object{"clock": fixtureClock(fixtureUTC+7210, 7310400000000, fixtureBoot), "update_id": "update_b"})
	s.check("phase_poll_before_continuous_deadline_blocked", []any{v["reason"], Get(v, "control", "remaining_seconds")}, []any{"UPDATE_COOLDOWN", 1})
	v = s.invoke("phase_poll", "start", Object{"clock": fixtureClock(fixtureUTC+7210, 7310900000000, fixtureBoot), "update_id": "update_b"})
	s.check("phase_poll_at_continuous_deadline_allowed", []any{v["reason"], Get(v, "attempt", "update_id")}, []any{nil, "update_b"})
	seed = s.fresh("wall_back")
	s.invoke("wall_back", "final", Object{"clock": fixtureClock(fixtureUTC+10, 110900000000, fixtureBoot), "update_id": "update_a", "report": finalReport(seed, nil)})
	first := s.invoke("wall_back", "read", Object{"clock": fixtureClock(fixtureUTC+5, 120900000000, fixtureBoot)})
	second := s.invoke("wall_back", "read", Object{"clock": fixtureClock(fixtureUTC+6, 121900000000, fixtureBoot)})
	s.check("wall_rollback_does_not_reset_continuous_wait", []any{Get(first, "control", "remaining_seconds"), Get(second, "control", "remaining_seconds"), Get(second, "control", "continuous_remaining_seconds")}, []any{7205, 7204, 7189})
	v = s.invoke("wall_back", "recover", Object{"clock": fixtureClock(fixtureUTC+100000, 0, fixtureBootB)})
	s.check("reboot_preserves_longer_wall_wait", []any{Get(v, "control", "remaining_seconds"), Get(v, "control", "continuous_remaining_seconds")}, []any{7204, 7204})
	for i, name := range []string{"origin_without_requests", "origin_count_exceeds_responses"} {
		seed = s.fresh(name)
		responses := int64(i)
		status, guest := int64(0), int64(0)
		if responses > 0 {
			status = 200
			guest = fixtureUTC + 10
		}
		payload := finalReport(seed, Object{"status": status, "raw": "", "wait": 0, "kind": "fallback", "guest": guest})
		payload["control_snapshot"] = seed
		payload["snapshot_sha256"] = Digest(Encoded(seed))
		payload["reason_code"] = nil
		payload["request_count"] = responses
		payload["response_count"] = responses
		defs := []any{}
		for i := 0; i < 3; i++ {
			defs = append(defs, Object{"definition": fmt.Sprint("fixture_", i), "status": 0, "http_status": 200, "origin_confirmed": true, "artifact_verified": true, "artifact": Object{"sha256": strings.Repeat("b", 64), "bytes": 1}})
		}
		payload["definitions"] = defs
		payload["all_required_origin_confirmations"] = true
		payload["all_required_artifacts_verified"] = true
		v = s.invoke(name, "final", elapsed(10, Object{"update_id": "update_a", "report": payload}))
		s.check(name+"_rejected", []any{v["reason"], Get(v, "control", "state")}, []any{"UPDATE_CONTROL_INVALID", "UNKNOWN"})
	}
	seed = s.fresh("durability")
	payload := finalReport(seed, nil)
	payload["dat_save_failures"] = 1
	v = s.invoke("durability", "final", elapsed(10, Object{"update_id": "update_a", "report": payload}))
	s.check("dat_save_failure_keeps_latest_memory_state", Get(v, "control", "snapshot"), payload["control_snapshot"])
	s.check("final_replay_idempotent", s.invoke("durability", "final", elapsed(10, Object{"update_id": "update_a", "report": payload}))["reason"], nil)
	s.invoke("durability", "recover", elapsed(20, nil))
	s.invoke("durability", "stopped", elapsed(20, Object{"update_id": "update_a", "cleaned": false}))
	v = s.invoke("durability", "attempt", elapsed(20, Object{"update_id": "update_a"}))
	s.check("stop_releases_slot_keeps_cleanup_charge", []any{Get(v, "attempt", "stop_confirmed"), Get(v, "attempt", "reserved_bytes"), Get(v, "attempt", "state")}, []any{true, 6 << 30, "CLEANUP_PENDING"})
	s.invoke("durability", "stopped", elapsed(21, Object{"update_id": "update_a", "cleaned": true}))
	s.check("cleanup_replay_once", s.invoke("durability", "stopped", elapsed(21, Object{"update_id": "update_a", "cleaned": true}))["reason"], nil)
	v = s.invoke("durability", "recover", Object{"clock": fixtureClock(fixtureUTC+20000, 0, fixtureBootB)})
	s.check("boot_restart_restarts_remaining_wait", []any{Get(v, "control", "remaining_seconds"), Get(v, "control", "next_allowed_utc")}, []any{7189, fixtureUTC + 20000 + 7189})
	s.fresh("timeout")
	s.check("deadline_before_boundary", s.invoke("timeout", "deadline", elapsed(599, Object{"update_id": "update_a"}))["reason"], nil)
	s.check("deadline_exact_boundary", s.invoke("timeout", "deadline", elapsed(600, Object{"update_id": "update_a"}))["reason"], "UPDATE_TIMEOUT")
	s.check("timeout_latched", Get(s.invoke("timeout", "attempt", elapsed(601, Object{"update_id": "update_a"})), "attempt", "reason"), "UPDATE_TIMEOUT")
	s.check("timeout_restore_denied", s.invoke("timeout", "restore", elapsed(601, Object{"update_id": "update_a"}))["reason"], "UPDATE_STATE_UNKNOWN")
	seed = s.fresh("interrupted")
	v = s.invoke("interrupted", "recover", elapsed(20, nil))
	s.check("restart_inflight_unknown", Get(v, "control", "state"), "UNKNOWN")
	s.invoke("interrupted", "stopped", elapsed(20, Object{"update_id": "update_a", "cleaned": true}))
	s.check("unknown_age_not_a_reset", s.invoke("interrupted", "start", elapsed(864000, Object{"update_id": "update_b"}))["reason"], "UPDATE_STATE_UNKNOWN")
	v = s.invoke("interrupted", "final", elapsed(864001, Object{"update_id": "update_a", "report": finalReport(seed, nil)}))
	s.check("same_attempt_complete_final_can_recover", Get(v, "control", "state"), "COOLDOWN")
	payload = finalReport(s.fresh("stale_generation"), nil)
	payload["base_generation"] = 99
	v = s.invoke("stale_generation", "final", elapsed(10, Object{"update_id": "update_a", "report": payload}))
	s.check("wrong_generation_does_not_replace_control", []any{v["reason"], Get(v, "control", "state")}, []any{"STALE_REPORT_REJECTED", "IN_FLIGHT"})
	seed = s.fresh("wall_clock")
	s.invoke("wall_clock", "final", elapsed(10, Object{"update_id": "update_a", "report": finalReport(seed, nil)}))
	s.invoke("wall_clock", "stopped", elapsed(10, Object{"update_id": "update_a", "cleaned": true}))
	v = s.invoke("wall_clock", "start", Object{"clock": fixtureClock(fixtureUTC+1000000, 120000000000, fixtureBoot), "update_id": "update_b"})
	s.check("wall_forward_does_not_shorten", []any{v["reason"], Get(v, "control", "remaining_seconds")}, []any{"UPDATE_COOLDOWN", 7190})
	v = s.invoke("wall_clock", "read", Object{"clock": fixtureClock(fixtureUTC+1000001, 119000000000, fixtureBoot)})
	s.check("continuous_rollback_unknown", v["reason"], "UPDATE_CLOCK_UNCERTAIN")
	s.invoke("freshness", "initialize", Object{"library_sha256": fixtureLibrary})
	s.invoke("freshness", "seed_freshness_fixture", nil)
	s.check("fresh_definition_24h_boundary", s.invoke("freshness", "read", elapsed(86400, nil))["definition_fresh"], true)
	s.check("stale_definition_after_24h", s.invoke("freshness", "read", elapsed(86401, nil))["definition_fresh"], false)
	s.check("freshness_not_trusted_across_boot", s.invoke("freshness", "read", Object{"clock": fixtureClock(fixtureUTC+86401, 0, fixtureBootB)})["definition_fresh"], false)
	s.fresh("stored_corruption")
	db, err := sql.Open("sqlite3", filepath.Join(h.Out, "stores/stored_corruption.sqlite"))
	Must(err)
	var stored []byte
	Must(db.QueryRow("SELECT data FROM update_control").Scan(&stored))
	control := Decode(stored)
	delete(control, "generation")
	_, err = db.Exec("UPDATE update_control SET data=?", Encoded(control))
	Must(err)
	Must(db.Close())
	s.check("missing_stored_field_not_defaulted", s.invoke("stored_corruption", "read", nil)["reason"], "UPDATE_CONTROL_INVALID")
}
