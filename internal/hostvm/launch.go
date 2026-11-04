package hostvm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func NativeEvents(control string) ([]Object, error) {
	path := filepath.Join(control, "events.jsonl")
	body, e := ReadBytes(path, 4<<20)
	if os.IsNotExist(e) {
		return []Object{}, nil
	}
	if e != nil {
		return nil, e
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		return nil, Error("NATIVE_EVENTS_TRUNCATED")
	}
	lines := bytes.Split(bytes.TrimSuffix(body, []byte{'\n'}), []byte{'\n'})
	if len(body) == 0 {
		return []Object{}, nil
	}
	if len(lines) > 2048 {
		return nil, Error("NATIVE_EVENT_COUNT_LIMIT")
	}
	events := make([]Object, 0, len(lines))
	for _, line := range lines {
		if len(line) > 65536 {
			return nil, Error("NATIVE_EVENT_LIMIT")
		}
		v, e := Decode(line)
		if e != nil {
			return nil, e
		}
		events = append(events, v)
	}
	return events, nil
}
func GuardianResult(control string, parent Object, children []Object, death *bool) (Object, error) {
	result, _, e := Read(filepath.Join(control, "guardian-result.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	var guardian Object
	expected := map[string]bool{}
	for _, c := range children {
		if Str(c, "role") == "guardian" {
			guardian = c
		} else {
			expected[identityKey(c)] = true
		}
	}
	targets := List(result, "targets")
	if guardian == nil || targets == nil || len(targets) > 64 {
		return nil, Error("GUARDIAN_TARGET_REPORT_INVALID")
	}
	seen := map[string]bool{}
	for _, v := range targets {
		item, ok := v.(Object)
		if !ok {
			return nil, Error("GUARDIAN_TARGET_REPORT_INVALID")
		}
		identity, e := ProcessIdentity(item, "")
		if e != nil {
			return nil, e
		}
		key := identityKey(identity)
		if seen[key] {
			return nil, Error("GUARDIAN_TARGET_IDENTITIES_DIFFER")
		}
		seen[key] = true
		if !Equal(item["process_group"], parent["pid"]) || Int(item, "uid") != int64(os.Getuid()) || item["exited"] != true || !isBool(item["term_sent"]) || !isBool(item["sigkill_sent"]) {
			return nil, Error("GUARDIAN_TARGET_STOP_UNCONFIRMED")
		}
	}
	for k := range expected {
		if !seen[k] {
			return nil, Error("GUARDIAN_TARGET_IDENTITIES_DIFFER")
		}
	}
	if Int(result, "schema") != 1 || !Equal(result["parent_pid"], parent["pid"]) || !Equal(result["parent_start_abstime"], parent["start_abstime"]) || !Equal(result["guardian_pid"], guardian["pid"]) || !Equal(result["guardian_start_abstime"], guardian["start_abstime"]) || !Equal(result["process_group"], parent["pid"]) || result["parent_pipe_eof"] != true || !isBool(result["parent_same_identity_live_at_eof"]) || !isBool(result["parent_stop_intent_seen"]) || death != nil && (result["parent_same_identity_live_at_eof"] != !*death || result["parent_stop_intent_seen"] != !*death) || result["all_targets_exited"] != true || result["monitor_failed"] != false || !isBool(result["term_sent"]) || !isBool(result["sigkill_sent"]) || Int(result, "elapsed_ns") < 0 || Int(result, "elapsed_ns") >= 10*1e9 {
		return nil, Error("GUARDIAN_COMPLETION_CONTRACT_FAILED")
	}
	return result, nil
}
func isBool(v any) bool { _, ok := v.(bool); return ok }
func identityKey(v Object) string {
	b, _ := Canonical([]any{v["pid"], v["start_abstime"]})
	return string(b)
}
func containsIdentity(rows []Object, value Object) bool {
	for _, v := range rows {
		if Equal(v, value) {
			return true
		}
	}
	return false
}
func identities(value any) ([]Object, error) {
	rows, ok := value.([]any)
	if !ok {
		return nil, Error("NATIVE_IDENTITIES_INVALID")
	}
	result := make([]Object, 0, len(rows))
	for _, v := range rows {
		m, ok := v.(Object)
		if !ok {
			return nil, Error("NATIVE_IDENTITIES_INVALID")
		}
		id, e := ProcessIdentity(m, "")
		if e != nil {
			return nil, e
		}
		result = append(result, id)
	}
	return result, nil
}
func primaryIdentities(finished []Object, watchdog Object, events []Object) ([]Object, error) {
	if len(finished) > 64 {
		return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
	}
	seen := map[int64]bool{}
	roles := map[string]bool{}
	primary := []Object{}
	for _, id := range finished {
		pid := Int(id, "pid")
		role := Str(id, "role")
		if seen[pid] || pid == Int(watchdog, "pid") || role != "guardian" && role != "vm" && role != "helper" && role != "descendant" {
			return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
		}
		seen[pid] = true
		if role != "descendant" {
			if roles[role] {
				return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
			}
			roles[role] = true
			primary = append(primary, id)
		}
	}
	if len(primary) > 3 {
		return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
	}
	for _, event := range events {
		if Str(event, "event") == "MONITOR_READY" {
			known, e := identities(event["processes"])
			if e != nil {
				return nil, e
			}
			for _, id := range known {
				if !containsIdentity(primary, id) {
					return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
				}
			}
		}
	}
	return primary, nil
}
func (r *Runtime) Launch(ctx context.Context, config Object, out string, started uint64, control *Control, progress func(Object) error) (report Object, returned error) {
	if control == nil || control.Runtime != r {
		return nil, Error("NATIVE_LAUNCH_CONTROL_REQUIRED")
	}
	deathTest := config["watchdog_death_fixture"] == true
	if deathTest && !deathFixtureConfig(r, config) {
		return nil, Error("DEATH_FIXTURE_CONFIGURATION_INVALID")
	}
	directory, e := control.Prepare(config, started)
	if e != nil {
		return nil, e
	}
	if e = os.Mkdir(out, 0700); e != nil {
		return nil, e
	}
	info, e := Owned(directory, unix.S_IFDIR, 0700)
	if e != nil {
		return nil, e
	}
	host, e := r.HostVersion()
	if e != nil {
		return nil, e
	}
	platform, e := r.NativePlatform()
	if e != nil {
		return nil, e
	}
	binary, e := HashFile(r.NativeBinary)
	if e != nil {
		return nil, e
	}
	source, e := HashFile(r.NativeSource)
	if e != nil {
		return nil, e
	}
	target := launchTarget(directory)
	report = Object{"schema": 1, "kind": "monitored_qemu_fixture", "passed": false, "host": host, "native_platform": platform, "binary_sha256": binary, "native_source_sha256": source, "control_directory": directory, "control_directory_identity": DirectoryIdentity(info), "target": target, "qemu_started": false, "temporary_service_absent": false, "broker_events": []any{}, "guardian_result_verified": false, "cleanup_all_exited": false, "identity_measurement_failures": []any{}, "broker_signals": []any{}, "auxiliary_resources": Object{"watchdog": Object{"samples": 0, "peak_footprint_bytes": 0, "peak_resident_bytes": 0, "measurement_failures": 0}, "broker": Object{"samples": 0, "peak_footprint_bytes": 0, "peak_resident_bytes": 0, "measurement_failures": 0}}}
	if deathTest {
		report["kind"] = "qemu_watchdog_death"
		report["stop_events_observed"] = false
		report["normal_completion_disabled"] = true
		report["child_signal_scope"] = "broker signals only watchdog; native guardian performs identity-checked target cleanup"
		report["death_test_contract"] = Object{"input_transfer_started": false, "ordinary_exchange_finished_permitted": false, "workspace_relay_continues": true}
	}
	var client *net.UnixConn
	var watchdog, guardian Object
	var watchdogStarted Object
	tracked := []Object{}
	registered := false
	socketEvents := []Object{}
	defer func() {
		if client != nil {
			client.Close()
		}
		diskEvents, err := NativeEvents(directory)
		if err != nil {
			report["events"] = []any{}
			report["event_readback_error"] = err.Error()
			report["passed"] = false
		} else {
			report["events"] = objectsAny(diskEvents)
		}
		all := append(append([]Object{}, socketEvents...), diskEvents...)
		known := map[string]Object{}
		if watchdog != nil {
			known[identityKey(watchdog)] = watchdog
		}
		for _, id := range tracked {
			known[identityKey(id)] = id
		}
		for _, event := range all {
			kind := Str(event, "event")
			if kind == "WATCHDOG_STARTED" || kind == "GUARDIAN_READY" {
				role := "watchdog"
				if kind == "GUARDIAN_READY" {
					role = "guardian"
				}
				id, er := ProcessIdentity(event, role)
				if er != nil {
					report["cleanup_identity_error"] = er.Error()
					report["passed"] = false
				} else {
					known[identityKey(id)] = id
				}
			}
			if kind == "MONITOR_READY" {
				ids, er := identities(event["processes"])
				if er != nil {
					report["cleanup_identity_error"] = er.Error()
					report["passed"] = false
				} else {
					for _, id := range ids {
						known[identityKey(id)] = id
					}
				}
			}
		}
		if result := Map(report, "guardian_result"); result != nil {
			for _, row := range List(result, "targets") {
				m, _ := row.(Object)
				id, er := ProcessIdentity(m, "guardian_target")
				if er == nil {
					if _, ok := known[identityKey(id)]; !ok {
						known[identityKey(id)] = id
					}
				}
			}
		}
		state := CommandResult(context.Background(), []string{"/bin/launchctl", "print", target}, 15*time.Second)
		if registered || Int(state, "exit_status") == 0 {
			report["bootout"] = CommandResult(context.Background(), []string{"/bin/launchctl", "bootout", target}, 15*time.Second)
		}
		ordered := make([]Object, 0, len(known))
		for _, id := range known {
			ordered = append(ordered, id)
		}
		sort.Slice(ordered, func(i, j int) bool {
			a := Str(ordered[i], "role") == "guardian" || Str(ordered[i], "role") == "watchdog"
			b := Str(ordered[j], "role") == "guardian" || Str(ordered[j], "role") == "watchdog"
			if a != b {
				return !a
			}
			return Int(ordered[i], "pid") < Int(ordered[j], "pid")
		})
		before := ReadbackAll(ordered)
		report["cleanup_before"] = before
		for _, row := range before {
			m := row.(Object)
			if m["same_identity_live"] == true {
				id := Map(m, "identity")
				current := IdentityReadback(id)
				if current["same_identity_live"] == true {
					if er := signalOwned(id, syscall.SIGKILL); er != nil {
						report["cleanup_signal_errors"] = append(List(report, "cleanup_signal_errors"), Object{"identity": id, "error": er.Error()})
					}
					report["broker_signals"] = append(List(report, "broker_signals"), Object{"identity": id, "signal": int(syscall.SIGKILL), "purpose": "emergency_owned_cleanup"})
					report["emergency_owned_cleanup"] = true
				}
				report["passed"] = false
			} else if m["same_identity_live"] == nil {
				report["identity_measurement_failures"] = append(List(report, "identity_measurement_failures"), m)
				report["passed"] = false
			}
		}
		until := time.Now().Add(2 * time.Second)
		after := ReadbackAll(ordered)
		for len(ordered) > 0 && !AllExited(after) && time.Now().Before(until) {
			time.Sleep(10 * time.Millisecond)
			after = ReadbackAll(ordered)
		}
		report["cleanup_after"] = after
		report["cleanup_all_exited"] = AllExited(after)
		if len(ordered) > 0 && !AllExited(after) {
			report["passed"] = false
		}
		for _, v := range after {
			m := v.(Object)
			if m["same_identity_live"] == nil {
				report["identity_measurement_failures"] = append(List(report, "identity_measurement_failures"), m)
			}
		}
		service := CommandResult(context.Background(), []string{"/bin/launchctl", "print", target}, 15*time.Second)
		report["service_readback"] = service
		report["temporary_service_absent"] = Int(service, "exit_status") == 113 && stringsContains(Str(service, "stderr"), "Could not find service")
		report["passed"] = Bool(report, "passed") && Bool(report, "temporary_service_absent")
		events, er := NativeEvents(directory)
		if er != nil {
			report["event_readback_error"] = er.Error()
			report["passed"] = false
		} else {
			report["events"] = objectsAny(events)
		}
		if deathTest {
			for _, event := range append(append([]Object{}, socketEvents...), events...) {
				if Str(event, "event") == "STOP_BEGIN" || Str(event, "event") == "FINISHED" {
					report["stop_events_observed"] = true
				}
			}
			report["passed"] = Bool(report, "passed") && report["stop_events_observed"] == false && report["emergency_owned_cleanup"] != true
		}
		if Bool(report, "passed") {
			report["status"] = "verified"
		} else {
			report["status"] = "failed"
		}
		if er = control.Record(out, report); er != nil {
			returned = er
		}
	}()
	fail := func(er error) (Object, error) {
		report["error"] = er.Error()
		report["status"] = "failed"
		report["passed"] = false
		return report, nil
	}
	bootstrap, e := control.Bootstrap(ctx)
	report["bootstrap"] = bootstrap
	if e != nil {
		return fail(e)
	}
	if Int(bootstrap, "exit_status") != 0 || bootstrap["failure"] != nil || bootstrap["start_acknowledged"] != true || bootstrap["stop_verified"] != true {
		report["status"] = "blocked"
		return report, nil
	}
	registered = true
	connectUntil := time.Now().Add(5 * time.Second)
	for time.Now().Before(connectUntil) {
		disk, e := NativeEvents(directory)
		if e != nil {
			return fail(e)
		}
		startedEvent := firstEvent(disk, "WATCHDOG_STARTED")
		socketPath := filepath.Join(directory, "watch.sock")
		if startedEvent != nil && !missing(socketPath) {
			if !Equal(startedEvent["process_group"], startedEvent["pid"]) {
				return fail(Error("NATIVE_START_IDENTITY_INVALID"))
			}
			watchdog, e = ProcessIdentity(startedEvent, "watchdog")
			if e != nil {
				return fail(e)
			}
			watchdogStarted = startedEvent
			if _, e = Owned(socketPath, unix.S_IFSOCK, 0600); e != nil {
				return fail(e)
			}
			connection, er := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			if er != nil {
				return fail(er)
			}
			client = connection
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if client == nil {
		return fail(Error("NATIVE_IPC_UNAVAILABLE"))
	}
	pending := []byte{}
	nextHeartbeat := time.Time{}
	cancelSent := false
	heartbeatClosed := false
	end := connectUntil.Add(time.Duration(control.Profile.TimeoutSeconds+10) * time.Second)
	for time.Now().Before(end) {
		if progress != nil {
			if e = progress(report); e != nil {
				return fail(e)
			}
		}
		if ctx.Err() != nil && !cancelSent {
			_ = client.SetWriteDeadline(time.Now().Add(time.Second))
			if _, e = client.Write([]byte("{\"event\":\"cancel\"}\n")); e != nil {
				return fail(e)
			}
			cancelSent = true
		}
		if !cancelSent && !heartbeatClosed && !time.Now().Before(nextHeartbeat) {
			disk, e := NativeEvents(directory)
			if e != nil {
				return fail(e)
			}
			allowed, e := control.AuthorizeStart(disk)
			if e != nil {
				return fail(e)
			}
			if !allowed {
				if control.StartDeniedReason != "" {
					report["start_denied_reason"] = control.StartDeniedReason
					_ = client.SetWriteDeadline(time.Now().Add(time.Second))
					_, e = client.Write([]byte("{\"event\":\"cancel\"}\n"))
					if e != nil {
						return fail(e)
					}
					cancelSent = true
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			_ = client.SetWriteDeadline(time.Now().Add(time.Second))
			if _, e = client.Write([]byte("{\"event\":\"heartbeat\"}\n{\"event\":\"start\"}\n")); e != nil {
				if errorsIsPipe(e) {
					heartbeatClosed = true
				} else {
					return fail(e)
				}
			}
			nextHeartbeat = time.Now().Add(500 * time.Millisecond)
			if watchdog == nil {
				if first := firstEvent(disk, "WATCHDOG_STARTED"); first != nil {
					watchdog, e = ProcessIdentity(first, "watchdog")
					if e != nil {
						return fail(e)
					}
				}
			}
			r.sampleResources(report, watchdog)
		}
		_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buffer := make([]byte, 65536)
		n, er := client.Read(buffer)
		if n > 0 {
			pending = append(pending, buffer[:n]...)
			if len(pending) > 131072 {
				return fail(Error("NATIVE_RECEIVE_LIMIT"))
			}
			for {
				newline := bytes.IndexByte(pending, '\n')
				if newline < 0 {
					break
				}
				line := pending[:newline]
				pending = pending[newline+1:]
				if len(line) > 65536 || len(socketEvents) >= 2048 {
					return fail(Error("NATIVE_EVENT_LIMIT"))
				}
				event, e := Decode(line)
				if e != nil {
					return fail(e)
				}
				socketEvents = append(socketEvents, event)
				report["broker_events"] = objectsAny(socketEvents)
				switch Str(event, "event") {
				case "GUARDIAN_READY":
					guardian, e = ProcessIdentity(event, "guardian")
					if e != nil {
						return fail(e)
					}
					first := watchdogStarted
					if first == nil || !Equal(first["process_group"], first["pid"]) || !Equal(event["process_group"], first["pid"]) {
						return fail(Error("GUARDIAN_GROUP_INVALID"))
					}
				case "MONITOR_READY":
					tracked, e = identities(event["processes"])
					if e != nil {
						return fail(e)
					}
					roles := map[string]bool{}
					pids := map[int64]bool{}
					for _, id := range tracked {
						roles[Str(id, "role")] = true
						pids[Int(id, "pid")] = true
					}
					if len(tracked) != 3 || len(roles) != 3 || !roles["guardian"] || !roles["vm"] || !roles["helper"] || len(pids) != 3 || guardian == nil || !containsIdentity(tracked, guardian) {
						return fail(Error("NATIVE_MONITOR_IDENTITIES_INVALID"))
					}
					report["qemu_started"] = Str(config, "mode") == "qemu"
				case "TRANSFER_ALLOWED":
					if deathTest {
						if cancelSent || ctx.Err() != nil {
							return fail(Error("DEATH_FIXTURE_CANCELLED"))
						}
						socketEvents, e = r.watchdogDeath(ctx, config, report, client, pending, socketEvents, tracked)
						report["broker_events"] = objectsAny(socketEvents)
						if e != nil {
							return fail(e)
						}
						return report, nil
					}
				case "FINISHED":
					report["terminal"] = event
					if deathTest {
						return fail(Error("NATIVE_STOP_PRECEDED_DEATH_FIXTURE"))
					}
					first := watchdogStarted
					if first == nil {
						return fail(Error("NATIVE_START_IDENTITY_MISSING"))
					}
					watchdog, e = ProcessIdentity(first, "watchdog")
					if e != nil {
						return fail(e)
					}
					finished, e := identities(event["processes"])
					if e != nil {
						return fail(e)
					}
					primary, e := primaryIdentities(finished, watchdog, objectsFromList(report["broker_events"]))
					if e != nil {
						return fail(e)
					}
					for _, id := range tracked {
						if !containsIdentity(primary, id) {
							return fail(Error("NATIVE_TERMINAL_IDENTITIES_DIFFER"))
						}
					}
					for _, v := range List(event, "processes") {
						if m, ok := v.(Object); !ok || m["exited"] != true {
							return fail(Error("NATIVE_TERMINAL_STOP_UNCONFIRMED"))
						}
					}
					if len(primary) > 0 {
						death := false
						result, e := GuardianResult(directory, watchdog, primary, &death)
						if e != nil {
							return fail(e)
						}
						report["guardian_result"] = result
						report["guardian_result_verified"] = true
					}
					tracked = finished
					expected := Str(config, "expected_stop_reason")
					if expected == "" {
						expected = "EXCHANGE_COMPLETE"
					}
					report["expected_terminal_reason"] = expected
					exit := Map(event, "guardian_exit")
					report["passed"] = event["all_exited"] == true && Str(event, "reason") == expected && event["transfer_allowed"] == true && Bool(exit, "confirmed") && Bool(exit, "result_valid")
					return report, nil
				}
			}
		}
		if er != nil {
			if timeout, ok := er.(net.Error); ok && timeout.Timeout() {
				continue
			}
			if er == io.EOF {
				break
			}
			return fail(er)
		}
	}
	return fail(Error("NATIVE_TERMINAL_UNAVAILABLE"))
}
func objectsAny(rows []Object) []any {
	result := make([]any, len(rows))
	for i, v := range rows {
		result[i] = v
	}
	return result
}
func objectsFromList(value any) []Object {
	a, _ := value.([]any)
	r := make([]Object, 0, len(a))
	for _, v := range a {
		if m, ok := v.(Object); ok {
			r = append(r, m)
		}
	}
	return r
}
func firstEvent(rows []Object, name string) Object {
	for _, e := range rows {
		if Str(e, "event") == name {
			return e
		}
	}
	return nil
}
func errorsIsPipe(e error) bool { return errors.Is(e, syscall.EPIPE) }
func (r *Runtime) sampleResources(report, watchdog Object) {
	for role, identity := range map[string]Object{"watchdog": watchdog, "broker": {"pid": os.Getpid()}} {
		sample := Map(Map(report, "auxiliary_resources"), role)
		pid := Int(identity, "pid")
		var actual Object
		var e error
		if pid > 1 {
			actual, e = NativeIdentity(int(pid))
		}
		if e != nil || actual == nil || role == "watchdog" && !Equal(actual["start_abstime"], identity["start_abstime"]) {
			sample["measurement_failures"] = Int(sample, "measurement_failures") + 1
			continue
		}
		sample["samples"] = Int(sample, "samples") + 1
		for _, pair := range [][2]string{{"peak_footprint_bytes", "footprint_bytes"}, {"peak_resident_bytes", "resident_bytes"}} {
			if Int(actual, pair[1]) > Int(sample, pair[0]) {
				sample[pair[0]] = actual[pair[1]]
			}
		}
	}
}
