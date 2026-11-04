package hostvm

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func deathFixtureConfig(r *Runtime, config Object) bool {
	if config["watchdog_death_fixture"] != true || Str(config, "mode") != "qemu" || Str(config, "fixture") != "transfer" || config["require_launchagent"] != true {
		return false
	}
	arguments, ok := Strings(config["helper_argv"])
	want := []string{filepath.Join(r.VM, ".build/filegate-bridge"), Str(config, "run_directory"), "--fixture", "transfer", "--watchdog-relay", "--hold-before-input-for-watchdog-death"}
	return ok && Equal(arguments, want)
}

func deathHoldObservation(run string) (Object, []byte, error) {
	observation, body, err := Read(filepath.Join(run, "fixture-observation.json"), ControlLimit)
	if err != nil {
		return nil, nil, err
	}
	if !Fields(observation, "schema", "fixture", "death_test", "input_transfer_started", "ordinary_exchange_finished_permitted", "workspace_relay_continues", "ready_acknowledged") ||
		Int(observation, "schema") != 2 || Str(observation, "fixture") != "transfer" || observation["death_test"] != true || observation["input_transfer_started"] != false ||
		observation["ordinary_exchange_finished_permitted"] != false || observation["workspace_relay_continues"] != true || observation["ready_acknowledged"] != true ||
		!missing(filepath.Join(run, "exchange.json")) || !missing(filepath.Join(run, "exchange.json.pending")) {
		return nil, nil, Error("DEATH_FIXTURE_TRANSFER_NOT_HELD")
	}
	return observation, body, nil
}

func deathEvents(client *net.UnixConn, pending []byte, received []Object, directory string) ([]Object, []Object, error) {
	if client.SetReadDeadline(time.Now().Add(time.Millisecond)) != nil {
		return nil, nil, Error("DEATH_FIXTURE_EVENT_READ_FAILED")
	}
	for {
		buffer := make([]byte, 65536)
		n, err := client.Read(buffer)
		pending = append(pending, buffer[:n]...)
		if len(pending) > 131072 {
			return nil, nil, Error("NATIVE_RECEIVE_LIMIT")
		}
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() || err == io.EOF {
				break
			}
			return nil, nil, err
		}
	}
	for len(pending) != 0 {
		newline := bytes.IndexByte(pending, '\n')
		if newline < 0 || newline > 65536 || len(received) >= 2048 {
			return nil, nil, Error("DEATH_FIXTURE_EVENT_STREAM_INCOMPLETE")
		}
		value, err := Decode(pending[:newline])
		if err != nil {
			return nil, nil, err
		}
		received = append(received, value)
		pending = pending[newline+1:]
	}
	disk, err := NativeEvents(directory)
	if err != nil {
		return nil, nil, err
	}
	for _, event := range append(append([]Object{}, received...), disk...) {
		if Str(event, "event") == "STOP_BEGIN" || Str(event, "event") == "FINISHED" {
			return received, disk, Error("NATIVE_STOP_PRECEDED_DEATH_FIXTURE")
		}
	}
	return received, disk, nil
}

func deathMilestones(disk, received []Object) ([]Object, error) {
	names := []string{"WATCHDOG_STARTED", "GUARDIAN_READY", "MONITOR_READY", "TRANSFER_ALLOWED"}
	channels := make([]map[string]Object, 2)
	for i, events := range [][]Object{disk, received} {
		channels[i] = map[string]Object{}
		previous := -1
		for _, event := range events {
			name := Str(event, "event")
			if name == "STOP_BEGIN" || name == "FINISHED" {
				return nil, Error("NATIVE_STOP_PRECEDED_DEATH_FIXTURE")
			}
			for step, expected := range names {
				if name != expected {
					continue
				}
				if step <= previous || channels[i][name] != nil {
					return nil, Error("DEATH_FIXTURE_EVENT_ORDER_INVALID")
				}
				previous = step
				channels[i][name] = event
			}
		}
	}
	ordered := make([]Object, len(names))
	for i, name := range names {
		logged, delivered := channels[0][name], channels[1][name]
		// Native logging holds post-release frames in memory; the socket is the transfer witness.
		if i < 3 && logged == nil || i > 0 && delivered == nil || logged != nil && delivered != nil && !Equal(logged, delivered) {
			return nil, Error("DEATH_FIXTURE_EVENT_ORDER_INVALID")
		}
		ordered[i] = logged
		if ordered[i] == nil {
			ordered[i] = delivered
		}
	}
	if Int(ordered[2], "continuous_ns") <= 0 || Int(ordered[3], "continuous_ns") < Int(ordered[2], "continuous_ns") {
		return nil, Error("DEATH_FIXTURE_EVENT_ORDER_INVALID")
	}
	return ordered, nil
}

func (r *Runtime) watchdogDeath(ctx context.Context, config, report Object, client *net.UnixConn, pending []byte, events, tracked []Object) ([]Object, error) {
	if !deathFixtureConfig(r, config) || ctx.Err() != nil {
		return events, Error("DEATH_FIXTURE_CONFIGURATION_INVALID")
	}
	directory := Str(report, "control_directory")
	var disk []Object
	var err error
	events, disk, err = deathEvents(client, pending, events, directory)
	if err != nil {
		return events, err
	}
	milestones, err := deathMilestones(disk, events)
	if err != nil {
		return events, err
	}
	first := milestones[0]
	watchdog, err := ProcessIdentity(first, "watchdog")
	if err != nil || !Equal(first["process_group"], first["pid"]) || len(tracked) != 3 {
		return events, Error("DEATH_FIXTURE_IDENTITIES_INVALID")
	}
	recorded, err := RecordedChildren(milestones, Int(watchdog, "pid"))
	if err != nil || len(recorded) != len(tracked) {
		return events, Error("DEATH_FIXTURE_IDENTITIES_INVALID")
	}
	for _, id := range tracked {
		if !containsIdentity(recorded, id) {
			return events, Error("DEATH_FIXTURE_IDENTITIES_INVALID")
		}
	}
	identities := append([]Object{watchdog}, tracked...)
	pids, roles := map[int64]bool{}, map[string]bool{}
	for _, id := range identities {
		pid, role := Int(id, "pid"), Str(id, "role")
		if pids[pid] || roles[role] || role != "watchdog" && role != "guardian" && role != "vm" && role != "helper" {
			return events, Error("DEATH_FIXTURE_IDENTITIES_INVALID")
		}
		pids[pid], roles[role] = true, true
	}
	until := time.Now().Add(2 * time.Second)
	var observation Object
	for {
		observation, _, err = deathHoldObservation(Str(config, "run_directory"))
		if err == nil {
			break
		}
		if ctx.Err() != nil || time.Now().After(until) {
			return events, Error("DEATH_FIXTURE_HOLD_UNCONFIRMED")
		}
		time.Sleep(10 * time.Millisecond)
	}
	events, disk, err = deathEvents(client, nil, events, directory)
	if err != nil {
		return events, err
	}
	report["death_fixture_observation"] = observation
	report["death_test_processes"] = objectsAny(identities)
	before := ReadbackAll(identities)
	report["death_test_before"] = before
	for _, value := range before {
		back := value.(Object)
		actual := Map(back, "actual")
		if back["same_identity_live"] != true || Int(actual, "uid") != int64(os.Getuid()) || !Equal(actual["process_group"], watchdog["pid"]) {
			return events, Error("DEATH_FIXTURE_PROCESSES_NOT_ALL_LIVE")
		}
	}
	parentAtSignal := IdentityReadback(watchdog)
	report["death_test_parent_at_signal"] = parentAtSignal
	if parentAtSignal["same_identity_live"] != true || ctx.Err() != nil {
		return events, Error("DEATH_FIXTURE_WATCHDOG_CHANGED")
	}
	start := time.Now()
	if err = signalOwned(watchdog, syscall.SIGKILL); err != nil {
		return events, err
	}
	report["broker_signals"] = append(List(report, "broker_signals"), Object{"identity": watchdog, "signal": int(syscall.SIGKILL), "purpose": "watchdog_death_fixture"})
	after := ReadbackAll(identities)
	for !AllExited(after) && time.Since(start) < 10*time.Second {
		time.Sleep(10 * time.Millisecond)
		after = ReadbackAll(identities)
	}
	report["termination_elapsed_ns"] = time.Since(start).Nanoseconds()
	report["death_test_after"] = after
	report["all_exited_without_child_signal"] = AllExited(after)
	events, disk, err = deathEvents(client, nil, events, directory)
	if err != nil {
		return events, err
	}
	report["events"] = objectsAny(disk)
	report["stop_events_observed"] = false
	death := true
	result, err := GuardianResult(directory, watchdog, tracked, &death)
	if err != nil {
		return events, err
	}
	report["guardian_result"] = result
	report["guardian_result_verified"] = true
	report["passed"] = AllExited(after) && Int(report, "termination_elapsed_ns") < 10*1e9 && Bool(report, "qemu_started") && ctx.Err() == nil
	return events, nil
}

func (r *Runtime) validateDeathFixtureProof(native Object) error {
	if Str(native, "kind") != "qemu_watchdog_death" || native["passed"] != true || Map(native, "terminal") != nil || native["qemu_started"] != true ||
		native["normal_completion_disabled"] != true || native["all_exited_without_child_signal"] != true || native["stop_events_observed"] != false ||
		Int(native, "termination_elapsed_ns") < 0 || Int(native, "termination_elapsed_ns") >= 10*1e9 || native["guardian_result_verified"] != true || len(List(native, "identity_measurement_failures")) != 0 {
		return Error("NATIVE_WATCHDOG_DEATH_UNCONFIRMED")
	}
	config, _, err := Read(filepath.Join(Str(native, "control_directory"), "config.json"), ControlLimit)
	if err != nil || !deathFixtureConfig(r, config) {
		return Error("DEATH_FIXTURE_CONFIGURATION_INVALID")
	}
	observation, _, err := deathHoldObservation(Str(config, "run_directory"))
	if err != nil || !Equal(observation, native["death_fixture_observation"]) {
		return Error("DEATH_FIXTURE_TRANSFER_NOT_HELD")
	}
	ids, err := identities(native["death_test_processes"])
	if err != nil || len(ids) != 4 {
		return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
	}
	var watchdog Object
	children := []Object{}
	pids, roles := map[int64]bool{}, map[string]bool{}
	for _, id := range ids {
		pid, role := Int(id, "pid"), Str(id, "role")
		if pids[pid] || roles[role] || role != "watchdog" && role != "guardian" && role != "vm" && role != "helper" {
			return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
		}
		pids[pid], roles[role] = true, true
		if role == "watchdog" {
			watchdog = id
		} else {
			children = append(children, id)
		}
	}
	if watchdog == nil || len(children) != 3 {
		return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
	}
	for _, field := range []string{"death_test_before", "death_test_after"} {
		rows := List(native, field)
		if len(rows) != len(ids) {
			return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
		}
		for i, value := range rows {
			back, ok := value.(Object)
			if !ok || !Equal(back["identity"], ids[i]) || back["same_identity_live"] != (field == "death_test_before") {
				return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
			}
			if field == "death_test_before" {
				actual := Map(back, "actual")
				if Int(actual, "uid") != int64(os.Getuid()) || !Equal(actual["process_group"], watchdog["pid"]) || !Equal(actual["start_abstime"], ids[i]["start_abstime"]) {
					return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
				}
			}
		}
	}
	signals := List(native, "broker_signals")
	if len(signals) != 1 {
		return Error("DEATH_FIXTURE_CHILD_SIGNAL_OBSERVED")
	}
	signal, ok := signals[0].(Object)
	if !ok || !Equal(signal["identity"], watchdog) || Int(signal, "signal") != int64(syscall.SIGKILL) || Str(signal, "purpose") != "watchdog_death_fixture" {
		return Error("DEATH_FIXTURE_CHILD_SIGNAL_OBSERVED")
	}
	disk := objectsFromList(native["events"])
	milestones, err := deathMilestones(disk, objectsFromList(native["broker_events"]))
	if err != nil {
		return err
	}
	first := milestones[0]
	started, err := ProcessIdentity(first, "watchdog")
	if err != nil || !Equal(started, watchdog) || !Equal(first["process_group"], watchdog["pid"]) || Str(config, "owner_kind") != "scan" ||
		!Equal(first["continuous_start_ns"], config["continuous_start_ns"]) || !Equal(first["continuous_deadline_ns"], config["continuous_deadline_ns"]) ||
		Int(config, "continuous_deadline_ns")-Int(config, "continuous_start_ns") != 300*1e9 || Int(milestones[2], "continuous_ns") < Int(config, "continuous_start_ns") || Int(milestones[3], "continuous_ns") >= Int(config, "continuous_deadline_ns") {
		return Error("DEATH_FIXTURE_EVENT_ORDER_INVALID")
	}
	recorded, err := RecordedChildren(milestones, Int(watchdog, "pid"))
	if err != nil || len(recorded) != len(children) {
		return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
	}
	for _, id := range children {
		if !containsIdentity(recorded, id) {
			return Error("DEATH_FIXTURE_IDENTITIES_INVALID")
		}
	}
	if parent := Map(native, "death_test_parent_at_signal"); !Equal(parent["identity"], watchdog) || parent["same_identity_live"] != true {
		return Error("DEATH_FIXTURE_WATCHDOG_CHANGED")
	}
	death := true
	guardian, err := GuardianResult(Str(native, "control_directory"), watchdog, children, &death)
	if err != nil || !Equal(guardian, native["guardian_result"]) {
		return Error("NATIVE_GUARDIAN_DEATH_UNCONFIRMED")
	}
	return nil
}
