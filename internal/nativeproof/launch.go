package nativeproof

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

type eventStream struct {
	client  *net.UnixConn
	pending []byte
	events  []object
}

func (s *eventStream) receive(timeout time.Duration) (bool, error) {
	if err := s.client.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, err
	}
	buffer := make([]byte, 65536)
	n, err := s.client.Read(buffer)
	s.pending = append(s.pending, buffer[:n]...)
	if len(s.pending) > 131072 {
		return false, failure("NATIVE_PROOF_RECEIVE_LIMIT")
	}
	for {
		end := bytes.IndexByte(s.pending, '\n')
		if end < 0 {
			break
		}
		if end > 65536 || len(s.events) >= 2048 {
			return false, failure("NATIVE_PROOF_EVENT_LIMIT")
		}
		event, decodeErr := hostvm.Decode(s.pending[:end])
		if decodeErr != nil {
			return false, decodeErr
		}
		s.events = append(s.events, event)
		s.pending = s.pending[end+1:]
	}
	if err != nil {
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			return true, nil
		}
		if err == io.EOF {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *eventStream) deathEvents(control string) ([]object, error) {
	for {
		count := len(s.events)
		open, err := s.receive(time.Millisecond)
		if err != nil {
			return nil, err
		}
		if !open || len(s.events) == count {
			break
		}
	}
	if len(s.pending) != 0 {
		return nil, failure("NATIVE_PROOF_EVENT_STREAM_INCOMPLETE")
	}
	disk, err := hostvm.NativeEvents(control)
	if err != nil {
		return nil, err
	}
	for _, event := range append(append([]object{}, s.events...), disk...) {
		if hostvm.Str(event, "event") == "STOP_BEGIN" || hostvm.Str(event, "event") == "FINISHED" {
			return nil, failure("NATIVE_PROOF_STOP_PRECEDED_DEATH")
		}
	}
	return disk, nil
}

func milestoneProof(disk, socket []object, config object) (object, []object, error) {
	names := []string{"WATCHDOG_STARTED", "GUARDIAN_READY", "MONITOR_READY", "TRANSFER_ALLOWED"}
	channels := [2]map[string]object{}
	for i, rows := range [][]object{disk, socket} {
		channels[i] = map[string]object{}
		previous := -1
		for _, row := range rows {
			for step, name := range names {
				if hostvm.Str(row, "event") != name {
					continue
				}
				if step <= previous || channels[i][name] != nil {
					return nil, nil, failure("NATIVE_PROOF_EVENT_ORDER_INVALID")
				}
				previous, channels[i][name] = step, row
			}
		}
	}
	ordered := make([]object, len(names))
	for i, name := range names {
		logged, delivered := channels[0][name], channels[1][name]
		if i < 3 && logged == nil || i > 0 && delivered == nil || logged != nil && delivered != nil && !hostvm.Equal(logged, delivered) {
			return nil, nil, failure("NATIVE_PROOF_EVENT_ORDER_INVALID")
		}
		ordered[i] = logged
		if logged == nil {
			ordered[i] = delivered
		}
	}
	watchdog, err := hostvm.ProcessIdentity(ordered[0], "watchdog")
	if err != nil || hostvm.Str(ordered[0], "mode") != "fixture" || !hostvm.Equal(ordered[0]["process_group"], watchdog["pid"]) || !hostvm.Equal(ordered[0]["continuous_start_ns"], config["continuous_start_ns"]) || !hostvm.Equal(ordered[0]["continuous_deadline_ns"], config["continuous_deadline_ns"]) ||
		hostvm.Int(ordered[2], "continuous_ns") < hostvm.Int(config, "continuous_start_ns") || hostvm.Int(ordered[3], "continuous_ns") < hostvm.Int(ordered[2], "continuous_ns") || hostvm.Int(ordered[3], "continuous_ns") >= hostvm.Int(config, "continuous_deadline_ns") {
		return nil, nil, failure("NATIVE_PROOF_EVENT_ORDER_INVALID")
	}
	children, err := hostvm.RecordedChildren(ordered, hostvm.Int(watchdog, "pid"))
	if err != nil || len(children) != 3 {
		return nil, nil, failure("NATIVE_PROOF_IDENTITIES_INVALID")
	}
	return watchdog, children, nil
}

func signalIdentity(identity object, group int64) error {
	back := hostvm.IdentityReadback(identity)
	actual := hostvm.Map(back, "actual")
	if back["same_identity_live"] != true || hostvm.Int(actual, "uid") != int64(os.Getuid()) || hostvm.Int(actual, "process_group") != group {
		return failure("NATIVE_PROOF_SIGNAL_IDENTITY_CHANGED")
	}
	return syscall.Kill(int(hostvm.Int(identity, "pid")), syscall.SIGKILL)
}

func killWatchdog(ctx context.Context, stream *eventStream, control string, config, report object) error {
	disk, err := stream.deathEvents(control)
	if err != nil || ctx.Err() != nil {
		return failure("NATIVE_PROOF_STOP_PRECEDED_DEATH")
	}
	watchdog, children, err := milestoneProof(disk, stream.events, config)
	if err != nil {
		return err
	}
	ids := append([]object{watchdog}, children...)
	seen := map[int64]bool{}
	for _, id := range ids {
		pid := hostvm.Int(id, "pid")
		if seen[pid] {
			return failure("NATIVE_PROOF_IDENTITIES_INVALID")
		}
		seen[pid] = true
	}
	report["death_test_processes"] = objects(ids)
	before := hostvm.ReadbackAll(ids)
	report["death_test_before"] = before
	for _, item := range before {
		row := item.(object)
		actual := hostvm.Map(row, "actual")
		if row["same_identity_live"] != true || hostvm.Int(actual, "uid") != int64(os.Getuid()) || !hostvm.Equal(actual["process_group"], watchdog["pid"]) {
			return failure("NATIVE_PROOF_PROCESSES_NOT_ALL_LIVE")
		}
	}
	report["death_test_parent_at_signal"] = hostvm.IdentityReadback(watchdog)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	started := time.Now()
	if err = signalIdentity(watchdog, hostvm.Int(watchdog, "pid")); err != nil {
		return err
	}
	report["broker_signals"] = []any{object{"identity": watchdog, "signal": int(syscall.SIGKILL), "purpose": "watchdog_death_fixture"}}
	after := hostvm.ReadbackAll(ids)
	for !hostvm.AllExited(after) && time.Since(started) < 10*time.Second {
		time.Sleep(10 * time.Millisecond)
		after = hostvm.ReadbackAll(ids)
	}
	report["termination_elapsed_ns"] = time.Since(started).Nanoseconds()
	report["termination_elapsed_seconds"] = time.Since(started).Seconds()
	report["death_test_after"] = after
	report["all_exited_without_child_signal"] = hostvm.AllExited(after)
	if _, err = stream.deathEvents(control); err != nil {
		return err
	}
	death := true
	guardian, err := hostvm.GuardianResult(control, watchdog, children, &death)
	if err != nil {
		return err
	}
	vmKilled := false
	for _, child := range children {
		if hostvm.Str(child, "role") != "vm" {
			continue
		}
		for _, item := range hostvm.List(guardian, "targets") {
			target, _ := item.(object)
			if hostvm.Equal(target["pid"], child["pid"]) && hostvm.Equal(target["start_abstime"], child["start_abstime"]) {
				vmKilled = target["term_sent"] == true && target["sigkill_sent"] == true
			}
		}
	}
	report["guardian_result"] = guardian
	report["guardian_result_verified"] = true
	report["guardian_fixture_vm_sigkill_confirmed"] = vmKilled
	if !vmKilled || !hostvm.AllExited(after) || hostvm.Int(report, "termination_elapsed_ns") >= 10*1e9 || ctx.Err() != nil {
		return failure("NATIVE_PROOF_GUARDIAN_DEATH_UNCONFIRMED")
	}
	report["passed"] = true
	return nil
}

func monitor(ctx context.Context, r *hostvm.Runtime, config, report object, control, out string) error {
	target := hostvm.Str(report, "target")
	absent, err := hostvm.ServiceAbsent(target)
	if err != nil || !absent {
		return failure("NATIVE_PROOF_SERVICE_ALREADY_PRESENT")
	}
	boot, err := hostvm.ControlledCommand(ctx, []string{"/bin/launchctl", "bootstrap", "gui/" + uidString(), filepath.Join(control, "watchdog.plist")}, 15, filepath.Join(out, "native-bootstrap-owner.json"), filepath.Join(r.Root, "experiments/host"), 3, filepath.Join(out, "native-bootstrap-dispatched.json"))
	report["bootstrap"] = boot
	if err != nil {
		return err
	}
	if hostvm.Int(boot, "exit_status") != 0 || boot["failure"] != nil || boot["start_acknowledged"] != true || boot["stop_verified"] != true {
		return failure("NATIVE_PROOF_BOOTSTRAP_FAILED")
	}
	until := time.Now().Add(5 * time.Second)
	var client *net.UnixConn
	for time.Now().Before(until) && ctx.Err() == nil {
		disk, err := hostvm.NativeEvents(control)
		if err != nil {
			return err
		}
		if first(disk, "WATCHDOG_STARTED") != nil {
			socket := filepath.Join(control, "watch.sock")
			if _, err = hostvm.Owned(socket, unix.S_IFSOCK, 0600); err == nil {
				client, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
				if err != nil {
					return err
				}
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if client == nil {
		return failure("NATIVE_PROOF_IPC_UNAVAILABLE")
	}
	defer client.Close()
	stream := &eventStream{client: client}
	defer func() { report["broker_events"] = objects(stream.events) }()
	nextHeartbeat := time.Time{}
	for time.Now().Before(until.Add(310*time.Second)) && ctx.Err() == nil {
		if !time.Now().Before(nextHeartbeat) {
			if err = client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				return err
			}
			if _, err = client.Write([]byte("{\"event\":\"heartbeat\"}\n{\"event\":\"start\"}\n")); err != nil {
				return err
			}
			nextHeartbeat = time.Now().Add(500 * time.Millisecond)
		}
		open, err := stream.receive(200 * time.Millisecond)
		if err != nil {
			return err
		}
		if first(stream.events, "TRANSFER_ALLOWED") != nil && config["fixture_resource_fault"] != nil {
			return resourceStop(ctx, client, stream, control, config, report)
		}
		for _, event := range stream.events {
			if hostvm.Str(event, "event") == "STOP_BEGIN" || hostvm.Str(event, "event") == "FINISHED" {
				return failure("NATIVE_PROOF_STOP_PRECEDED_DEATH")
			}
		}
		if first(stream.events, "TRANSFER_ALLOWED") != nil {
			return killWatchdog(ctx, stream, control, config, report)
		}
		if !open {
			return failure("NATIVE_PROOF_IPC_CLOSED")
		}
	}
	return failure("NATIVE_PROOF_DEADLINE_OR_CANCELLED")
}

// resourceStop keeps the broker heartbeat and sends no signal while it waits for the native resource decision, then checks that decision and the guardian's identity-checked cleanup.
func resourceStop(ctx context.Context, client *net.UnixConn, stream *eventStream, control string, config, report object) error {
	disk, err := hostvm.NativeEvents(control)
	if err != nil {
		return err
	}
	watchdog, children, err := milestoneProof(disk, stream.events, config)
	if err != nil {
		return err
	}
	ids := append([]object{watchdog}, children...)
	report["resource_processes"] = objects(ids)
	report["resource_before"] = hostvm.ReadbackAll(ids)
	deadline := time.Now().Add(15 * time.Second)
	nextHeartbeat := time.Time{}
	open := true
	for open && time.Now().Before(deadline) && ctx.Err() == nil {
		if first(stream.events, "STOP_BEGIN") == nil && !time.Now().Before(nextHeartbeat) {
			if err = client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				return err
			}
			if _, err = client.Write([]byte("{\"event\":\"heartbeat\"}\n")); err != nil {
				return err
			}
			nextHeartbeat = time.Now().Add(500 * time.Millisecond)
		}
		if open, err = stream.receive(200 * time.Millisecond); err != nil {
			return err
		}
	}
	stop, transfer := first(stream.events, "STOP_BEGIN"), first(stream.events, "TRANSFER_ALLOWED")
	report["resource_stop"] = stop
	if stop == nil {
		return failure("NATIVE_RESOURCE_DECISION_MISSING")
	}
	if err = resourceDecision(hostvm.Str(config, "fixture_resource_fault"), transfer, stop, report); err != nil {
		return err
	}
	after := hostvm.ReadbackAll(ids)
	for started := time.Now(); !hostvm.AllExited(after) && time.Since(started) < 15*time.Second; after = hostvm.ReadbackAll(ids) {
		time.Sleep(20 * time.Millisecond)
	}
	report["resource_after"] = after
	logged, err := hostvm.NativeEvents(control)
	if err != nil {
		return err
	}
	if !hostvm.Equal(first(logged, "STOP_BEGIN"), stop) {
		return failure("NATIVE_RESOURCE_EVENT_MISMATCH")
	}
	death := false
	guardian, err := hostvm.GuardianResult(control, watchdog, children, &death)
	if err != nil {
		return err
	}
	report["guardian_result"] = guardian
	report["guardian_result_verified"] = true
	if !hostvm.AllExited(after) {
		return failure("NATIVE_RESOURCE_TARGETS_NOT_EXITED")
	}
	report["passed"] = true
	return nil
}

// resourceDecision compares the native STOP_BEGIN with the pinned expectation; the human reason text is matched only as the fixed reason code.
func resourceDecision(fault string, transfer, stop, report object) error {
	expected := resourceExpectations[fault]
	evidence := hostvm.Map(stop, "resource_evidence")
	elapsed := hostvm.Int(stop, "continuous_ns") - hostvm.Int(transfer, "continuous_ns")
	report["resource_decision_elapsed_ns"] = elapsed
	ok := expected != nil && transfer != nil && hostvm.Str(stop, "reason") == hostvm.Str(expected, "reason") && hostvm.Str(evidence, "trigger") == hostvm.Str(expected, "trigger") &&
		elapsed >= hostvm.Int(expected, "min_elapsed_ns") && elapsed <= hostvm.Int(expected, "max_elapsed_ns")
	switch fault {
	case "pressure-warning":
		ok = ok && hostvm.Int(evidence, "warning_elapsed_ns") >= hostvm.Int(expected, "min_warning_elapsed_ns")
	case "measure-failure":
		ok = ok && hostvm.Int(evidence, "attempts") == hostvm.Int(expected, "attempts")
	case "memory-limit":
		ok = ok && hostvm.Int(evidence, "limit_bytes") == hostvm.Int(expected, "limit_bytes") && hostvm.Int(hostvm.Map(evidence, "sample"), "footprint_bytes") == hostvm.Int(expected, "footprint_bytes")
	}
	if !ok {
		return failure("NATIVE_RESOURCE_DECISION_UNEXPECTED")
	}
	return nil
}
