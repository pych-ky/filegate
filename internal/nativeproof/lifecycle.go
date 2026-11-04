package nativeproof

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

func uidString() string { return strconv.Itoa(os.Getuid()) }

func qualify(ctx context.Context, r *hostvm.Runtime, build object, buildDirectory, out string) (report object, returned error) {
	pins, err := sourcePins(r.Root)
	if err != nil {
		return nil, err
	}
	host, err := r.HostVersion()
	if err != nil {
		return nil, err
	}
	platform, err := r.NativePlatform()
	if err != nil {
		return nil, err
	}
	started, err := r.Clock()
	if err != nil {
		return nil, err
	}
	control, err := hostvm.RandomPath("fgw-")
	if err != nil {
		return nil, err
	}
	run, err := hostvm.RandomPath("fg-fixture-")
	if err != nil {
		return nil, err
	}
	target := fmt.Sprintf("gui/%d/com.filegate.stage0.integrated.%s", os.Getuid(), filepath.Base(control))
	config := object{"schema": 1, "mode": "fixture", "owner_kind": "scan", "require_launchagent": true, "run_directory": run, "control_directory": control,
		"continuous_start_ns": started, "continuous_deadline_ns": started + 300*1e9,
		"vm_argv": []string{r.NativeBinary, "fixture-child", "fixture-vm", "normal"}, "helper_argv": []string{r.NativeBinary, "fixture-child", "fixture-helper", "heartbeat-stop"}}
	boot, err := hostvm.BootUUID()
	if err != nil {
		return nil, err
	}
	intent := object{"schema": 1, "kind": "go_native_proof_intent", "control_directory": control, "run_directory": run, "target": target, "config": config,
		"boot_session_uuid": boot, "binary_sha256": build["binary_sha256"], "native_source_sha256": build["source_sha256"]}
	if _, err = hostvm.WriteNew(filepath.Join(out, "native-intent.json"), intent); err != nil {
		return nil, err
	}
	report = object{"schema": 1, "kind": "launchagent_death", "passed": false, "host": host, "native_platform": platform,
		"binary_sha256": build["binary_sha256"], "native_source_sha256": build["source_sha256"], "control_directory": control, "target": target,
		"qemu_started": false, "normal_completion_disabled": true, "stop_events_observed": false, "guardian_result_verified": false,
		"guardian_fixture_vm_sigkill_confirmed": false, "cleanup_all_exited": false, "temporary_service_absent": false, "broker_events": []any{}, "broker_signals": []any{}, "identity_measurement_failures": []any{},
		"implementation": "go", "python_dependency": false, "raw_allocation_bytes": 0, "global_slot_finalized": false,
		"child_signal_scope": "broker signals only watchdog; native guardian performs identity-checked target cleanup", "proof_scope": "fixed harmless native fixture children; no QEMU or product scan"}
	defer func() {
		if returned != nil {
			report["error"] = returned.Error()
			report["passed"] = false
		}
		if cleanupErr := cleanup(r, out, intent, report); cleanupErr != nil {
			report["cleanup_error"] = cleanupErr.Error()
			report["passed"] = false
			returned = cleanupErr
		}
		if err := verifyPins(r.Root, pins); err != nil {
			report["source_verification_error"] = err.Error()
			report["passed"] = false
			returned = err
		}
		binarySHA, binaryErr := hostvm.HashFile(r.NativeBinary)
		if binaryErr != nil || binarySHA != build["binary_sha256"] {
			report["passed"] = false
			returned = failure("NATIVE_MONITOR_BINARY_CHANGED")
		}
		currentHost, hostErr := r.HostVersion()
		currentPlatform, platformErr := r.NativePlatform()
		currentBoot, bootErr := hostvm.BootUUID()
		if hostErr != nil || platformErr != nil || bootErr != nil || !hostvm.Equal(currentHost, host) || !hostvm.Equal(currentPlatform, platform) || currentBoot != boot {
			report["passed"] = false
			returned = failure("NATIVE_PROOF_PLATFORM_CHANGED")
		}
		report["status"] = "failed"
		if report["passed"] == true {
			report["status"] = "verified"
		}
		if _, err := hostvm.WriteNew(filepath.Join(out, "results.json"), report); err != nil {
			returned = err
		}
	}()
	for _, path := range []string{run, control} {
		if err = os.Mkdir(path, 0700); err != nil {
			return report, err
		}
		info, err := hostvm.Owned(path, unix.S_IFDIR, 0700)
		if err != nil {
			return report, err
		}
		key := "run_directory_identity"
		if path == control {
			key = "control_directory_identity"
		}
		intent[key] = hostvm.DirectoryIdentity(info)
	}
	if _, err = hostvm.WriteNew(filepath.Join(out, "directory-owner.json"), object{"schema": 1, "run_directory": run, "run_directory_identity": intent["run_directory_identity"], "control_directory": control, "control_directory_identity": intent["control_directory_identity"]}); err != nil {
		return report, err
	}
	report["control_directory_identity"] = intent["control_directory_identity"]
	body, err := hostvm.Encoded(config)
	if err != nil {
		return report, err
	}
	if err = saveBytes(filepath.Join(control, "config.json"), body); err != nil {
		return report, err
	}
	if err = saveBytes(filepath.Join(control, "watchdog.plist"), hostvm.PlistBytes(control, r.NativeBinary)); err != nil {
		return report, err
	}
	self, err := os.Executable()
	if err != nil {
		return report, err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return report, err
	}
	selfSHA, err := hostvm.HashFile(self)
	if err != nil {
		return report, err
	}
	buildSHA, err := hostvm.HashFile(filepath.Join(buildDirectory, "build.json"))
	if err != nil {
		return report, err
	}
	producer := object{"schema": 1, "runner": self, "runner_sha256": selfSHA, "source_sha256": pins, "native_build_path": filepath.Join(buildDirectory, "build.json"), "native_build_sha256": buildSHA}
	if _, err = hostvm.WriteNew(filepath.Join(out, "producer-source.json"), producer); err != nil {
		return report, err
	}
	return report, monitor(ctx, r, config, report, control, out)
}

func knownIdentities(events []object) ([]object, error) {
	known := map[int64]object{}
	add := func(id object) error {
		pid := hostvm.Int(id, "pid")
		if old := known[pid]; old != nil && !hostvm.Equal(old, id) {
			return failure("NATIVE_PROOF_CLEANUP_IDENTITIES_DIFFER")
		}
		known[pid] = id
		return nil
	}
	for _, event := range events {
		name := hostvm.Str(event, "event")
		if name == "WATCHDOG_STARTED" || name == "GUARDIAN_READY" {
			role := "watchdog"
			if name == "GUARDIAN_READY" {
				role = "guardian"
			}
			id, err := hostvm.ProcessIdentity(event, role)
			if err != nil {
				return nil, err
			}
			if err = add(id); err != nil {
				return nil, err
			}
		}
		if name == "MONITOR_READY" {
			rows := hostvm.List(event, "processes")
			if len(rows) != 3 {
				return nil, failure("NATIVE_PROOF_CLEANUP_IDENTITIES_INVALID")
			}
			for _, row := range rows {
				value, _ := row.(object)
				id, err := hostvm.ProcessIdentity(value, "")
				if err != nil {
					return nil, err
				}
				if err = add(id); err != nil {
					return nil, err
				}
			}
		}
	}
	result := make([]object, 0, len(known))
	for _, id := range known {
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool {
		left := hostvm.Str(result[i], "role") == "guardian" || hostvm.Str(result[i], "role") == "watchdog"
		right := hostvm.Str(result[j], "role") == "guardian" || hostvm.Str(result[j], "role") == "watchdog"
		if left != right {
			return !left
		}
		return hostvm.Int(result[i], "pid") < hostvm.Int(result[j], "pid")
	})
	if len(result) > 4 {
		return nil, failure("NATIVE_PROOF_CLEANUP_IDENTITIES_INVALID")
	}
	return result, nil
}

func cleanup(r *hostvm.Runtime, out string, intent, report object) error {
	control, run, target := hostvm.Str(intent, "control_directory"), hostvm.Str(intent, "run_directory"), hostvm.Str(intent, "target")
	if !regexp.MustCompile(`^/private/tmp/fgw-[0-9a-f]{32}$`).MatchString(control) || !regexp.MustCompile(`^/private/tmp/fg-fixture-[0-9a-f]{32}$`).MatchString(run) || target != fmt.Sprintf("gui/%d/com.filegate.stage0.integrated.%s", os.Getuid(), filepath.Base(control)) {
		return failure("NATIVE_PROOF_CLEANUP_SCOPE_INVALID")
	}
	for _, name := range []string{"control_directory", "run_directory"} {
		path := hostvm.Str(intent, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		info, err := hostvm.Owned(path, unix.S_IFDIR, 0700)
		if err != nil || !hostvm.Equal(hostvm.DirectoryIdentity(info), hostvm.Map(intent, name+"_identity")) {
			return failure("NATIVE_PROOF_DIRECTORY_CHANGED")
		}
	}
	if _, err := os.Lstat(filepath.Join(out, "native-bootstrap-dispatched.json")); err == nil {
		config, _, err := hostvm.Read(filepath.Join(control, "config.json"), hostvm.ControlLimit)
		if err != nil || !hostvm.Equal(config, intent["config"]) || !fixedConfig(r, config) {
			return failure("NATIVE_PROOF_CONTROL_INPUTS_CHANGED")
		}
		plist, err := hostvm.ReadBytes(filepath.Join(control, "watchdog.plist"), hostvm.ControlLimit)
		if err != nil || !bytes.Equal(plist, hostvm.PlistBytes(control, r.NativeBinary)) {
			return failure("NATIVE_PROOF_CONTROL_INPUTS_CHANGED")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	disk, err := hostvm.NativeEvents(control)
	if err != nil {
		return err
	}
	report["events"] = objects(disk)
	combined := append([]object{}, disk...)
	for _, row := range hostvm.List(report, "broker_events") {
		value, ok := row.(object)
		if !ok {
			return failure("NATIVE_PROOF_EVENT_INVALID")
		}
		combined = append(combined, value)
	}
	ids, err := knownIdentities(combined)
	if err != nil {
		return err
	}
	for _, event := range combined {
		if hostvm.Str(event, "event") == "STOP_BEGIN" || hostvm.Str(event, "event") == "FINISHED" {
			report["stop_events_observed"] = true
			report["passed"] = false
		}
	}
	before := hostvm.ReadbackAll(ids)
	report["cleanup_before"] = before
	group := hostvm.Int(first(disk, "WATCHDOG_STARTED"), "pid")
	for _, item := range before {
		row := item.(object)
		if row["same_identity_live"] == nil {
			return failure("NATIVE_PROOF_CLEANUP_IDENTITY_UNAVAILABLE")
		}
		if row["same_identity_live"] == true {
			report["passed"] = false
			id := hostvm.Map(row, "identity")
			if err = signalIdentity(id, group); err != nil {
				return err
			}
			report["emergency_owned_cleanup"] = true
			report["broker_signals"] = append(hostvm.List(report, "broker_signals"), object{"identity": id, "signal": 9, "purpose": "emergency_owned_cleanup"})
		}
	}
	report["bootout"] = hostvm.CommandResult(context.Background(), []string{"/bin/launchctl", "bootout", target}, 15*time.Second)
	after := hostvm.ReadbackAll(ids)
	until := time.Now().Add(2 * time.Second)
	for len(ids) != 0 && !hostvm.AllExited(after) && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
		after = hostvm.ReadbackAll(ids)
	}
	report["cleanup_after"] = after
	report["cleanup_all_exited"] = hostvm.AllExited(after)
	absent, err := hostvm.ServiceAbsent(target)
	report["temporary_service_absent"] = absent
	if err != nil || !absent || len(ids) != 0 && !hostvm.AllExited(after) {
		return failure("NATIVE_PROOF_CLEANUP_STOP_UNCONFIRMED")
	}
	if len(ids) == 0 {
		if first(disk, "WATCHDOG_STARTED") != nil {
			return failure("NATIVE_PROOF_CLEANUP_START_UNCONFIRMED")
		}
		report["native_children_not_started"] = true
	}
	artifacts := object{}
	for _, name := range []string{"config.json", "watchdog.plist", "events.jsonl", "guardian-result.json"} {
		path := filepath.Join(control, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		body, err := hostvm.ReadBytes(path, 4<<20)
		if err != nil {
			return err
		}
		if err = hostvm.SaveCopy(filepath.Join(out, name), body); err != nil {
			return err
		}
		artifacts[name] = hostvm.HashBytes(body)
	}
	report["artifacts_sha256"] = artifacts
	for _, item := range []struct {
		path, field string
		allowed     map[string]uint32
	}{{control, "control_directory_identity", map[string]uint32{"config.json": unix.S_IFREG, "watchdog.plist": unix.S_IFREG, "events.jsonl": unix.S_IFREG, "guardian-result.json": unix.S_IFREG, "watch.sock": unix.S_IFSOCK}}, {run, "run_directory_identity", map[string]uint32{}}} {
		if err = reclaimDirectory(item.path, hostvm.Map(intent, item.field), item.allowed); err != nil {
			return err
		}
	}
	report["external_directories_reclaimed"] = true
	if err = slotBinding(r, out); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(r.State, "active-vm.json")); err != nil {
		return err
	}
	if err = hostvm.SyncDirectory(r.State); err != nil {
		return err
	}
	report["global_slot_finalized"] = true
	report["passed"] = report["passed"] == true && report["cleanup_all_exited"] == true && report["stop_events_observed"] == false && report["emergency_owned_cleanup"] != true
	return nil
}

func reclaimDirectory(path string, identity object, allowed map[string]uint32) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Uid != uint32(os.Getuid()) || info.Mode&07777 != 0700 || !hostvm.Equal(hostvm.DirectoryIdentity(info), identity) {
		return failure("NATIVE_PROOF_DIRECTORY_CHANGED")
	}
	entries, err := directory.ReadDir(len(allowed) + 1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > len(allowed) {
		return failure("NATIVE_PROOF_UNEXPECTED_CONTROL_FILE")
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		kind, ok := allowed[entry.Name()]
		if !ok || unix.Fstatat(fd, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || uint32(stat.Mode)&unix.S_IFMT != kind || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Getuid()) {
			return failure("NATIVE_PROOF_UNEXPECTED_CONTROL_FILE")
		}
	}
	for _, entry := range entries {
		if err = unix.Unlinkat(fd, entry.Name(), 0); err != nil {
			return err
		}
	}
	if err = unix.Fsync(fd); err != nil {
		return err
	}
	current, err := hostvm.Owned(path, unix.S_IFDIR, 0700)
	if err != nil || !hostvm.Equal(hostvm.DirectoryIdentity(current), identity) {
		return failure("NATIVE_PROOF_DIRECTORY_CHANGED")
	}
	if err = unix.Rmdir(path); err != nil {
		return err
	}
	return hostvm.SyncDirectory(filepath.Dir(path))
}

func recoverProof(r *hostvm.Runtime, out string) error {
	intent, _, err := hostvm.Read(filepath.Join(out, "native-intent.json"), hostvm.ControlLimit)
	if err != nil {
		if os.IsNotExist(err) {
			for _, name := range []string{"native-bootstrap-owner.json", "native-bootstrap-dispatched.json", "directory-owner.json"} {
				if _, statErr := os.Lstat(filepath.Join(out, name)); !os.IsNotExist(statErr) {
					return failure("NATIVE_PROOF_UNSTARTED_SCOPE_INVALID")
				}
			}
			if err = slotBinding(r, out); err != nil {
				return err
			}
			if err = os.Remove(filepath.Join(r.State, "active-vm.json")); err != nil {
				return err
			}
			if err = hostvm.SyncDirectory(r.State); err != nil {
				return err
			}
			_, err = hostvm.WriteNew(filepath.Join(out, "recovery-results.json"), object{"schema": 1, "kind": "go_native_proof_prelaunch_recovery", "passed": false, "bootstrap_not_started": true, "global_slot_finalized": true, "raw_allocation_bytes": 0})
		}
		return err
	}
	owner, _, err := hostvm.Read(filepath.Join(out, "directory-owner.json"), hostvm.ControlLimit)
	if err != nil {
		return err
	}
	for _, name := range []string{"control_directory", "run_directory"} {
		if !hostvm.Equal(intent[name], owner[name]) {
			return failure("NATIVE_PROOF_RECOVERY_SCOPE_CHANGED")
		}
		intent[name+"_identity"] = owner[name+"_identity"]
	}
	boot, err := hostvm.BootUUID()
	if err != nil || hostvm.Str(intent, "boot_session_uuid") != boot {
		return failure("NATIVE_PROOF_RECOVERY_BOOT_CHANGED")
	}
	config := hostvm.Map(intent, "config")
	binarySHA, binaryErr := hostvm.HashFile(r.NativeBinary)
	sourceSHA, sourceErr := hostvm.HashFile(r.NativeSource)
	if hostvm.Str(intent, "kind") != "go_native_proof_intent" || hostvm.Int(intent, "schema") != 1 || !fixedConfig(r, config) ||
		binaryErr != nil || sourceErr != nil || intent["binary_sha256"] != binarySHA || intent["native_source_sha256"] != sourceSHA ||
		!hostvm.Equal(config["run_directory"], intent["run_directory"]) || !hostvm.Equal(config["control_directory"], intent["control_directory"]) ||
		hostvm.Str(intent, "target") != fmt.Sprintf("gui/%d/com.filegate.stage0.integrated.%s", os.Getuid(), filepath.Base(hostvm.Str(intent, "control_directory"))) {
		return failure("NATIVE_PROOF_RECOVERY_SCOPE_CHANGED")
	}
	report := object{"schema": 1, "kind": "go_native_proof_recovery", "passed": false, "broker_events": []any{}, "broker_signals": []any{}, "stop_events_observed": false}
	if err = cleanup(r, out, intent, report); err != nil {
		return err
	}
	_, err = hostvm.WriteNew(filepath.Join(out, "recovery-results.json"), report)
	return err
}

func fixedConfig(r *hostvm.Runtime, config object) bool {
	return hostvm.Fields(config, "schema", "mode", "owner_kind", "require_launchagent", "run_directory", "control_directory", "continuous_start_ns", "continuous_deadline_ns", "vm_argv", "helper_argv") &&
		hostvm.Int(config, "schema") == 1 && hostvm.Str(config, "mode") == "fixture" && hostvm.Str(config, "owner_kind") == "scan" && config["require_launchagent"] == true &&
		hostvm.Int(config, "continuous_start_ns") > 0 && hostvm.Int(config, "continuous_deadline_ns")-hostvm.Int(config, "continuous_start_ns") == 300*1e9 &&
		hostvm.Equal(config["vm_argv"], []string{r.NativeBinary, "fixture-child", "fixture-vm", "normal"}) && hostvm.Equal(config["helper_argv"], []string{r.NativeBinary, "fixture-child", "fixture-helper", "heartbeat-stop"})
}
