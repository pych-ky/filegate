package verification

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

var vmNativeCases = []string{"intent", "control-directory", "config-partial", "bootstrap-owner-before", "bootstrap-owner-after", "bootstrap-complete", "native-start", "monitor-ready", "record-copy", "results-pending", "watchdog-death", "pre-guardian-death", "unknown-control", "bootstrap-dispatch", "bootstrap-dispatch-unknown", "bootstrap-dispatch-absent"}

func init() { Register("native-crash", runVMNativeCrash) }
func vmRemovePreexecDirectories(h *Harness, out string, marker Object) {
	h.Check("preexec_fixture_removal_service_stopped", h.Process == nil && strings.HasPrefix(Str(marker, "mode"), "bootstrap-dispatch"))
	owner, err := hostvm.ReadOwnership(filepath.Join(out, "native-bootstrap-dispatched.json"))
	Must(err)
	stopped, err := hostvm.VerifyStopped(owner)
	Must(err)
	h.Check("preexec_dispatch_owner_exited", Bool(stopped, "stop_verified") && Int(owner, "leader", "pid") == Int(marker, "identity", "pid") && Int(owner, "leader", "start_abstime") == Int(marker, "identity", "start_abstime") && !Exists(filepath.Join(out, "native-start.json")))
	plan := ReadJSON(filepath.Join(out, "native-intent.json"))
	control := Str(plan, "control_directory")
	events, err := hostvm.NativeEvents(control)
	Must(err)
	h.Check("preexec_native_never_started", len(events) == 0)
	absent, err := hostvm.ServiceAbsent("gui/" + strconv.Itoa(os.Getuid()) + "/com.filegate.stage0.integrated." + filepath.Base(control))
	Must(err)
	h.Check("preexec_native_service_absent", absent)
	preparation := ReadJSON(filepath.Join(out, "preparation-intent.json"))
	prepared := ReadJSON(filepath.Join(out, "prepared-identity.json"))
	nativeDirectory := ReadJSON(filepath.Join(out, "native-directory.json"))
	rows := []Object{{"path": Str(preparation, "run_directory"), "identity": preparation["run_directory_identity"], "kind": "run"}, {"path": control, "identity": nativeDirectory, "kind": "control"}}
	removed := []Object{}
	for _, row := range rows {
		path := Str(row, "path")
		kind := Str(row, "kind")
		h.Check("preexec_removal_fixed_scope", filepath.Dir(path) == "/private/tmp" && (kind == "run" && strings.HasPrefix(filepath.Base(path), "filegate-vm-") || kind == "control" && strings.HasPrefix(filepath.Base(path), "fgw-")))
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		Must(err)
		f := os.NewFile(uintptr(fd), path)
		var info unix.Stat_t
		Must(unix.Fstat(fd, &info))
		h.Check("preexec_remove_same_directory", info.Uid == uint32(os.Getuid()) && info.Mode&07777 == 0700 && hostvm.SameDirectory(info, Map(row, "identity")))
		names, err := f.Readdirnames(-1)
		Must(err)
		expectedNames := map[string]bool{"config.json": true, "watchdog.plist": true}
		if kind == "run" {
			expectedNames = map[string]bool{"work.raw": true, "prepared.json": true, "product-request.json": true}
		}
		h.Check("preexec_exact_fixture_file_set", len(names) == len(expectedNames))
		files := []Object{}
		for _, name := range names {
			limit := int64(65536)
			allowed := expectedNames[name]
			if name == "work.raw" {
				limit = hostvm.RawBytes
			}
			var child unix.Stat_t
			Must(unix.Fstatat(fd, name, &child, unix.AT_SYMLINK_NOFOLLOW))
			h.Check("preexec_remove_only_fixed_owned_files", allowed && child.Mode&unix.S_IFMT == unix.S_IFREG && child.Uid == uint32(os.Getuid()) && child.Mode&07777 == 0600 && child.Nlink == 1 && child.Size <= limit)
			if name == "work.raw" {
				h.Check("preexec_raw_identity", child.Size == hostvm.RawBytes && hostvm.SameDirectory(child, Map(prepared, "raw_identity")))
			}
			files = append(files, Object{"name": name, "device": uint64(child.Dev), "inode": child.Ino, "bytes": child.Size})
			Must(unix.Unlinkat(fd, name, 0))
		}
		Must(unix.Fsync(fd))
		var current unix.Stat_t
		Must(unix.Lstat(path, &current))
		h.Check("preexec_directory_identity_before_rmdir", current.Dev == info.Dev && current.Ino == info.Ino)
		Must(unix.Rmdir(path))
		Must(f.Close())
		Must(hostvm.SyncDirectory(filepath.Dir(path)))
		removed = append(removed, Object{"path": path, "files": files})
	}
	WriteJSON(filepath.Join(h.Out, Str(marker, "mode")+"-fixture-directory-removal.json"), Object{"fixture_only": true, "real_os_restart": false, "before_exec_owner_verified_exited": true, "native_never_started": true, "removed": removed})
}
func runVMNativeCrash(h *Harness) {
	base := newVMSuite(h)
	normal, workspace, runner := h.Binary, h.Workspace, h.Runner
	h.StartTimeout = 55 * time.Second
	h.StopTimeout = 30 * time.Second
	names := vmSelected(h, vmNativeCases)
	prepared := map[string]Object{}
	builds := []Object{{"name": "normal", "exit_code": 0, "binary_sha256": FileDigest(normal)}}
	for _, name := range names {
		marker := filepath.Join(h.Out, name+"-runner.json")
		clone := vmFixtureWorkspace(h, name, marker)
		binary := vmBrokerCrashOverlay(h, "native-"+name, marker)
		prepared[name] = Object{"marker": marker, "workspace": clone, "binary": binary}
		builds = append(builds, Object{"name": name, "exit_code": 0, "binary_sha256": FileDigest(binary)})
	}
	h.Record["builds"] = builds
	if h.PrepareOnly {
		h.Record["scope"] = "native crash Go fixture construction only"
		h.Record["runtime_executed"] = false
		return
	}
	cases := []Object{}
	for _, name := range names {
		record := prepared[name]
		h.Data = filepath.Join(h.Temporary, "native-"+name)
		h.Socket = filepath.Join(h.Data, "filegate.sock")
		h.Binary = Str(record, "binary")
		h.Workspace = Str(record, "workspace")
		h.Runner = filepath.Join(h.Workspace, ".build/filegate-vm")
		s := &vmSuite{h: h}
		body := []byte("FileGate harmless native crash recovery TXT fixture.\n")
		path := filepath.Join(h.InputDirectory, "native.txt")
		Write(path, body)
		h.Check(name+"_gates_closed", GatesClosed(s.start()))
		code, receipt := vmSubmit(h, path, Object{"idempotency_key": name, "expected_type": "txt", "expected_sha256": Digest(body)})
		h.Check(name+"_input_committed", code == 0 && Str(receipt, "input_receipt", "sha256") == Digest(body))
		vmWaitBrokerCrash(h, name)
		markerPath := Str(record, "marker")
		observed := ReadJSON(markerPath)
		before, directory := vmStartupState(s, name+"-before-restart")
		out := filepath.Join(directory, "output")
		raw := filepath.Join(Str(observed, "run_directory"), "work.raw")
		info, err := os.Stat(raw)
		Must(err)
		h.Check(name+"_raw_and_reservation_retained", info.Size() == 4<<30 && Int(before, "runtime", "raw_reserved") == 4<<30 && Int(before, "remaining_pins") == 1 && Int(before, "remaining_queue") == 1)
		producer := Map(observed, "identity")
		gate := Map(observed, "gate_identity")
		if strings.HasPrefix(name, "bootstrap-dispatch") {
			producer = Map(observed, "producer_identity")
			gate = Map(observed, "identity")
		}
		vmWaitIdentityExit(h, name+"_producer_exited", producer, 10*time.Second)
		vmWaitIdentityExit(h, name+"_gate_exited", gate, 10*time.Second)
		beforeHashes := vmCopyRuntime(h, directory, filepath.Join(h.Out, name, "before-runtime"))
		var injection string
		var injectionID unix.Stat_t
		if name == "unknown-control" {
			injection, injectionID = vmInjectUnknown(h, Str(observed, "control_directory"))
		}
		h.Binary = normal
		s.start()
		after, _ := vmStartupState(s, name+"-after-restart")
		if strings.HasPrefix(name, "bootstrap-dispatch") {
			terminalAttempt := after["attempt"]
			h.Check(name+"_same_boot_dispatch_keeps_pin_and_raw", Str(after, "runtime", "state") == "STOP_FAILED" && Int(after, "runtime", "raw_reserved") == 4<<30 && Int(after, "remaining_pins") == 1 && Int(after, "remaining_queue") == 1 && Exists(raw) && !Exists(filepath.Join(out, "native-previous-boot.json")) && !Exists(filepath.Join(out, "stop-proof.json")))
			h.Stop(true)
			if name == "bootstrap-dispatch-unknown" {
				injection, injectionID = vmInjectUnknown(h, Str(observed, "control_directory"))
			}
			if name == "bootstrap-dispatch-absent" {
				vmRemovePreexecDirectories(h, out, observed)
			}
			Write(markerPath+".previous-boot", []byte("synthetic previous-boot branch; no OS restart\n"))
			s.start()
			after, _ = vmStartupState(s, name+"-after-previous-boot-fixture")
			if name == "bootstrap-dispatch-unknown" {
				h.Check(name+"_previous_boot_unknown_keeps_reservation", Str(after, "runtime", "state") == "STOP_FAILED" && Int(after, "runtime", "raw_reserved") == 4<<30 && Int(after, "remaining_pins") == 1 && Exists(raw) && Exists(injection))
				h.Stop(true)
				vmRemoveInjection(h, injection, injectionID)
				s.start()
				after, _ = vmStartupState(s, name+"-after-owned-marker-removal")
			}
			h.Check(name+"_previous_boot_preserves_terminal_attempt", Equal(after["attempt"], terminalAttempt))
			injectionRecord := ReadJSON(markerPath + ".boot-injection.json")
			proof := ReadJSON(filepath.Join(out, "native-previous-boot.json"))
			h.Check(name+"_synthetic_boot_explicit_and_hash_bound", Get(injectionRecord, "fixture_only") == true && Get(injectionRecord, "real_os_restart") == false && Str(proof, "previous_boot_uuid") == Str(injectionRecord, "injected_previous_boot_uuid") && Str(proof, "observed_boot_uuid") == Str(injectionRecord, "actual_boot_uuid") && Str(proof, "native_intent_sha256") == Str(injectionRecord, "after_sha256") && Str(proof, "native_intent_sha256") == FileDigest(filepath.Join(out, "native-intent.json")))
		}
		if name == "unknown-control" {
			h.Check("unknown_control_keeps_pin_and_raw", Str(after, "runtime", "state") == "STOP_FAILED" && Int(after, "runtime", "raw_reserved") == 4<<30 && Int(after, "remaining_pins") == 1 && Int(after, "remaining_queue") == 1 && Get(after, "job", "runtime_cleanup_complete") == false && Exists(raw) && Exists(injection))
			status, rejected := h.Request("POST", "/v1/jobs", Object{"source_kind": "local", "root_id": "fixture", "source": "native.txt", "idempotency_key": "blocked-while-unknown"}, nil, nil)
			h.Check("unknown_control_blocks_intake", status == 503 && ErrorCode(rejected) == "RECOVERY_REQUIRED")
			h.Stop(true)
			vmRemoveInjection(h, injection, injectionID)
			s.start()
			settled, _ := vmStartupState(s, name+"-after-injection-removal")
			h.Check("resolved_failure_preserves_terminal_attempt", Equal(settled["attempt"], after["attempt"]))
			after = settled
		}
		job := Map(after, "job")
		h.Check(name+"_recovered_attempt_hold", Str(job, "phase") == "FAILED" && Str(job, "verdict") == "HOLD" && Get(job, "release", "eligible") == false && len(after["rejection_evidence"].([]Object)) == 0)
		h.Check(name+"_settled_only_after_proof", Str(after, "runtime", "state") == "FINISHED" && Int(after, "runtime", "raw_reserved") == 0 && Int(after, "runtime", "raw_written") == 0 && Int(after, "remaining_pins") == 0 && Int(after, "remaining_queue") == 0 && Bool(job, "runtime_cleanup_complete") && FileDigest(filepath.Join(h.Data, "objects", Str(job, "input_receipt", "object_id"))) == Digest(body))
		kind := Str(ReadJSON(filepath.Join(out, "stop-proof.json")), "kind")
		expectedKind := "native_guardian"
		switch name {
		case "intent", "control-directory", "config-partial", "bootstrap-owner-before", "bootstrap-owner-after", "unknown-control":
			expectedKind = "native_prelaunch"
		case "bootstrap-complete", "native-start":
			expectedKind = "native_unstarted"
		case "pre-guardian-death":
			expectedKind = "native_stopped_group"
		case "bootstrap-dispatch", "bootstrap-dispatch-unknown", "bootstrap-dispatch-absent":
			expectedKind = "native_previous_boot"
		}
		h.Check(name+"_expected_stop_authority", kind == expectedKind)
		vmProofChain(h, out, job, kind)
		if kind == "native_guardian" || kind == "native_stopped_group" || kind == "native_unstarted" {
			native := ReadJSON(filepath.Join(out, "watchdog/results.json"))
			runtime, err := hostvm.New(h.Workspace)
			Must(err)
			actualKind, err := runtime.NativeChecks(native)
			Must(err)
			h.Check(name+"_native_actual_readback", actualKind == kind && Bool(native, "cleanup_all_exited") && Bool(native, "temporary_service_absent"))
			started := name == "monitor-ready" || name == "record-copy" || name == "results-pending" || name == "watchdog-death"
			h.Check(name+"_native_vm_scope_matches_window", Get(native, "qemu_started") == started && Get(native, "emergency_owned_cleanup") != true)
			if name == "watchdog-death" {
				h.Check("watchdog_death_independent_guardian", Get(observed, "watchdog_sigkill") == true && Get(native, "terminal") == nil && Str(native, "kind") == "recovered_native_guardian" && Bool(native, "guardian_result", "parent_pipe_eof") && Get(native, "guardian_result", "parent_same_identity_live_at_eof") == false && Get(native, "guardian_result", "parent_stop_intent_seen") == false && Bool(native, "guardian_result", "all_targets_exited") && Get(native, "guardian_result", "monitor_failed") == false)
			}
			if name == "pre-guardian-death" {
				h.Check("pre_guardian_group_stopped", Get(observed, "watchdog_sigkill") == true && kind == "native_stopped_group" && Get(native, "terminal") == nil && Bool(native, "process_group_empty") && Get(native, "guardian_result_verified") == false)
			}
			if name == "watchdog-death" || name == "pre-guardian-death" {
				valid := true
				for _, event := range List(native, "events") {
					typeName := Str(event, "event")
					valid = valid && typeName != "FINISHED" && (name != "pre-guardian-death" || typeName != "GUARDIAN_READY" && typeName != "MONITOR_READY")
				}
				h.Check(name+"_no_fabricated_monitor_events", valid)
			}
		}
		h.Stop(false)
		s.start()
		repeated, _ := vmStartupState(s, name+"-second-restart")
		h.Check(name+"_second_restart_preserves_attempt", Equal(repeated, after))
		code, replay := vmSubmit(h, path, Object{"idempotency_key": name, "expected_type": "txt", "expected_sha256": Digest(body)})
		h.Check(name+"_same_key_replays_without_reexecution", code == 0 && Bool(replay, "replayed") && Get(replay, "job_id") == Get(job, "job_id") && Get(replay, "current_input_checked") == false && Equal(Get(replay, "input_receipt"), Get(job, "input_receipt")))
		h.Stop(false)
		cases = append(cases, Object{"name": name, "before_runtime_sha256": beforeHashes, "runtime_artifacts_sha256": vmCopyRuntime(h, directory, filepath.Join(h.Out, name, "runtime")), "producer_exited": true, "gate_exited": true, "vm_started": name == "monitor-ready" || name == "record-copy" || name == "results-pending" || name == "watchdog-death", "synthetic_previous_boot": strings.HasPrefix(name, "bootstrap-dispatch"), "real_os_restart": false})
		h.Record["cases"] = cases
		h.Workspace = workspace
		h.Runner = runner
	}
	h.Binary = normal
	base.directories = nil
	h.Record["all_runtime_cleanup_confirmed"] = true
	h.Record["real_os_restart"] = false
	h.Check("native_crash_exact_case_count", len(cases) == len(names))
}
