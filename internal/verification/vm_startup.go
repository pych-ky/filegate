package verification

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

var vmStartupCases = []string{"reservation", "request-partial", "request-synced", "before-start", "after-start", "after-start-live", "before-owner", "resource-intent", "slot-before", "slot-after", "run-created", "prepare-owner-before", "unknown-output", "nonempty-run"}

func init() { Register("startup", runVMStartup); Register("recovery", runVMRecovery) }
func vmSelected(h *Harness, known []string) []string {
	if len(h.Cases) == 0 {
		return known
	}
	seen := map[string]bool{}
	for _, name := range h.Cases {
		found := false
		for _, v := range known {
			found = found || name == v
		}
		h.Check("selected_case_known_"+name, found && !seen[name])
		seen[name] = true
	}
	return h.Cases
}
func vmPrepareStartupBroker(h *Harness, name string) string {
	scan, runtime := filepath.Join(h.Root, "internal/broker/scan.go"), filepath.Join(h.Root, "internal/broker/runtime.go")
	path, marker, replacement := "", "", ""
	switch name {
	case "reservation":
		path = scan
		marker = "\tif os.Mkdir(directory, 0700) != nil || syncDirectory(filepath.Dir(directory)) != nil {"
		replacement = "\tos.Exit(91)\n" + marker
	case "request-partial":
		path = scan
		marker = "\t_, err = f.Write(body)"
		replacement = "\tif filepath.Base(path)==\"request.json\" {_,_=f.Write(body[:len(body)/2]);_=f.Sync();os.Exit(91)}\n" + marker
	case "request-synced":
		path = runtime
		marker = "\tstartupLock, err := b.prepareStartup(run)"
		replacement = "\tos.Exit(91)\n" + marker
	case "before-start":
		path = runtime
		marker = "\terr = cmd.Start()"
		replacement = "\tos.Exit(91)\n" + marker
	default:
		panic(Failure{"startup_broker_window_invalid"})
	}
	binary := filepath.Join(h.Out, "filegate-startup-"+name)
	BuildOverlay(h, "startup-"+name, binary, map[string]string{path: ReplaceOnce(string(Read(path)), marker, replacement)})
	return binary
}
func vmProofChain(h *Harness, out string, job Object, expectedKind string) Object {
	summaryPath := filepath.Join(out, "recovery-results.json")
	if !Exists(summaryPath) {
		summaryPath = filepath.Join(out, "results.json")
	}
	summary := ReadJSON(summaryPath)
	complete := ReadJSON(filepath.Join(out, "cleanup-complete.json"))
	intent := ReadJSON(filepath.Join(out, "cleanup-intent.json"))
	proof := ReadJSON(filepath.Join(out, "stop-proof.json"))
	owner := ReadJSON(filepath.Join(out, "slot-owner.json"))
	input := Map(job, "input_receipt")
	binding := Object{"schema": 1, "job_id": job["job_id"], "attempt_id": job["attempt_id"], "input_sha256": input["sha256"], "byte_size": input["byte_size"]}
	for _, record := range []Object{complete, intent, proof, owner} {
		valid := true
		for k, v := range binding {
			valid = valid && Equal(record[k], v)
		}
		h.Check("recovery_record_binding", valid)
	}
	h.Check("recovery_hash_chain", Str(summary, "recovery_evidence", "path") == "cleanup-complete.json" && Str(summary, "recovery_evidence", "sha256") == FileDigest(filepath.Join(out, "cleanup-complete.json")) && Str(complete, "cleanup_intent_sha256") == FileDigest(filepath.Join(out, "cleanup-intent.json")) && Str(complete, "stop_proof_sha256") == FileDigest(filepath.Join(out, "stop-proof.json")) && Str(intent, "stop_proof_sha256") == Str(complete, "stop_proof_sha256") && Str(intent, "slot_owner_sha256") == FileDigest(filepath.Join(out, "slot-owner.json")) && Str(complete, "kind") == expectedKind && Str(intent, "kind") == expectedKind && Str(proof, "kind") == expectedKind && Bool(proof, "stopped"))
	checks := Map(proof, "checks")
	allChecks := len(checks) > 0
	for _, value := range checks {
		allChecks = allChecks && value == true
	}
	evidence := Map(proof, "evidence")
	path := Str(evidence, "path")
	h.Check("recovery_stop_evidence_hash", allChecks && filepath.IsLocal(path) && Str(evidence, "sha256") == FileDigest(filepath.Join(out, path)))
	expectedChecks := map[string]Object{
		"resources_unstarted":  {"producer_stopped": true, "prepare_not_started": true},
		"prepare_unstarted":    {"leader_stopped": true, "group_empty": true},
		"native_prelaunch":     {"producer_stopped": true, "bootstrap_not_started": true, "service_absent": true},
		"native_previous_boot": {"boot_changed": true, "producer_stopped": true, "service_absent": true},
		"native_guardian":      {"identities_stopped": true, "service_absent": true, "guardian_verified": true},
		"native_stopped_group": {"identities_stopped": true, "group_empty": true, "service_absent": true},
		"native_unstarted":     {"terminal_empty": true, "transfer_disabled": true, "watchdog_stopped": true, "service_absent": true},
	}
	h.Check("recovery_typed_stop_checks", expectedChecks[expectedKind] != nil && Equal(checks, expectedChecks[expectedKind]))
	h.Check("recovery_never_certifies_pass", Get(summary, "passed") == false && Get(summary, "report_accepted") == false && Get(summary, "product_enabled") == false && Get(summary, "stage0_gate_passed") == false && Bool(summary, "raw_reclaimed") && Bool(summary, "vm_slot_finalized") && Int(summary, "reservation_charge_bytes") == 0 && Bool(complete, "raw_reclaimed") && Bool(complete, "external_directories_reclaimed"))
	h.Check("recovery_termination_and_raw_evidence", Get(summary, "job_id") == Get(job, "job_id") && Get(summary, "attempt_id") == Get(job, "attempt_id") && Bool(summary, "termination", "all_exited") && Bool(summary, "termination", "identity_verified") && Get(summary, "termination", "stop_failed") == false && Equal(ReadJSON(filepath.Join(out, "raw-cleanup.json")), Object{"reclaimed": true, "reservation_charge_bytes": 0, "closed_fd_evidence": "identity-bound stop-proof.json", "external_directories_reclaimed": true}))
	for _, row := range List(intent, "directories") {
		path := Str(row, "path")
		h.Check("cleanup_directory_scoped_and_absent", filepath.Dir(path) == "/private/tmp" && (strings.HasPrefix(filepath.Base(path), "fgw-") || strings.HasPrefix(filepath.Base(path), "filegate-vm-")) && !Exists(path))
	}
	return proof
}
func vmCopyRuntime(h *Harness, source, target string) Object {
	hashes := Object{}
	if !Exists(source) {
		return hashes
	}
	Must(filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		h.Check("runtime_copy_owned_regular", info.Mode().IsRegular() && info.Size() <= 16<<20)
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		Write(destination, Read(path))
		hashes[relative] = FileDigest(destination)
		return nil
	}))
	return hashes
}
func vmInjectUnknown(h *Harness, directory string) (string, unix.Stat_t) {
	info, err := os.Stat(directory)
	Must(err)
	h.Check("injection_private_directory", info.IsDir() && info.Mode().Perm() == 0700)
	path := filepath.Join(directory, "verification-owned-unknown")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	Must(err)
	_, err = f.Write([]byte("FileGate synthetic owned unknown-file fixture.\n"))
	Must(err)
	Must(f.Sync())
	Must(f.Close())
	var identity unix.Stat_t
	Must(unix.Lstat(path, &identity))
	return path, identity
}
func vmRemoveInjection(h *Harness, path string, identity unix.Stat_t) {
	h.Check("injection_remove_service_stopped", h.Process == nil)
	var current unix.Stat_t
	Must(unix.Lstat(path, &current))
	h.Check("remove_only_same_owned_injection", current.Dev == identity.Dev && current.Ino == identity.Ino && current.Mode&unix.S_IFMT == unix.S_IFREG && current.Uid == uint32(os.Getuid()) && current.Size == identity.Size && current.Mtim == identity.Mtim)
	Must(os.Remove(path))
	Must(hostvm.SyncDirectory(filepath.Dir(path)))
}
func runVMStartup(h *Harness) {
	base := newVMSuite(h)
	normal, workspace, runner := h.Binary, h.Workspace, h.Runner
	h.StartTimeout = 55 * time.Second
	h.StopTimeout = 30 * time.Second
	names := vmSelected(h, vmStartupCases)
	builds := []Object{{"name": "normal", "exit_code": 0, "binary_sha256": FileDigest(normal)}}
	prepared := map[string]Object{}
	for _, name := range names {
		binary, clone, marker := "", workspace, ""
		if name == "reservation" || name == "request-partial" || name == "request-synced" || name == "before-start" {
			binary = vmPrepareStartupBroker(h, name)
		} else {
			marker = filepath.Join(h.Out, name+"-runner.json")
			clone = vmFixtureWorkspace(h, name, marker)
			binary = vmBrokerCrashOverlay(h, "startup-"+name, marker)
		}
		builds = append(builds, Object{"name": name, "exit_code": 0, "binary_sha256": FileDigest(binary)})
		prepared[name] = Object{"binary": binary, "workspace": clone, "marker": marker}
	}
	h.Record["builds"] = builds
	if h.PrepareOnly {
		h.Record["runtime_executed"] = false
		h.Record["scope"] = "startup Go fixture construction only"
		return
	}
	cases := []Object{}
	for _, name := range names {
		record := prepared[name]
		h.Data = filepath.Join(h.Temporary, "startup-"+name)
		h.Socket = filepath.Join(h.Data, "filegate.sock")
		h.Binary = Str(record, "binary")
		h.Workspace = Str(record, "workspace")
		h.Runner = filepath.Join(h.Workspace, ".build/filegate-vm")
		s := &vmSuite{h: h}
		body := []byte("FileGate synthetic startup recovery fixture.\n")
		path := filepath.Join(h.InputDirectory, "startup.txt")
		Write(path, body)
		h.Check(name+"_gates_closed", GatesClosed(s.start()))
		_, _ = vmSubmit(h, path, Object{"idempotency_key": name, "expected_sha256": Digest(body)})
		vmWaitBrokerCrash(h, name)
		before, directory := vmStartupState(s, name+"-before-restart")
		job := Map(before, "job")
		out := filepath.Join(directory, "output")
		h.Check(name+"_reservation_survives_crash", Int(before, "runtime", "raw_reserved") == 4<<30 && Int(before, "remaining_pins") == 1 && Int(before, "remaining_queue") == 1 && Str(job, "input_receipt", "sha256") == Digest(body) && FileDigest(filepath.Join(h.Data, "objects", Str(job, "input_receipt", "object_id"))) == Digest(body))
		h.Check(name+"_runtime_reservation_boundary", Exists(directory) == (name != "reservation"))
		h.Check(name+"_no_vm_started", !Exists(filepath.Join(out, "vm-started.json")) && !Exists(filepath.Join(out, "watchdog")))
		marker := Str(record, "marker")
		var observed Object
		if marker != "" {
			observed = ReadJSON(marker)
		}
		if name == "after-start-live" {
			h.Check("producer_survives_broker_with_lock", hostvm.IdentityReadback(Map(observed, "identity"))["same_identity_live"] == true)
		} else if observed != nil {
			vmWaitIdentityExit(h, name+"_producer_exited", Map(observed, "identity"), 10*time.Second)
		}
		if observed != nil {
			vmWaitIdentityExit(h, name+"_gate_exited_without_go", Map(observed, "gate_identity"), 10*time.Second)
			if run := Str(observed, "run_directory"); run != "" {
				h.Check(name+"_gate_never_allocated_raw", !Exists(filepath.Join(run, "work.raw")))
			}
		}
		negative := name == "unknown-output" || name == "nonempty-run"
		var injected string
		var identity unix.Stat_t
		if negative {
			target := out
			if name == "nonempty-run" {
				target = Str(observed, "run_directory")
			}
			injected, identity = vmInjectUnknown(h, target)
		}
		beforeCopy := vmCopyRuntime(h, directory, filepath.Join(h.Out, name, "before-runtime"))
		h.Binary = normal
		s.start()
		after, _ := vmStartupState(s, name+"-after-restart")
		if name == "after-start-live" {
			h.Check("live_producer_blocks_recovery", hostvm.IdentityReadback(Map(observed, "identity"))["same_identity_live"] == true && Str(after, "runtime", "state") == "STOP_FAILED" && Int(after, "runtime", "raw_reserved") == 4<<30 && Int(after, "remaining_pins") == 1 && Get(after, "job", "runtime_cleanup_complete") == false && !Exists(filepath.Join(directory, "startup-recovery.json")))
			h.Stop(true)
			Write(marker+".release", nil)
			vmWaitIdentityExit(h, "released_producer_exited", Map(observed, "identity"), 10*time.Second)
			s.start()
			settled, _ := vmStartupState(s, name+"-after-producer-exit")
			h.Check("producer_exit_does_not_rewrite_terminal_attempt", Equal(settled["attempt"], after["attempt"]))
			after = settled
		}
		job = Map(after, "job")
		h.Check(name+"_restart_finishes_hold_without_pass", Str(job, "phase") == "FAILED" && Str(job, "verdict") == "HOLD" && Get(job, "release", "eligible") == false && len(after["rejection_evidence"].([]Object)) == 0)
		if negative {
			h.Check(name+"_unknown_start_keeps_reservation", Get(job, "runtime_cleanup_complete") == false && Contains(Get(job, "execution_errors"), "VM_STOP_FAILED") && Str(after, "runtime", "state") == "STOP_FAILED" && Int(after, "runtime", "raw_reserved") == 4<<30 && Int(after, "remaining_pins") == 1 && Int(after, "remaining_queue") == 1 && !Exists(filepath.Join(out, "cleanup-complete.json")) && Exists(injected))
			status, rejected := h.Request("POST", "/v1/jobs", Object{"source_kind": "local", "root_id": "fixture", "source": "startup.txt", "idempotency_key": "must-not-start"}, nil, nil)
			h.Check(name+"_unknown_start_blocks_new_intake", status == 503 && ErrorCode(rejected) == "RECOVERY_REQUIRED")
			h.Stop(true)
			vmRemoveInjection(h, injected, identity)
			s.start()
			settled, _ := vmStartupState(s, name+"-after-injection-removed")
			h.Check(name+"_resolving_unknown_preserves_attempt", Equal(settled["attempt"], after["attempt"]))
			after = settled
			job = Map(after, "job")
		}
		reason := "INTERRUPTED"
		if negative || name == "after-start-live" {
			reason = "VM_STOP_FAILED"
		}
		h.Check(name+"_known_unstarted_settled", Bool(job, "runtime_cleanup_complete") && Contains(Get(job, "execution_errors"), reason) && Str(after, "runtime", "state") == "FINISHED" && Int(after, "runtime", "raw_reserved") == 0 && Int(after, "runtime", "raw_written") == 0 && Int(after, "remaining_pins") == 0 && Int(after, "remaining_queue") == 0)
		resource := name == "resource-intent" || name == "slot-before" || name == "slot-after" || name == "run-created" || name == "prepare-owner-before" || name == "nonempty-run"
		if resource {
			proof := vmProofChain(h, out, job, "resources_unstarted")
			h.Check(name+"_resources_not_started", Equal(proof["checks"], Object{"producer_stopped": true, "prepare_not_started": true}) && Str(proof, "evidence", "path") == "resource-intent.json" && Str(proof, "evidence", "sha256") == FileDigest(filepath.Join(out, "resource-intent.json")))
		} else {
			proof := ReadJSON(filepath.Join(directory, "startup-recovery.json"))
			authority := "producer_exited_before_resources"
			if name == "reservation" || name == "request-partial" || name == "request-synced" {
				authority = "reserved_not_dispatched"
			}
			h.Check(name+"_unstarted_authority", Int(proof, "schema") == 1 && Str(proof, "authority") == authority && Get(proof, "job_id") == Get(job, "job_id") && Get(proof, "attempt_id") == Get(job, "attempt_id") && Get(proof, "output_absent") == (name != "before-owner" && name != "unknown-output"))
		}
		state, err := hostvm.New(h.Workspace)
		Must(err)
		h.Check(name+"_shared_slot_reclaimed", !Exists(filepath.Join(state.State, "active-vm.json")))
		h.Stop(false)
		s.start()
		repeated, _ := vmStartupState(s, name+"-second-restart")
		h.Check(name+"_restart_idempotent", Equal(repeated, after))
		code, replay := vmSubmit(h, path, Object{"idempotency_key": name, "expected_sha256": Digest(body)})
		h.Check(name+"_same_key_replays_original", code == 0 && Bool(replay, "replayed") && Get(replay, "job_id") == Get(job, "job_id") && Get(replay, "current_input_checked") == false && Get(replay, "body_consumed") == false && Str(replay, "input_receipt", "sha256") == Digest(body))
		h.Stop(false)
		artifacts := vmCopyRuntime(h, directory, filepath.Join(h.Out, name, "runtime"))
		cases = append(cases, Object{"name": name, "vm_started": false, "producer_exited": observed == nil || hostvm.IdentityReadback(Map(observed, "identity"))["same_identity_live"] == false, "rejection_of_unknown_file_verified": negative, "before_artifacts_sha256": beforeCopy, "runtime_artifacts_sha256": artifacts})
		h.Record["cases"] = cases
	}
	h.Binary = normal
	h.Workspace = workspace
	h.Runner = runner
	base.directories = nil
	h.Record["all_runtime_cleanup_confirmed"] = true
	h.Check("all_startup_cases_complete", len(cases) == len(names))
}
func runVMRecovery(h *Harness) { runVMRecoveryCases(h) }
