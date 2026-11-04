package verification

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	"filegate.local/filegate/internal/hostvm"
)

func vmSignal(h *Harness, id Object, signal syscall.Signal) {
	before := hostvm.IdentityReadback(id)
	h.Check("signal_exact_live_fixture_identity", before["same_identity_live"] == true && Int(before, "actual", "uid") == int64(os.Getuid()))
	Must(syscall.Kill(int(Int(id, "pid")), signal))
}
func runVMRecoveryCases(h *Harness) {
	s := newVMSuite(h)
	normalWorkspace, normalRunner := h.Workspace, h.Runner
	h.StartTimeout = 55 * time.Second
	h.StopTimeout = 30 * time.Second
	defer func() { h.Workspace = normalWorkspace; h.Runner = normalRunner; s.finish() }()
	root := vmCorpus(h)
	text := vmCorpusCases(h, root, "text_cases", []string{"ascii"})[0]
	archive := vmCorpusCases(h, root, "cases", []string{"parent_path"})[0]
	names := []string{"prepare-cancel", "cleanup-runner-death"}
	if h.PrepareOnly {
		names = names[:1]
	}
	names = vmSelected(h, names)
	prepared := map[string]Object{}
	for _, name := range names {
		phase := "prepare-cancel"
		if name == "cleanup-runner-death" {
			phase = "cleanup"
		}
		marker := filepath.Join(h.Out, name+"-runner.json")
		clone := vmFixtureWorkspace(h, phase, marker)
		prepared[name] = Object{"workspace": clone, "marker": marker}
	}
	cases := []Object{}
	for _, name := range names {
		record := prepared[name]
		h.Workspace = Str(record, "workspace")
		h.Runner = filepath.Join(h.Workspace, ".build/filegate-vm")
		h.Check(name+"_gates_closed", GatesClosed(s.start()))
		test := text
		if name == "cleanup-runner-death" {
			test = archive
		}
		receipt, directory := s.submit(test, name)
		out := filepath.Join(directory, "output")
		timeout := 30 * time.Second
		if name == "cleanup-runner-death" {
			timeout = 330 * time.Second
		}
		marker := Str(record, "marker")
		paused := vmWaitFile(h, marker, timeout)
		identity := Map(paused, "identity")
		s.runner = identity
		h.Check(name+"_producer_live", hostvm.IdentityReadback(identity)["same_identity_live"] == true)
		if name == "prepare-cancel" {
			owner := ReadJSON(filepath.Join(out, "preparation-owner.json"))
			preparation := ReadJSON(filepath.Join(out, "preparation-intent.json"))
			run := Str(preparation, "run_directory")
			h.Check("prepare_owner_before_go", Int(owner, "schema") == 1 && Str(owner, "kind") == "prepare_process_group" && Int(owner, "leader", "process_group") == Int(owner, "leader", "pid") && hostvm.IdentityReadback(Map(owner, "leader"))["same_identity_live"] == true && !Exists(filepath.Join(run, "work.raw")) && !Exists(filepath.Join(run, "prepared.json")))
			status, cancelled := h.Request("POST", "/v1/jobs/"+Str(receipt, "job_id")+"/cancel", Object{}, nil, nil)
			h.Check("prepare_cancel_accepted", status == 200 && Get(cancelled, "job_id") == Get(receipt, "job_id") && Str(cancelled, "phase") == "PREPARING" && Get(cancelled, "runtime_cleanup_complete") == false && Int(s.database(cancelled), "runtime", "cancel_requested") == 1)
			Write(marker+".release", nil)
			vmWaitFile(h, filepath.Join(out, "results.json"), 45*time.Second)
			job := vmWaitJob(h, Str(receipt, "job_id"), 45*time.Second)
			preparation = ReadJSON(filepath.Join(out, "preparation.json"))
			h.Check("prepare_cancel_before_ack", Get(preparation, "start_acknowledged") == false && Str(preparation, "failure") == "CONTROL_CANCELLED" && Bool(preparation, "stop_verified") && Bool(preparation, "stop_evidence", "group_empty") && Str(preparation, "ownership_sha256") == FileDigest(filepath.Join(out, "preparation-owner.json")) && Str(job, "phase") == "CANCELLED" && Str(job, "verdict") == "HOLD")
			proof := vmProofChain(h, out, job, "prepare_unstarted")
			h.Check("prepare_owner_stopped_proof", Str(proof, "evidence", "path") == "preparation-owner.json" && Equal(proof["checks"], Object{"leader_stopped": true, "group_empty": true}))
			database := s.database(job)
			h.Check("prepare_cancel_accounting", Bool(job, "runtime_cleanup_complete") && Int(database, "runtime", "raw_reserved") == 0 && Int(database, "remaining_pins") == 0 && Int(database, "remaining_queue") == 0)
			WriteJSON(filepath.Join(h.Out, name, "state.json"), Object{"intake": receipt, "job": job, "database": database, "paused": paused})
			h.Stop(false)
			vmWaitIdentityExit(h, "prepare_cancel_runner_exited", identity, 10*time.Second)
			s.directories = s.directories[:len(s.directories)-1]
		} else {
			intent := ReadJSON(filepath.Join(out, "cleanup-intent.json"))
			proof := ReadJSON(filepath.Join(out, "stop-proof.json"))
			native := ReadJSON(filepath.Join(out, "watchdog/results.json"))
			status, beforeJob := h.Request("GET", "/v1/jobs/"+Str(receipt, "job_id"), nil, nil, nil)
			database := s.database(beforeJob)
			rejection := database["rejection_evidence"]
			h.Check("cleanup_window_has_durable_block", status == 200 && Str(beforeJob, "verdict") == "BLOCK" && Get(beforeJob, "runtime_cleanup_complete") == false && len(rejection.([]Object)) == 1 && Str(intent, "stop_proof_sha256") == FileDigest(filepath.Join(out, "stop-proof.json")) && Str(proof, "kind") == "native_guardian" && Bool(proof, "stopped") && Str(proof, "evidence", "sha256") == FileDigest(filepath.Join(out, "watchdog/results.json")) && Bool(native, "guardian_result_verified") && Bool(native, "cleanup_all_exited") && Bool(native, "temporary_service_absent") && Bool(native, "terminal", "all_exited") && !Exists(filepath.Join(out, "cleanup-complete.json")) && !Exists(filepath.Join(out, "results.json")) && Int(database, "runtime", "raw_reserved") == 4<<30 && Int(database, "remaining_pins") == 1)
			for _, row := range List(intent, "directories") {
				h.Check("cleanup_retains_scoped_directory", Exists(Str(row, "path")))
			}
			vmSignal(h, identity, syscall.SIGKILL)
			vmWaitIdentityExit(h, "killed_runner_exited", identity, 10*time.Second)
			failed := vmWaitJob(h, Str(receipt, "job_id"), 45*time.Second)
			failedDB := s.database(failed)
			h.Check("runner_death_keeps_block_and_reservation", Str(failed, "phase") == "FAILED" && Str(failed, "verdict") == "BLOCK" && Get(failed, "runtime_cleanup_complete") == false && Contains(Get(failed, "execution_errors"), "VM_STOP_FAILED") && Equal(failedDB["rejection_evidence"], rejection) && Int(failedDB, "runtime", "raw_reserved") == 4<<30 && Int(failedDB, "remaining_pins") == 1)
			h.Stop(true)
			s.start()
			job := vmWaitJob(h, Str(receipt, "job_id"), 45*time.Second)
			after := s.database(job)
			h.Check("restart_recovers_without_rewriting_attempt", Str(job, "verdict") == "BLOCK" && Str(job, "phase") == "FAILED" && Equal(after["rejection_evidence"], rejection) && Equal(after["attempt"], failedDB["attempt"]))
			vmProofChain(h, out, job, "native_guardian")
			s.persist(name, receipt, job, directory, false)
			recoverySHA := FileDigest(filepath.Join(out, "recovery-results.json"))
			h.Stop(false)
			s.start()
			status, repeated := h.Request("GET", "/v1/jobs/"+Str(job, "job_id"), nil, nil, nil)
			h.Check("recovery_settlement_is_idempotent", status == 200 && Equal(repeated, job) && Equal(s.database(repeated), after) && FileDigest(filepath.Join(out, "recovery-results.json")) == recoverySHA)
			h.Stop(false)
		}
		cases = append(cases, Object{"name": name, "producer_exited": hostvm.IdentityReadback(identity)["same_identity_live"] == false, "runtime_artifacts_sha256": vmCopyRuntime(h, directory, filepath.Join(h.Out, name, "runtime"))})
		h.Record["cases"] = cases
		h.Workspace = normalWorkspace
		h.Runner = normalRunner
	}
	h.Check("selected_recovery_cases_complete", len(cases) == len(names))
	h.Record["all_runtime_cleanup_confirmed"] = true
}
