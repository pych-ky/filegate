package verification

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"
)

func init() { Register("retention", runVMRetention) }
func vmChangeState(h *Harness, change func(*sql.Tx)) {
	h.Check("fixture_changes_only_while_service_stopped", h.Process == nil)
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(h.Data, "state.sqlite")+"?mode=rw")
	Must(err)
	defer db.Close()
	transaction, err := db.Begin()
	Must(err)
	defer transaction.Rollback()
	change(transaction)
	Must(transaction.Commit())
}
func vmResolved(h *Harness, job Object) int64 {
	rows := h.Query("SELECT resolved_at FROM runtime_finalizations WHERE attempt_id=?", Str(job, "attempt_id"))
	if len(rows) == 0 {
		return -1
	}
	return Int(Object{"n": rows[0][0]}, "n")
}
func vmAgeFixture(h *Harness, jobID string, created, finished, resolved int, pin int) {
	vmChangeState(h, func(tx *sql.Tx) {
		var body []byte
		Must(tx.QueryRow("SELECT data FROM jobs WHERE id=?", jobID).Scan(&body))
		job := Decode(body)
		now := time.Now().UTC()
		if created >= 0 {
			value := now.Add(-time.Duration(created) * 24 * time.Hour)
			job["created_at"] = value.Format(time.RFC3339Nano)
			_, err := tx.Exec("UPDATE jobs SET created=? WHERE id=?", value.UnixNano(), jobID)
			Must(err)
		}
		if finished >= 0 {
			value := now.Add(-time.Duration(finished) * 24 * time.Hour)
			job["finished_at"] = value.Format(time.RFC3339Nano)
			_, err := tx.Exec("UPDATE jobs SET finished=? WHERE id=?", value.UnixNano(), jobID)
			Must(err)
		}
		_, err := tx.Exec("UPDATE jobs SET data=? WHERE id=?", Encoded(job), jobID)
		Must(err)
		if pin == 1 {
			_, err = tx.Exec("INSERT INTO resource_pins(owner_id,object_id) VALUES(?,?)", "retention_fixture", Str(job, "input_receipt", "object_id"))
			Must(err)
		} else if pin == 0 {
			_, err = tx.Exec("DELETE FROM resource_pins WHERE owner_id=?", "retention_fixture")
			Must(err)
		}
		if resolved >= 0 {
			value := now.Add(-time.Duration(resolved) * 24 * time.Hour)
			_, err = tx.Exec("UPDATE runtime_finalizations SET resolved_at=? WHERE attempt_id=?", value.UnixNano(), Str(job, "attempt_id"))
			Must(err)
		}
	})
}
func vmRetentionSnapshot(s *vmSuite, name string, job Object) Object {
	value := s.database(job)
	value["resolved_at"] = vmResolved(s.h, job)
	WriteJSON(filepath.Join(s.h.Out, name+".json"), value)
	return value
}
func vmRuntimeFiles(h *Harness, directory, except string) map[string]string {
	hashes := map[string]string{}
	Must(filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			panic(Failure{"runtime_artifact_symlink"})
		}
		if entry.IsDir() || path == except {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		hashes[relative] = FileDigest(path)
		return nil
	}))
	return hashes
}
func vmRetentionCrash(h *Harness, window string) {
	args := []string{h.Binary, "--data-dir", h.Data, "serve", "--input-root", "fixture=" + h.InputDirectory, "--input-root", "alias=" + h.InputDirectory, "--vm-runner", h.Runner, "--vm-workspace", h.Workspace, "--vm-proof", h.Proof}
	result := Execute(h.Root, args, nil, 30*time.Second)
	h.Logs = append(h.Logs, result.Stdout, result.Stderr)
	h.Check("recovery_stopped_"+window, result.ExitCode == 91)
}
func runVMRetention(h *Harness) {
	s := newVMSuite(h)
	defer s.finish()
	normal := h.Binary
	source := filepath.Join(h.Root, "internal/broker/runtime_retention.go")
	body := string(Read(source))
	binaries := map[string]string{"normal": normal}
	for _, window := range []struct{ name, marker string }{{"before-delete", "\tpath := filepath.Join(directory, \"output\", \"report.json\")"}, {"after-sync", "\t// 停止・回収証拠と確定済み判定は、詳細レポートの期限削除から分離する。"}} {
		binary := filepath.Join(h.Out, "filegate-retention-"+window.name)
		BuildOverlay(h, "retention-"+window.name, binary, map[string]string{source: ReplaceOnce(body, window.marker, "\tos.Exit(91)\n"+window.marker)})
		binaries[window.name] = binary
	}
	root := vmCorpus(h)
	archive := vmCorpusCases(h, root, "cases", []string{"parent_path"})[0]
	h.Check("gates_closed", GatesClosed(s.start()))
	receipt, directory := s.submit(archive, "retention-block")
	id := Str(receipt, "job_id")
	code, job := vmWaitCLI(h, id)
	h.Check("real_vm_block", code == 20 && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "BLOCK")
	before := s.persist("real-block", receipt, job, directory, true)
	h.Check("runtime_verified_before_retention", Str(before, "runtime", "state") == "FINISHED" && Int(before, "runtime", "report_reserved") > 0 && Int(before, "remaining_pins") == 0)
	report := filepath.Join(directory, "output/report.json")
	original := filepath.Join(h.Data, "objects", Str(receipt, "input_receipt", "object_id"))
	reportSHA := FileDigest(report)
	controls := vmRuntimeFiles(h, directory, report)
	h.Stop(false)
	h.Check("runtime_finalization_recorded", vmResolved(h, job) > 0)
	vmChangeState(h, func(tx *sql.Tx) {
		_, err := tx.Exec("DELETE FROM runtime_finalizations WHERE attempt_id=?", Str(job, "attempt_id"))
		Must(err)
	})
	migrationStarted := time.Now().UnixNano()
	s.start()
	resolvedAt := vmResolved(h, job)
	h.Check("legacy_finished_resolution_starts_now", resolvedAt >= migrationStarted)
	h.Stop(false)
	vmAgeFixture(h, id, 6, -1, -1, -1)
	s.start()
	status, result := h.Request("POST", "/v1/prune", Object{}, nil, nil)
	h.Check("before_seven_days_preserved", status == 200 && Int(result, "objects_removed") == 0 && Int(result, "jobs_removed") == 0 && FileDigest(report) == reportSHA && Exists(original))
	h.Stop(false)
	vmAgeFixture(h, id, 8, -1, -1, 1)
	s.start()
	status, result = h.Request("POST", "/v1/prune", Object{}, nil, nil)
	h.Check("expired_pinned_data_preserved", status == 200 && Int(result, "objects_removed") == 0 && Int(result, "jobs_removed") == 0 && FileDigest(report) == reportSHA && Exists(original))
	h.Stop(false)
	vmAgeFixture(h, id, -1, -1, -1, 0)
	Must(os.Chmod(report, 0644))
	s.start()
	status, failure := h.Request("POST", "/v1/prune", Object{}, nil, nil)
	h.Check("unsafe_report_keeps_deletion_pending", status == 503 && ErrorCode(failure) == "CLEANUP_PENDING" && FileDigest(report) == reportSHA)
	h.Stop(false)
	Must(os.Chmod(report, 0600))
	h.Binary = binaries["before-delete"]
	vmRetentionCrash(h, "before_report_delete")
	first := vmRetentionSnapshot(s, "before-report-delete", job)
	h.Check("durable_report_deletion_intent", Str(first, "runtime", "state") == "REPORT_PRUNING" && Int(first, "runtime", "report_reserved") == Int(before, "runtime", "report_reserved") && FileDigest(report) == reportSHA && !Exists(original) && Equal(first["attempt"], before["attempt"]) && Equal(first["rejection_evidence"], before["rejection_evidence"]))
	h.Binary = binaries["after-sync"]
	vmRetentionCrash(h, "after_report_sync")
	second := vmRetentionSnapshot(s, "after-report-sync", job)
	h.Check("deleted_report_still_charged_until_commit", !Exists(report) && Str(second, "runtime", "state") == "REPORT_PRUNING" && Int(second, "runtime", "report_reserved") == Int(before, "runtime", "report_reserved") && Equal(second["attempt"], before["attempt"]) && Equal(second["rejection_evidence"], before["rejection_evidence"]))
	h.Binary = normal
	s.start()
	status, current := h.Request("GET", "/v1/jobs/"+id, nil, nil, nil)
	after := vmRetentionSnapshot(s, "report-deletion-complete", current)
	h.Check("report_deletion_recovers_without_verdict_change", status == 200 && Str(current, "verdict") == "BLOCK" && Bool(current, "runtime_cleanup_complete") && Get(current, "release", "eligible") == false && Get(current, "input_receipt", "content_available") == false && !Exists(report) && Str(after, "runtime", "state") == "FINISHED" && Int(after, "runtime", "report_reserved") == 0 && Int(after, "runtime", "raw_reserved") == 0 && Str(after, "runtime", "report_sha256") == reportSHA && Int(after, "runtime", "control_reserved") == Int(before, "runtime", "control_reserved") && Int(after, "resolved_at") == resolvedAt && Equal(after["attempt"], before["attempt"]) && Equal(after["rejection_evidence"], before["rejection_evidence"]))
	h.Check("stop_and_cleanup_evidence_unchanged", Equal(vmRuntimeFiles(h, directory, report), controls))
	code, replay := vmSubmit(h, filepath.Join(h.InputDirectory, Str(archive, "name")), Object{"idempotency_key": "retention-block", "expected_type": "zip", "expected_sha256": archive["sha256"]})
	h.Check("expired_original_replay_preserves_receipt", code == 0 && Bool(replay, "replayed") && Str(replay, "job_id") == id && Get(replay, "current_input_checked") == false && Get(replay, "body_consumed") == false && Get(replay, "input_receipt", "content_available") == false && Str(replay, "input_receipt", "sha256") == Str(receipt, "input_receipt", "sha256") && Str(replay, "job", "verdict") == "BLOCK")
	status, repeated := h.Request("POST", "/v1/prune", Object{}, nil, nil)
	expected := vmClone(after)
	delete(expected, "resolved_at")
	h.Check("repeated_prune_is_idempotent", status == 200 && Int(repeated, "objects_removed") == 0 && Int(repeated, "jobs_removed") == 0 && Equal(s.database(current), expected))
	h.Stop(false)
	s.start()
	h.Check("second_restart_preserves_evidence", Equal(s.database(current), expected) && vmResolved(h, current) == resolvedAt)
	h.Stop(false)
	s.stopped(directory)
	vmAgeFixture(h, id, 40, 31, -1, -1)
	s.start()
	status, result = h.Request("POST", "/v1/prune", Object{}, nil, nil)
	h.Check("recent_resolution_protects_old_terminal_history", status == 200 && Int(result, "jobs_removed") == 0 && Exists(directory) && vmResolved(h, current) == resolvedAt)
	h.Stop(false)
	vmAgeFixture(h, id, -1, -1, 31, -1)
	s.start()
	status, result = h.Request("POST", "/v1/prune", Object{}, nil, nil)
	h.Check("thirty_day_history_pruned", status == 200 && Int(result, "objects_removed") == 0 && Int(result, "jobs_removed") == 1 && !Exists(directory))
	code, expired := vmSubmit(h, filepath.Join(h.InputDirectory, Str(archive, "name")), Object{"idempotency_key": "retention-block", "expected_type": "zip", "expected_sha256": archive["sha256"]})
	h.Check("old_key_stays_expired", code == 2 && ErrorCode(expired) == "KEY_EXPIRED")
	counts := Object{}
	for _, table := range []string{"jobs", "attempts", "runtime_runs", "runtime_finalizations", "rejection_evidence", "resource_pins", "tombstones"} {
		counts[table] = vmScalar(h, "SELECT count(*) FROM "+table)
	}
	h.Check("history_reclaimed_tombstone_retained", Equal(counts, Object{"jobs": 0, "attempts": 0, "runtime_runs": 0, "runtime_finalizations": 0, "rejection_evidence": 0, "resource_pins": 0, "tombstones": 1}))
	WriteJSON(filepath.Join(h.Out, "history-counts.json"), counts)
	h.Stop(false)
	s.directories = nil
	home, err := os.UserHomeDir()
	Must(err)
	h.Check("no_new_vm_after_retention", !Exists(filepath.Join(home, "Library/Application Support/FileGate/verification/experiments/host/.build/active-vm.json")))
	h.Record["retention_timestamps_are_fixture_data"] = true
}
