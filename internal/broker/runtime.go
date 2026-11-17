package broker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	updatecontrol "filegate.local/filegate/internal/update"
)

type runtimeSummary struct {
	Schema         int     `json:"schema"`
	JobID          string  `json:"job_id"`
	AttemptID      string  `json:"attempt_id"`
	Passed         bool    `json:"passed"`
	ReportSHA256   *string `json:"report_sha256"`
	ReportAccepted bool    `json:"report_accepted"`
	Termination    struct {
		AllExited        bool   `json:"all_exited"`
		IdentityVerified bool   `json:"identity_verified"`
		StopFailed       bool   `json:"stop_failed"`
		ReasonCode       string `json:"reason_code"`
	} `json:"termination"`
	RawReclaimed           bool             `json:"raw_reclaimed"`
	VMSlotFinalized        bool             `json:"vm_slot_finalized"`
	ReservationChargeBytes int64            `json:"reservation_charge_bytes"`
	NativeEvidence         *runtimeEvidence `json:"native_evidence"`
	RecoveryEvidence       *runtimeEvidence `json:"recovery_evidence,omitempty"`
	ProductEnabled         bool             `json:"product_enabled"`
	Stage0GatePassed       bool             `json:"stage0_gate_passed"`
}

type runtimeEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type runtimeEvent struct {
	Event             string          `json:"event"`
	RawAllocatedBytes int64           `json:"raw_allocated_bytes,omitempty"`
	ReportPath        string          `json:"report_path,omitempty"`
	Progress          json.RawMessage `json:"progress,omitempty"`
}

func (b *Broker) executeScan(run *scanRun) {
	select {
	case <-run.stopped:
		b.finishScan(run, nil, run.stopReason, true)
		return
	default:
	}
	var metadata scanMetadata
	b.mu.Lock()
	var stored []byte
	err := b.db.QueryRow("SELECT data FROM intake_metadata WHERE job_id=?", run.job.JobID).Scan(&stored)
	b.mu.Unlock()
	if err == nil {
		err = json.Unmarshal(stored, &metadata)
	}
	if len(metadata.DisplayName) > 2048 || len(metadata.DeclaredMediaType) > 256 || len(metadata.ExpectedType) > 32 {
		err = failure("UNSUPPORTED_FORMAT", 400)
	}
	request := scanRequest{SchemaVersion: 2, JobID: run.job.JobID, AttemptID: run.job.AttemptID, PolicyDigest: formatPolicy, InputPath: filepath.Join(b.config.DataDir, "objects", run.job.InputReceipt.ObjectID), ExpectedSHA256: run.job.InputReceipt.SHA256, ByteSize: run.job.InputReceipt.ByteSize, Metadata: metadata}
	if run.definition != nil {
		request.SchemaVersion, request.Definition = 3, run.definition
	}
	if err == nil {
		err = writePrivate(filepath.Join(run.directory, "request.json"), request)
	}
	if err != nil {
		b.finishScan(run, nil, "VM_START_FAILED", true)
		return
	}
	startupLock, err := b.prepareStartup(run)
	if err != nil {
		b.finishScan(run, nil, "VM_START_FAILED", true)
		return
	}
	defer startupLock.Close()
	vm := b.config.VM
	cmd := exec.Command(vm.RunnerPath, "--request", filepath.Join(run.directory, "request.json"), "--out", filepath.Join(run.directory, "output"), "--proof", vm.Proof, "--startup-lock-fd", "3")
	cmd.Dir = vm.Workspace
	cmd.ExtraFiles = []*os.File{startupLock}
	input, err := cmd.StdinPipe()
	if err != nil {
		b.finishScan(run, nil, "VM_START_FAILED", true)
		return
	}
	output, writer, err := os.Pipe()
	if err != nil {
		input.Close()
		b.finishScan(run, nil, "VM_START_FAILED", true)
		return
	}
	cmd.Stdout = writer
	cmd.Stderr = io.Discard
	err = cmd.Start()
	writer.Close()
	if err != nil {
		input.Close()
		output.Close()
		b.finishScan(run, nil, "VM_START_FAILED", true)
		return
	}
	defer output.Close()
	defer input.Close()
	defer run.stop()
	inputContext, finishInput := context.WithCancel(context.Background())
	defer finishInput()
	go func() {
		defer input.Close()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-inputContext.Done():
				return
			case <-run.stopped:
				return
			case <-run.accepted:
				if _, err := io.WriteString(input, "report-accepted\n"); err != nil {
					run.stop()
					return
				}
			case <-ticker.C:
				if _, err := io.WriteString(input, "heartbeat\n"); err != nil {
					run.stop()
					return
				}
			}
		}
	}()
	events := make(chan []byte, 8)
	readingDone := make(chan struct{})
	defer close(readingDone)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			select {
			case events <- line:
			case <-readingDone:
				return
			}
		}
		if scanner.Err() != nil {
			select {
			case events <- nil:
			case <-readingDone:
			}
		}
	}()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	deadline := time.NewTimer(315 * time.Second)
	defer deadline.Stop()
	monitor := time.NewTicker(time.Second)
	defer monitor.Stop()
	var stopDeadline *time.Timer
	var stopExpiry <-chan time.Time
	stopSignal := run.stopped
	var report *scanReport
	reportDigest := ""
	reason := ""
	finished, seenPreparing, seenInspecting, seenReport := false, false, false, false
	seenFinished, runnerFailed := false, false
	for !finished || events != nil {
		select {
		case <-stopSignal:
			stopSignal = nil
			stopDeadline = time.NewTimer(35 * time.Second)
			defer stopDeadline.Stop()
			stopExpiry = stopDeadline.C
			if reason == "" {
				reason = run.stopReason
			}
		case <-stopExpiry:
			b.finishScan(run, nil, "VM_STOP_FAILED", false)
			return
		case <-deadline.C:
			reason = "SCAN_TIMEOUT"
			run.stop()
		case <-monitor.C:
			b.mu.Lock()
			pending, e := b.pendingRuntime(b.db)
			inputs, inputErr := b.pendingInputs(b.db)
			pending += inputs
			if e == nil {
				e = inputErr
			}
			b.mu.Unlock()
			if e == nil {
				e = checkFree(b.config.DataDir, pending)
			}
			if e != nil && reason == "" {
				reason = errorReason(e)
				run.stop()
			}
		case processErr := <-waited:
			runnerFailed = processErr != nil
			finished = true
			waited = nil
		case line, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			var event runtimeEvent
			if strictJSON(line, &event) != nil {
				reason = "REPORT_VALIDATION_FAILED"
				run.stop()
				continue
			}
			if event.Event != "PROGRESS" && len(event.Progress) != 0 {
				reason = "REPORT_VALIDATION_FAILED"
				run.stop()
				continue
			}
			switch event.Event {
			case "PROGRESS":
				if !seenInspecting || seenReport || seenFinished || event.RawAllocatedBytes != 0 || event.ReportPath != "" || b.scanProgress(run, event.Progress) != nil {
					reason = "REPORT_VALIDATION_FAILED"
					run.stop()
				}
			case "PREPARING":
				if seenPreparing || seenInspecting || event.RawAllocatedBytes != 0 || event.ReportPath != "" {
					reason = "REPORT_VALIDATION_FAILED"
					run.stop()
					continue
				}
				seenPreparing = true
			case "INSPECTING":
				if !seenPreparing || seenInspecting || event.RawAllocatedBytes != rawReservation || event.ReportPath != "" {
					reason = "REPORT_VALIDATION_FAILED"
					run.stop()
					continue
				}
				seenInspecting = true
				if err = b.scanPhase(run, "INSPECTING", rawReservation); err != nil {
					reason = errorReason(err)
					run.stop()
				}
			case "REPORT_READY":
				if !seenInspecting || seenReport || event.RawAllocatedBytes != 0 || event.ReportPath != filepath.Join(run.directory, "output", "report.json") {
					reason = "REPORT_VALIDATION_FAILED"
					run.stop()
					continue
				}
				seenReport = true
				value, digest, e := b.acceptReport(run)
				if e != nil {
					reason = errorReason(e)
					run.stop()
					continue
				}
				report = &value
				reportDigest = digest
				if !b.progressMatchesReport(run, value) {
					reason = "REPORT_VALIDATION_FAILED"
					run.stop()
					continue
				}
				select {
				case run.accepted <- struct{}{}:
				case <-run.stopped:
				}
			case "FINISHED":
				if seenFinished || event.RawAllocatedBytes != 0 || event.ReportPath != "" {
					reason = "REPORT_VALIDATION_FAILED"
					run.stop()
				}
				seenFinished = true
				finishInput()
			default:
				reason = "REPORT_VALIDATION_FAILED"
				run.stop()
			}
		}
	}
	summary, e := readRuntimeSummary(run)
	if e != nil {
		b.finishScan(run, nil, "VM_STOP_FAILED", false)
		return
	}
	if reason == "INTERRUPTED" && !runnerFailed && seenFinished && summary.Passed && summary.ReportAccepted {
		reason = ""
	}
	if run.definition != nil && (reason == "" || reason == "INTERRUPTED") && summary.Termination.ReasonCode == "DATABASE_STALE" {
		reason = "DATABASE_STALE"
	}
	if reason == "" && (runnerFailed || !seenFinished) {
		reason = "INTERRUPTED"
	}
	if reason == "" && (!summary.Passed || !summary.ReportAccepted || report == nil) {
		reason = summary.Termination.ReasonCode
		if reason == "EXCHANGE_COMPLETE" {
			reason = "INCOMPLETE_REQUIRED_CHECKS"
		}
	}
	if report != nil && summary.ReportSHA256 != nil {
		_, digest, e := decodeReport(filepath.Join(run.directory, "output", "report.json"), run.job, run.definitionBinding())
		if e != nil || digest != *summary.ReportSHA256 || digest != reportDigest {
			reason = "REPORT_VALIDATION_FAILED"
			report = nil
		}
	}
	b.finishScan(run, report, reason, true)
}

func readRuntimeSummary(run *scanRun) (runtimeSummary, error) {
	return readRuntimeSummaryKeeping(run, nil)
}

// readRuntimeSummaryKeeping sets a non-nil normal to the validated results.json bytes only when that file, not
// recovery-results.json, was the summary read.
func readRuntimeSummaryKeeping(run *scanRun, normal *[]byte) (runtimeSummary, error) {
	var summary runtimeSummary
	path := filepath.Join(run.directory, "output", "recovery-results.json")
	_, recoveryErr := os.Lstat(path)
	if os.IsNotExist(recoveryErr) {
		path = filepath.Join(run.directory, "output", "results.json")
	} else if recoveryErr != nil {
		return summary, failure("VM_STOP_FAILED", 503)
	}
	body, err := readPrivate(path, 64<<10)
	if err != nil || strictJSON(body, &summary) != nil {
		return summary, failure("VM_STOP_FAILED", 503)
	}
	summaryBody := body
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || (len(fields) != 13 && len(fields) != 14) {
		return summary, failure("VM_STOP_FAILED", 503)
	}
	for _, name := range []string{"schema", "job_id", "attempt_id", "passed", "report_sha256", "report_accepted", "termination", "raw_reclaimed", "vm_slot_finalized", "reservation_charge_bytes", "native_evidence", "product_enabled", "stage0_gate_passed"} {
		value, ok := fields[name]
		if !ok || (string(value) == "null" && name != "native_evidence" && name != "report_sha256") {
			return summary, failure("VM_STOP_FAILED", 503)
		}
	}
	if _, err = requiredFields(fields["termination"], "all_exited", "identity_verified", "stop_failed", "reason_code"); err != nil {
		return summary, failure("VM_STOP_FAILED", 503)
	}
	if (len(fields) == 14 || recoveryErr == nil) && summary.RecoveryEvidence == nil {
		return summary, failure("VM_STOP_FAILED", 503)
	}
	if summary.Schema != 1 || summary.JobID != run.job.JobID || summary.AttemptID != run.job.AttemptID || summary.ProductEnabled || summary.Stage0GatePassed || !summary.Termination.AllExited || !summary.Termination.IdentityVerified || summary.Termination.StopFailed || !summary.RawReclaimed || !summary.VMSlotFinalized || summary.ReservationChargeBytes != 0 {
		return summary, failure("VM_STOP_FAILED", 503)
	}
	reasons := map[string]bool{"EXCHANGE_COMPLETE": true, "INTERRUPTED": true, "SCAN_TIMEOUT": true, "RESOURCE_MONITOR_FAILED": true, "HOST_RESOURCE_PRESSURE": true, "WORKSPACE_LIMIT": true, "WORKSPACE_IO_ERROR": true, "WORKSPACE_CONFIGURATION_ERROR": true, "REPORT_VALIDATION_FAILED": true, "INCOMPLETE_REQUIRED_CHECKS": true, "DATABASE_STALE": true}
	if !reasons[summary.Termination.ReasonCode] || (summary.ReportAccepted && (summary.ReportSHA256 == nil || !validDigest(*summary.ReportSHA256))) {
		return summary, failure("VM_STOP_FAILED", 503)
	}
	if summary.RecoveryEvidence != nil {
		if _, err = requiredFields(fields["recovery_evidence"], "path", "sha256"); err != nil || validateRecoveryEvidence(run, summary) != nil {
			return summary, failure("VM_STOP_FAILED", 503)
		}
	}
	if evidence := summary.NativeEvidence; evidence != nil {
		if _, err = requiredFields(fields["native_evidence"], "path", "sha256"); err != nil {
			return summary, failure("VM_STOP_FAILED", 503)
		}
		if evidence.Path != "watchdog/results.json" || !validDigest(evidence.SHA256) {
			return summary, failure("VM_STOP_FAILED", 503)
		}
		body, err = readPrivate(filepath.Join(run.directory, "output", "watchdog", "results.json"), controlReservation)
		if err != nil {
			return summary, failure("VM_STOP_FAILED", 503)
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != evidence.SHA256 {
			return summary, failure("VM_STOP_FAILED", 503)
		}
		var native struct {
			Kind                   string `json:"kind"`
			ProcessGroupEmpty      bool   `json:"process_group_empty"`
			GuardianResultVerified bool   `json:"guardian_result_verified"`
			CleanupAllExited       bool   `json:"cleanup_all_exited"`
			TemporaryServiceAbsent bool   `json:"temporary_service_absent"`
			EmergencyOwnedCleanup  bool   `json:"emergency_owned_cleanup"`
			Terminal               *struct {
				AllExited bool `json:"all_exited"`
			} `json:"terminal"`
		}
		if json.Unmarshal(body, &native) != nil || !native.CleanupAllExited || !native.TemporaryServiceAbsent || native.EmergencyOwnedCleanup {
			return summary, failure("VM_STOP_FAILED", 503)
		}
		if native.Kind == "recovered_native_guardian" || native.Kind == "recovered_native_group" {
			var complete struct {
				Kind string `json:"kind"`
			}
			completion, e := readPrivate(filepath.Join(run.directory, "output", "cleanup-complete.json"), 64<<10)
			expected := "native_guardian"
			valid := native.GuardianResultVerified
			if native.Kind == "recovered_native_group" {
				expected, valid = "native_stopped_group", native.ProcessGroupEmpty && !native.GuardianResultVerified
			}
			if summary.RecoveryEvidence == nil || native.Terminal != nil || !valid || e != nil || json.Unmarshal(completion, &complete) != nil || complete.Kind != expected {
				return summary, failure("VM_STOP_FAILED", 503)
			}
		} else if !native.GuardianResultVerified || native.Terminal == nil || !native.Terminal.AllExited {
			return summary, failure("VM_STOP_FAILED", 503)
		}
		var cleanup struct {
			Reclaimed   bool  `json:"reclaimed"`
			Reservation int64 `json:"reservation_charge_bytes"`
		}
		cleanupBody, e := readPrivate(filepath.Join(run.directory, "output", "raw-cleanup.json"), 64<<10)
		if e != nil || json.Unmarshal(cleanupBody, &cleanup) != nil || !cleanup.Reclaimed || cleanup.Reservation != 0 {
			return summary, failure("VM_STOP_FAILED", 503)
		}
	} else {
		_, startedErr := os.Lstat(filepath.Join(run.directory, "output", "vm-started.json"))
		previousBoot := false
		if summary.RecoveryEvidence != nil {
			var complete cleanupComplete
			completion, e := readPrivate(filepath.Join(run.directory, "output", "cleanup-complete.json"), 64<<10)
			previousBoot = e == nil && strictJSON(completion, &complete) == nil && complete.Kind == "native_previous_boot"
		}
		if summary.Passed || summary.ReportAccepted || summary.ReportSHA256 != nil || (!os.IsNotExist(startedErr) && !previousBoot) {
			return summary, failure("VM_STOP_FAILED", 503)
		}
	}
	if normal != nil && os.IsNotExist(recoveryErr) {
		*normal = summaryBody
	}
	return summary, nil
}

func (b *Broker) finishScan(run *scanRun, report *scanReport, reason string, clean bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.finishScanLocked(run, report, reason, clean) != nil {
		b.recoveryBlocked = true
	}
}

func (b *Broker) finishScanLocked(run *scanRun, report *scanReport, reason string, clean bool) error {
	var releaseSnapshot *scanReleaseSnapshot
	if clean && reason == "" && run.definition != nil && report != nil && completeScanReport(*report) {
		verified, err := b.validateScanRelease(run, *report)
		if err != nil {
			reason = "REPORT_VALIDATION_FAILED"
		} else {
			releaseSnapshot = &verified
		}
	}
	var reportBytes, controlBytes int64
	if clean {
		var err error
		reportBytes, controlBytes, err = runtimeCharges(run.directory)
		if err != nil {
			clean = false
		}
	}
	ctx := context.Background()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	j, err := readJob(ctx, tx, run.job.JobID)
	if err != nil {
		return err
	}
	if j.AttemptID != run.job.AttemptID {
		return failure("RECOVERY_REQUIRED", 503)
	}
	var cancelled int
	if tx.QueryRow("SELECT cancel_requested FROM runtime_runs WHERE attempt_id=?", j.AttemptID).Scan(&cancelled) != nil {
		return storageError()
	}
	if !clean {
		b.recoveryBlocked = true
		reason = "VM_STOP_FAILED"
	}
	wasTerminal := j.Terminal()
	if !wasTerminal && releaseSnapshot != nil && clean && reason == "" && cancelled == 0 {
		finished, clockErr := updatecontrol.ReadClock()
		if clockErr != nil || finished.Boot != releaseSnapshot.Captured.Boot || finished.UTC < releaseSnapshot.Captured.UTC || finished.ContinuousNS < releaseSnapshot.Captured.ContinuousNS {
			releaseSnapshot = nil
			reason = "UPDATE_CLOCK_UNCERTAIN"
		} else {
			releaseSnapshot.Finished = &finished
		}
	}
	if !wasTerminal {
		j.Phase = "FINISHED"
		j.FinishedAt = nowText()
		if releaseSnapshot != nil && releaseSnapshot.Finished != nil {
			j.FinishedAt = time.Unix(releaseSnapshot.Finished.UTC, 0).UTC().Format(time.RFC3339Nano)
		}
		j.Release.Eligible = false
		if j.Verdict != "BLOCK" {
			j.Verdict = "HOLD"
			j.ReasonCodes = []string{"INCOMPLETE_REQUIRED_CHECKS"}
			if report != nil && report.Result.StructureStatus == "HOLD" {
				j.ReasonCodes = append(j.ReasonCodes, report.Result.Reasons...)
			}
			if report != nil {
				for _, code := range report.AV.ReasonCodes {
					if code != "INCOMPLETE_REQUIRED_CHECKS" {
						j.ReasonCodes = append(j.ReasonCodes, code)
					}
				}
			}
		}
		if j.Verdict != "BLOCK" && releaseSnapshot != nil && clean && reason == "" && cancelled == 0 {
			j.Coverage.RequiredChecksComplete = Stage0Passed
			if Stage0Passed {
				j.Verdict = "PASS"
				j.ReasonCodes = []string{}
			}
		}
		if reason != "" {
			j.Phase = "FAILED"
			j.ExecutionErrors = append(j.ExecutionErrors, reason)
			j.ReasonCodes = append(j.ReasonCodes, reason)
		}
		if cancelled != 0 {
			j.Phase = "CANCELLED"
			j.ExecutionErrors = append(j.ExecutionErrors, "CANCELLED")
			j.ReasonCodes = append(j.ReasonCodes, "CANCELLED")
		}
		if (report == nil || reason != "" || cancelled != 0) && j.Coverage.AVResult != "detected" {
			j.Coverage.AVResult = "inconclusive"
		}
	}
	j.RuntimeCleanupComplete = clean
	if writeJob(ctx, tx, j) != nil {
		return storageError()
	}
	if !wasTerminal {
		if _, err = tx.Exec("UPDATE attempts SET data=? WHERE id=?", encode(j), j.AttemptID); err != nil {
			return storageError()
		}
		if releaseSnapshot != nil && clean && reason == "" && cancelled == 0 {
			if _, err = tx.Exec("UPDATE scan_release_snapshots SET data=? WHERE attempt_id=?", encode(releaseSnapshot), j.AttemptID); err != nil {
				return storageError()
			}
		}
	}
	if clean {
		if _, err = tx.Exec("UPDATE runtime_runs SET state='FINISHED',raw_reserved=0,raw_written=0,report_reserved=?,control_reserved=? WHERE attempt_id=?", reportBytes, controlBytes, j.AttemptID); err != nil {
			return storageError()
		}
		if _, err = tx.Exec("INSERT OR IGNORE INTO runtime_finalizations(attempt_id,resolved_at) VALUES(?,?)", j.AttemptID, time.Now().UnixNano()); err != nil {
			return storageError()
		}
		if _, err = tx.Exec("DELETE FROM resource_pins WHERE owner_id=?", j.AttemptID); err != nil {
			return storageError()
		}
		if _, err = tx.Exec("UPDATE scan_definition_snapshots SET active=0 WHERE attempt_id=?", j.AttemptID); err != nil {
			return storageError()
		}
		if _, err = tx.Exec("DELETE FROM scan_queue WHERE job_id=?", j.JobID); err != nil {
			return storageError()
		}
	} else if _, err = tx.Exec("UPDATE runtime_runs SET state='STOP_FAILED' WHERE attempt_id=?", j.AttemptID); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) pendingRuntime(q queryer) (int64, error) {
	var pending int64
	err := q.QueryRowContext(context.Background(), "SELECT coalesce(sum(max(0,raw_reserved-raw_written)+report_reserved+control_reserved),0) FROM runtime_runs WHERE state!='FINISHED'").Scan(&pending)
	if err != nil {
		return 0, storageError()
	}
	releases, err := b.pendingReleaseStorage(q)
	if err != nil {
		return 0, err
	}
	updates, err := b.pendingUpdates(q)
	if err != nil {
		return 0, err
	}
	return pending + releases + updates, nil
}

func (b *Broker) recoverScans() error {
	rows, err := b.db.Query("SELECT job_id,attempt_id,directory,state FROM runtime_runs WHERE state!='FINISHED'")
	if err != nil {
		return storageError()
	}
	type recovery struct{ job, attempt, directory, state string }
	var pending []recovery
	for rows.Next() {
		var r recovery
		if rows.Scan(&r.job, &r.attempt, &r.directory, &r.state) != nil {
			rows.Close()
			return storageError()
		}
		pending = append(pending, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, r := range pending {
		if r.state == "REPORT_PRUNING" {
			if err = b.finishReportDeletion(r.attempt, r.directory); err != nil {
				return err
			}
			continue
		}
		if r.state == "PRUNING" {
			if err = b.finishRuntimeDeletion(r.attempt, r.directory); err != nil {
				return err
			}
			continue
		}
		j, e := readJob(context.Background(), b.db, r.job)
		if e != nil {
			return e
		}
		if j.AttemptID != r.attempt || r.directory != filepath.Join(b.config.DataDir, "runtime", r.attempt) {
			return failure("RECOVERY_REQUIRED", 503)
		}
		run := &scanRun{job: j, directory: r.directory}
		handled, e := b.recoverStartup(run, r.state)
		if !handled {
			e = b.validateScanRequest(run)
			if e == nil {
				_, e = readRuntimeSummary(run)
				if e != nil {
					e = b.recoverRuntime(run)
				}
			}
		}
		if e = b.finishScanLocked(run, nil, "INTERRUPTED", e == nil); e != nil {
			return e
		}
	}
	rows, err = b.db.Query("SELECT job_id FROM scan_queue WHERE attempt_id NOT IN (SELECT attempt_id FROM runtime_runs)")
	if err != nil {
		return storageError()
	}
	var queued []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return storageError()
		}
		queued = append(queued, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, id := range queued {
		if err = b.finishQueued(id, "INTERRUPTED"); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(filepath.Join(b.config.DataDir, "runtime"))
	if err != nil {
		return storageError()
	}
	for _, entry := range entries {
		var known int
		if !entry.IsDir() || b.db.QueryRow("SELECT count(*) FROM runtime_runs WHERE attempt_id=?", entry.Name()).Scan(&known) != nil || known != 1 {
			b.recoveryBlocked = true
		}
	}
	return nil
}
