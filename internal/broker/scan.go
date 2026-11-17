package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	updatecontrol "filegate.local/filegate/internal/update"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const rawReservation int64 = 4 << 30
const controlReservation int64 = 64 << 20

type scanRun struct {
	job        Job
	directory  string
	stopped    chan struct{}
	accepted   chan struct{}
	stopOnce   sync.Once
	stopReason string
	definition *updatecontrol.ScanDefinition
	progress   *ScanProgress
}

func (r *scanRun) stop() { r.stopFor("INTERRUPTED") }
func (r *scanRun) stopFor(reason string) {
	r.stopOnce.Do(func() { r.stopReason = reason; close(r.stopped) })
}

func metadataFor(r Request) scanMetadata {
	var m scanMetadata
	if r.SourceKind == "local" {
		m.DisplayName = filepath.Base(r.Source)
	}
	if r.DisplayName != nil {
		m.DisplayName = *r.DisplayName
	}
	if r.DeclaredMediaType != nil {
		m.DeclaredMediaType = *r.DeclaredMediaType
	}
	if r.ExpectedType != nil {
		m.ExpectedType = *r.ExpectedType
	}
	return m
}
func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (b *Broker) configureVM() error {
	if b.config.VM == nil {
		return nil
	}
	vm := *b.config.VM
	canonical, err := filepath.EvalSymlinks(b.config.DataDir)
	if err != nil || canonical != b.config.DataDir {
		return failure("INVALID_VM_CONFIGURATION", 400)
	}
	for _, path := range []string{vm.RunnerPath, vm.Workspace, vm.Proof} {
		if path == "" || !filepath.IsAbs(path) {
			return failure("INVALID_VM_CONFIGURATION", 400)
		}
	}
	resolved, err := filepath.EvalSymlinks(vm.RunnerPath)
	if err != nil || resolved != vm.RunnerPath || vm.RunnerPath != filepath.Join(vm.Workspace, ".build/filegate-vm") {
		return failure("INVALID_VM_CONFIGURATION", 400)
	}
	for _, path := range []string{vm.RunnerPath, vm.Proof} {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() {
			return failure("INVALID_VM_CONFIGURATION", 400)
		}
	}
	info, err := os.Lstat(vm.RunnerPath)
	if err != nil || info.Mode().Perm()&0111 == 0 {
		return failure("INVALID_VM_CONFIGURATION", 400)
	}
	var data, work unix.Stat_t
	if unix.Stat(b.config.DataDir, &data) != nil || unix.Stat(vm.Workspace, &work) != nil || data.Dev != work.Dev || work.Mode&unix.S_IFMT != unix.S_IFDIR {
		return failure("INVALID_VM_CONFIGURATION", 400)
	}
	b.runnerSHA, err = digestFile(vm.RunnerPath)
	if err != nil {
		return failure("INVALID_VM_CONFIGURATION", 400)
	}
	b.proofSHA, err = digestFile(vm.Proof)
	if err != nil {
		return failure("INVALID_VM_CONFIGURATION", 400)
	}
	b.config.VM = &vm
	return nil
}

func (b *Broker) wakeScan() {
	select {
	case b.scanWake <- struct{}{}:
	default:
	}
}
func (b *Broker) scanLoop() {
	defer close(b.scanDone)
	for {
		select {
		case <-b.scanStop:
			return
		case <-b.scanWake:
		}
		for {
			b.mu.Lock()
			if b.closed || b.recoveryBlocked || b.config.VM == nil || b.pressureGateLocked() != nil {
				b.mu.Unlock()
				break
			}
			var id string
			err := b.db.QueryRow("SELECT job_id FROM scan_queue ORDER BY rowid LIMIT 1").Scan(&id)
			if err != nil {
				b.mu.Unlock()
				break
			}
			ready, updateErr := b.prepareUpdateScanLocked(id)
			if updateErr != nil || !ready {
				if updateErr != nil && b.finishQueued(id, errorReason(updateErr)) != nil {
					b.recoveryBlocked = true
				}
				b.mu.Unlock()
				continue
			}
			if b.updates != nil && b.updates.active != nil {
				b.mu.Unlock()
				break
			}
			run, err := b.prepareScan(id)
			if err != nil {
				if !b.recoveryBlocked && b.finishQueued(id, errorReason(err)) != nil {
					b.recoveryBlocked = true
				}
				b.mu.Unlock()
				continue
			}
			b.scanActive = run
			b.mu.Unlock()
			b.executeScan(run)
			b.mu.Lock()
			b.scanActive = nil
			b.mu.Unlock()
		}
	}
}

func errorReason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "SCANNER_ERROR"
}

func (b *Broker) prepareScan(id string) (*scanRun, error) {
	if err := b.pressureGateLocked(); err != nil {
		return nil, err
	}
	ctx := context.Background()
	j, err := readJob(ctx, b.db, id)
	if err != nil {
		return nil, err
	}
	if j.Terminal() || j.InputReceipt == nil || !j.InputReceipt.ContentAvailable {
		return nil, failure("INPUT_MISSING", 409)
	}
	if err = b.verifyObject(filepath.Join(b.config.DataDir, "objects", j.InputReceipt.ObjectID), j.InputReceipt.SHA256, j.InputReceipt.ByteSize); err != nil {
		return nil, failure("INPUT_HASH_MISMATCH", 409)
	}
	var reports int64
	if b.db.QueryRow("SELECT coalesce(sum(report_reserved+control_reserved),0) FROM runtime_runs").Scan(&reports) != nil {
		return nil, storageError()
	}
	if reports+reportLimit+controlReservation > 1<<30 {
		return nil, failure("QUOTA_EXCEEDED", 507)
	}
	pending, err := b.pendingRuntime(b.db)
	if err != nil {
		return nil, err
	}
	pending += rawReservation + reportLimit + controlReservation
	inputs, err := b.pendingInputs(b.db)
	if err != nil {
		return nil, err
	}
	pending += inputs
	if err = checkFree(b.config.DataDir, pending); err != nil {
		return nil, err
	}
	if sha, e := digestFile(b.config.VM.RunnerPath); e != nil || sha != b.runnerSHA {
		return nil, failure("VM_START_FAILED", 503)
	}
	if sha, e := digestFile(b.config.VM.Proof); e != nil || sha != b.proofSHA {
		return nil, failure("VM_START_FAILED", 503)
	}
	definition, err := b.scanDefinition()
	if err != nil {
		return nil, err
	}
	var releaseSnapshot *scanReleaseSnapshot
	if definition != nil {
		releaseSnapshot, err = b.captureScanRelease(j, definition)
		if err != nil {
			return nil, err
		}
	}
	directory := filepath.Join(b.config.DataDir, "runtime", j.AttemptID)
	j.Phase = "PREPARING"
	j.RuntimeCleanupComplete = false
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storageError()
	}
	defer tx.Rollback()
	// The new attempt reuses the stored original, so it charges no new original bytes; its raw, report and control space is checked above,
	// and the shared run-evidence pool again in this transaction.
	if err = b.scanStartAdmission(tx); err != nil {
		return nil, err
	}
	if _, err = tx.Exec("INSERT INTO runtime_runs(attempt_id,job_id,state,directory,raw_reserved,report_reserved,control_reserved) VALUES(?,?,'RESERVED',?,?,?,?)", j.AttemptID, j.JobID, directory, rawReservation, reportLimit, controlReservation); err != nil {
		return nil, storageError()
	}
	if _, err = tx.Exec("INSERT INTO resource_pins(owner_id,object_id) VALUES(?,?)", j.AttemptID, j.InputReceipt.ObjectID); err != nil {
		return nil, storageError()
	}
	if releaseSnapshot != nil {
		if _, err = tx.Exec("INSERT INTO scan_release_snapshots(attempt_id,data) VALUES(?,?)", j.AttemptID, encode(releaseSnapshot)); err != nil {
			return nil, storageError()
		}
	}
	if definition != nil {
		if _, err = tx.Exec("INSERT INTO scan_definition_snapshots(attempt_id,update_id,active,data) VALUES(?,?,1,?)", j.AttemptID, definition.UpdateID, encode(definition)); err != nil {
			return nil, storageError()
		}
	}
	if err = writeJob(ctx, tx, j); err != nil {
		return nil, storageError()
	}
	if _, err = tx.Exec("UPDATE attempts SET data=? WHERE id=?", encode(j), j.AttemptID); err != nil {
		return nil, storageError()
	}
	if tx.Commit() != nil {
		b.recoveryBlocked = true
		return nil, storageError()
	}
	if os.Mkdir(directory, 0700) != nil || syncDirectory(filepath.Dir(directory)) != nil {
		b.recoveryBlocked = true
		return nil, storageError()
	}
	return &scanRun{job: j, directory: directory, stopped: make(chan struct{}), accepted: make(chan struct{}, 1), definition: definition}, nil
}

func (b *Broker) finishQueued(id, reason string) error {
	ctx := context.Background()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	j, err := readJob(ctx, tx, id)
	if err != nil {
		return err
	}
	j.Phase = "FAILED"
	if reason == "CANCELLED" {
		j.Phase = "CANCELLED"
	}
	if len(j.ConfirmedRejections) == 0 {
		j.Verdict = "HOLD"
	}
	j.ExecutionErrors = append(j.ExecutionErrors, reason)
	j.ReasonCodes = append(j.ReasonCodes, reason)
	j.FinishedAt = nowText()
	j.RuntimeCleanupComplete = true
	j.Coverage.AVResult = "inconclusive"
	if writeJob(ctx, tx, j) != nil {
		return storageError()
	}
	if _, err = tx.Exec("UPDATE attempts SET data=? WHERE id=?", encode(j), j.AttemptID); err != nil {
		return storageError()
	}
	if _, err = tx.Exec("DELETE FROM scan_queue WHERE job_id=?", id); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) acceptReport(run *scanRun) (scanReport, string, error) {
	report, digest, err := decodeReport(filepath.Join(run.directory, "output", "report.json"), run.job, run.definitionBinding())
	if err != nil {
		return report, digest, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ctx := context.Background()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return report, digest, storageError()
	}
	defer tx.Rollback()
	j, err := readJob(ctx, tx, run.job.JobID)
	if err != nil || j.AttemptID != run.job.AttemptID || j.Terminal() {
		return report, digest, failure("REPORT_VALIDATION_FAILED", 409)
	}
	j.ScanDetails, err = scanDetailsForReport(ctx, tx, run, report)
	if err != nil {
		return report, digest, err
	}
	j.Coverage.RequiredAVInputCount = report.Result.RequiredAVInputCount
	j.Coverage.ProfileID = report.AV.ProfileID
	j.Coverage.AVProcessStatus = report.AV.ProcessStatus
	j.Coverage.AVResult = report.AV.AVResult
	j.Coverage.AVNormalResultCount = report.avValidation.NormalResultCount
	rejections := append(append([]formatRejection(nil), report.Result.ConfirmedRejections...), report.avValidation.ConfirmedRejections...)
	if len(rejections) != 0 {
		for _, e := range rejections {
			rejection := RejectionEvidence{EvidenceID: newID("evidence"), ObjectID: e.ObjectID, ReasonCode: e.ReasonCode}
			if _, err = tx.Exec("INSERT INTO rejection_evidence(evidence_id,attempt_id,job_id,object_id,input_sha256,report_sha256,reason_code,validated_at) VALUES(?,?,?,?,?,?,?,?)", rejection.EvidenceID, j.AttemptID, j.JobID, e.ObjectID, j.InputReceipt.SHA256, digest, e.ReasonCode, nowText()); err != nil {
				return report, digest, storageError()
			}
			j.ConfirmedRejections = append(j.ConfirmedRejections, rejection)
		}
		j.Verdict = "BLOCK"
		j.ReasonCodes = append([]string(nil), report.Result.Reasons...)
		if len(report.avValidation.ConfirmedRejections) != 0 {
			j.ReasonCodes = append(j.ReasonCodes, "MALWARE_DETECTED")
		}
	}
	if writeJob(ctx, tx, j) != nil {
		return report, digest, storageError()
	}
	if _, err = tx.Exec("UPDATE attempts SET data=? WHERE id=?", encode(j), j.AttemptID); err != nil {
		return report, digest, storageError()
	}
	if _, err = tx.Exec("UPDATE runtime_runs SET report_sha256=? WHERE attempt_id=?", digest, j.AttemptID); err != nil {
		return report, digest, storageError()
	}
	if tx.Commit() != nil {
		return report, digest, storageError()
	}
	return report, digest, nil
}

func (b *Broker) scanPhase(run *scanRun, phase string, allocated int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
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
	if j.AttemptID != run.job.AttemptID || j.Terminal() {
		return failure("REPORT_VALIDATION_FAILED", 409)
	}
	j.Phase = phase
	if writeJob(ctx, tx, j) != nil {
		return storageError()
	}
	if _, err = tx.Exec("UPDATE attempts SET data=? WHERE id=?", encode(j), j.AttemptID); err != nil {
		return storageError()
	}
	if _, err = tx.Exec("UPDATE runtime_runs SET state=?,raw_written=? WHERE attempt_id=?", phase, allocated, j.AttemptID); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func writePrivate(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := openPrivate(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = syncFile(f)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncDirectory(filepath.Dir(path))
}
