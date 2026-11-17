package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"filegate.local/filegate/internal/acquire"
	"io"
	"os"
	"path/filepath"
	"time"
)

func (b *Broker) Submit(ctx context.Context, request Request, body io.Reader) (Receipt, error) {
	r, fingerprint, err := b.validateRequest(request)
	if err != nil {
		return Receipt{}, err
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return Receipt{}, failure("SERVICE_STOPPING", 503)
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		b.mu.Unlock()
		return Receipt{}, storageError()
	}
	key := hash("intake\x00" + r.IdempotencyKey)
	var oldFingerprint, oldID string
	err = tx.QueryRowContext(ctx, "SELECT fingerprint,job_id FROM intakes WHERE key_hash=?", key).Scan(&oldFingerprint, &oldID)
	if err == nil {
		j, e := readJob(ctx, tx, oldID)
		tx.Rollback()
		b.mu.Unlock()
		if e != nil {
			return Receipt{}, e
		}
		receipt := receiptFor(j, true)
		if fingerprint != oldFingerprint {
			return receipt, &Error{Code: "IDEMPOTENCY_CONFLICT", Status: 409, Receipt: &receipt}
		}
		if j.IntakeStatus == "FAILED" || j.IntakeStatus == "CANCELLED" {
			return receipt, &Error{Code: "INTAKE_TERMINAL_WITHOUT_INPUT", Status: 409, Receipt: &receipt}
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, storageError()
	}
	var tombstone string
	err = tx.QueryRowContext(ctx, "SELECT job_id FROM tombstones WHERE key_hash=?", key).Scan(&tombstone)
	if err == nil {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, failure("KEY_EXPIRED", 409)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, storageError()
	}
	var outstanding int
	var queued int
	var charged int64
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM reservations").Scan(&outstanding) != nil || tx.QueryRowContext(ctx, "SELECT coalesce(sum(size),0) FROM objects WHERE available=1").Scan(&charged) != nil {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, storageError()
	}
	if r.SourceKind != "url" && (len(b.active) > 0 || outstanding > 0) {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, failure("RESOURCE_BUSY", 429)
	}
	if tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM scan_queue)+(SELECT count(*) FROM update_waiters)").Scan(&queued) != nil {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, storageError()
	}
	if queued+outstanding >= 20 {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, failure("RESOURCE_BUSY", 429)
	}
	if charged+int64(outstanding+1)*MaxInputBytes > OriginalBudget {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, failure("QUOTA_EXCEEDED", 507)
	}
	if err = b.admission(tx, MaxInputBytes); err != nil {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, err
	}
	created := time.Now().UTC()
	j := Job{SchemaVersion: "4", JobID: newID("job"), Phase: "ACQUIRING", Verdict: "UNDECIDED", IntakeStatus: "ACQUIRING", ReasonCodes: []string{}, ExecutionErrors: []string{}, CreatedAt: created.Format(time.RFC3339Nano), Coverage: pendingCoverage(), ConfirmedRejections: []RejectionEvidence{}, RuntimeCleanupComplete: true}
	if r.SourceKind == "url" {
		j.Phase = "QUEUED"
		j.IntakeStatus = "RESERVED"
	}
	objectID := newID("object")
	if _, err = tx.ExecContext(ctx, "INSERT INTO jobs(id,created,data) VALUES(?,?,?)", j.JobID, created.UnixNano(), encode(j)); err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO intakes(key_hash,fingerprint,job_id) VALUES(?,?,?)", key, fingerprint, j.JobID)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO reservations(job_id,object_id) VALUES(?,?)", j.JobID, objectID)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO intake_metadata(job_id,data) VALUES(?,?)", j.JobID, encode(metadataFor(r)))
	}
	if err != nil || tx.Commit() != nil {
		tx.Rollback()
		b.mu.Unlock()
		return Receipt{}, storageError()
	}
	if r.SourceKind == "url" {
		b.urlQueue = append(b.urlQueue, urlIntake{request: r, job: j, objectID: objectID})
		b.startNextURLLocked()
		b.mu.Unlock()
		return receiptFor(j, false), nil
	}
	runCtx, stopCause := context.WithCancelCause(ctx)
	run := &ingestRun{cancel: func() { stopCause(context.Canceled) }, stopCause: stopCause, done: make(chan struct{})}
	b.active[j.JobID] = run
	b.mu.Unlock()
	return b.acquireInput(runCtx, r, body, j, objectID, run)
}

func (b *Broker) acquireInput(runCtx context.Context, r Request, body io.Reader, j Job, objectID string, run *ingestRun) (Receipt, error) {
	defer func() {
		run.cancel()
		b.mu.Lock()
		delete(b.active, j.JobID)
		close(run.done)
		b.startNextURLLocked()
		b.mu.Unlock()
	}()
	b.mu.Lock()
	capacityErr := b.inputCapacityLocked()
	b.mu.Unlock()
	if capacityErr != nil {
		return b.failIntake(j.JobID, objectID, capacityErr, false)
	}
	runCtx, stop := context.WithCancelCause(runCtx)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				b.mu.Lock()
				err := b.inputCapacityLocked()
				if err != nil {
					stop(err)
				}
				b.mu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}()
	defer func() {
		stop(nil)
		<-monitorDone
	}()

	var input io.Reader = body
	var closer io.Closer
	var err error
	if r.SourceKind == "local" {
		input, err = b.openLocal(r)
		if err == nil {
			closer = input.(io.Closer)
		}
	} else if r.SourceKind == "url" {
		var download *acquire.Body
		download, err = acquire.Open(runCtx, r.URL)
		if err == nil {
			input, closer = download, download
			if len(download.ContentType) > 256 {
				err = failure("DOWNLOAD_FRAMING_UNSUPPORTED", 400)
			} else {
				metadata := metadataFor(r)
				metadata.DeclaredMediaType = download.ContentType
				b.mu.Lock()
				_, e := b.db.Exec("UPDATE intake_metadata SET data=? WHERE job_id=?", encode(metadata), j.JobID)
				b.mu.Unlock()
				if e != nil {
					err = storageError()
				}
			}
		}
	} else if body == nil {
		err = failure("INVALID_REQUEST", 400)
	} else {
		closer, _ = body.(io.Closer)
	}
	if err != nil {
		if closer != nil {
			closer.Close()
		}
		if cause := intakeContextError(runCtx); cause != nil {
			err = cause
		}
		return b.failIntake(j.JobID, objectID, err, false)
	}
	b.mu.Lock()
	run.closer = closer
	b.mu.Unlock()
	watchDone := make(chan struct{})
	watchExited := make(chan struct{})
	go func() {
		defer close(watchExited)
		select {
		case <-runCtx.Done():
			if closer != nil {
				closer.Close()
			}
		case <-watchDone:
		}
	}()
	defer func() {
		close(watchDone)
		<-watchExited
	}()
	partial := filepath.Join(b.config.DataDir, "partial", objectID)
	out, err := openPrivate(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if closer != nil {
			closer.Close()
		}
		return b.failIntake(j.JobID, objectID, failure("WORKSPACE_IO_ERROR", 503), false)
	}
	sha := sha256.New()
	buffer := make([]byte, 64<<10)
	var size int64
	consumed := false
	fullyReceived := false
	for {
		if err = intakeContextError(runCtx); err != nil {
			break
		}
		n, readErr := input.Read(buffer)
		consumed = true
		if err = intakeContextError(runCtx); err != nil {
			break
		}
		if n > 0 {
			if size+int64(n) > MaxInputBytes {
				err = failure("LIMIT_EXCEEDED", 413)
				break
			}
			if _, err = out.Write(buffer[:n]); err != nil {
				err = failure("WORKSPACE_IO_ERROR", 503)
				break
			}
			sha.Write(buffer[:n])
			size += int64(n)
			b.mu.Lock()
			run.written = size
			b.mu.Unlock()
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				fullyReceived = true
				err = nil
			} else {
				var fixed acquire.Error
				if errors.As(readErr, &fixed) {
					err = failure(fixed.Error(), 400)
				} else {
					err = failure("DOWNLOAD_INCOMPLETE", 400)
				}
			}
			break
		}
		if n == 0 {
			select {
			case <-runCtx.Done():
				err = intakeContextError(runCtx)
			case <-time.After(time.Millisecond):
			}
			if err != nil {
				break
			}
		}
	}
	if closer != nil {
		if e := closer.Close(); err == nil && e != nil {
			err = failure("WORKSPACE_IO_ERROR", 503)
		}
	}
	if cause := intakeContextError(runCtx); cause != nil {
		err = cause
	}
	digest := hex.EncodeToString(sha.Sum(nil))
	if err == nil && r.ExpectedSHA256 != nil && digest != *r.ExpectedSHA256 {
		err = failure("INPUT_HASH_MISMATCH", 409)
	}
	if err == nil {
		err = out.Chmod(0400)
	}
	if err == nil {
		err = syncFile(out)
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		receipt, failureErr := b.failIntake(j.JobID, objectID, err, consumed)
		receipt.CurrentInputChecked = fullyReceived
		var detail *Error
		if errors.As(failureErr, &detail) {
			detail.Receipt = &receipt
		}
		return receipt, failureErr
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	var cancelled int
	if b.db.QueryRow("SELECT cancel_requested FROM reservations WHERE job_id=?", j.JobID).Scan(&cancelled) != nil {
		b.recoveryBlocked = true
		return Receipt{}, storageError()
	}
	if cause := intakeContextError(runCtx); cause != nil {
		return b.failIntakeLocked(j.JobID, objectID, cause, consumed)
	}
	if cancelled != 0 {
		return b.failIntakeLocked(j.JobID, objectID, failure("CANCELLED", 409), consumed)
	}
	if err = b.inputCapacityLocked(); err != nil {
		return b.failIntakeLocked(j.JobID, objectID, err, consumed)
	}
	if _, err = b.db.Exec("UPDATE reservations SET complete_sha=?,complete_size=? WHERE job_id=?", digest, size, j.JobID); err != nil {
		b.recoveryBlocked = true
		return Receipt{}, storageError()
	}
	if err = b.publishObject(objectID, digest, size); err != nil {
		b.recoveryBlocked = true
		return Receipt{}, err
	}
	j, err = b.commitInput(j.JobID, objectID, digest, size)
	if err != nil {
		b.recoveryBlocked = true
		return Receipt{}, err
	}
	receipt := receiptFor(j, false)
	receipt.CurrentInputChecked = true
	receipt.BodyConsumed = true
	return receipt, nil
}

func (b *Broker) inputCapacityLocked() error {
	if err := b.pressureGateLocked(); err != nil {
		return err
	}
	return b.inputStorageCapacityLocked()
}

func (b *Broker) inputStorageCapacityLocked() error {
	pending, err := b.pendingRuntime(b.db)
	inputs, inputErr := b.pendingInputs(b.db)
	if err != nil {
		return err
	}
	if inputErr != nil {
		return inputErr
	}
	return checkFree(b.config.DataDir, inputs+pending)
}

func intakeContextError(ctx context.Context) error {
	cause := context.Cause(ctx)
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return failure("CANCELLED", 409)
	}
	return cause
}

func (b *Broker) failIntake(jobID, objectID string, cause error, consumed bool) (Receipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failIntakeLocked(jobID, objectID, cause, consumed)
}
func (b *Broker) failIntakeLocked(jobID, objectID string, cause error, consumed bool) (Receipt, error) {
	ctx := context.Background()
	j, err := readJob(ctx, b.db, jobID)
	if err != nil {
		b.recoveryBlocked = true
		return Receipt{}, err
	}
	code := "WORKSPACE_IO_ERROR"
	status := 503
	var apiErr *Error
	var downloadErr acquire.Error
	if errors.As(cause, &apiErr) {
		code = apiErr.Code
		status = apiErr.Status
	} else if errors.As(cause, &downloadErr) {
		code = downloadErr.Error()
		status = 400
	}
	wasTerminal := j.IntakeStatus == "FAILED" || j.IntakeStatus == "CANCELLED"
	if !wasTerminal {
		j.Phase = "FAILED"
		j.IntakeStatus = "FAILED"
		if code == "CANCELLED" {
			j.Phase = "CANCELLED"
			j.IntakeStatus = "CANCELLED"
		}
		j.Verdict = "HOLD"
		j.ReasonCodes = []string{code}
		j.ExecutionErrors = []string{code}
		j.FinishedAt = nowText()
		j.Coverage = pendingCoverage()
		j.ConfirmedRejections = []RejectionEvidence{}
		j.RuntimeCleanupComplete = true
	}
	cleaned := true
	for _, dir := range []string{"partial", "objects"} {
		p := filepath.Join(b.config.DataDir, dir, objectID)
		if info, e := os.Lstat(p); e == nil {
			if !info.Mode().IsRegular() {
				cleaned = false
				continue
			}
			if e = os.Remove(p); e != nil {
				cleaned = false
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			cleaned = false
		}
		if syncDirectory(filepath.Join(b.config.DataDir, dir)) != nil {
			cleaned = false
		}
	}
	if !cleaned {
		if !wasTerminal {
			j.ReasonCodes = append(j.ReasonCodes, "CLEANUP_PENDING")
		}
		b.recoveryBlocked = true
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		b.recoveryBlocked = true
		return Receipt{}, storageError()
	}
	defer tx.Rollback()
	if !wasTerminal {
		if err = writeJob(ctx, tx, j); err != nil {
			b.recoveryBlocked = true
			return Receipt{}, storageError()
		}
	}
	if cleaned {
		if _, err = tx.Exec("DELETE FROM reservations WHERE job_id=?", jobID); err != nil {
			b.recoveryBlocked = true
			return Receipt{}, storageError()
		}
	}
	if tx.Commit() != nil {
		b.recoveryBlocked = true
		return Receipt{}, storageError()
	}
	receipt := receiptFor(j, false)
	receipt.BodyConsumed = consumed
	return receipt, &Error{Code: code, Status: status, Receipt: &receipt}
}

func (b *Broker) commitInput(jobID, objectID, digest string, size int64) (Job, error) {
	ctx := context.Background()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, storageError()
	}
	defer tx.Rollback()
	j, err := readJob(ctx, tx, jobID)
	if err != nil {
		return Job{}, err
	}
	j.InputReceipt = &InputReceipt{ObjectID: objectID, SHA256: digest, ByteSize: size, ContentAvailable: true}
	j.IntakeStatus = "COMMITTED"
	j.AttemptID = newID("attempt")
	j.Phase = "FINISHED"
	j.Verdict = "HOLD"
	j.ReasonCodes = []string{"INCOMPLETE_REQUIRED_CHECKS"}
	j.ExecutionErrors = []string{}
	j.FinishedAt = nowText()
	j.Coverage = pendingCoverage()
	j.ConfirmedRejections = []RejectionEvidence{}
	j.RuntimeCleanupComplete = true
	if b.config.VM != nil {
		j.Phase = "QUEUED_FOR_SCAN"
		j.Verdict = "UNDECIDED"
		j.ReasonCodes = []string{}
		j.FinishedAt = ""
		j.RuntimeCleanupComplete = false
	}

	if _, err = tx.Exec("INSERT INTO objects(id,job_id,sha256,size,available) VALUES(?,?,?,?,1)", objectID, jobID, digest, size); err != nil {
		return Job{}, storageError()
	}
	if _, err = tx.Exec("INSERT INTO attempts(id,job_id,data) VALUES(?,?,?)", j.AttemptID, jobID, encode(j)); err != nil {
		return Job{}, storageError()
	}
	if b.config.VM != nil {
		if _, err = tx.Exec("INSERT INTO scan_queue(job_id,attempt_id) VALUES(?,?)", jobID, j.AttemptID); err != nil {
			return Job{}, storageError()
		}
	}
	if err = writeJob(ctx, tx, j); err != nil {
		return Job{}, storageError()
	}
	if _, err = tx.Exec("DELETE FROM reservations WHERE job_id=?", jobID); err != nil {
		return Job{}, storageError()
	}
	if tx.Commit() != nil {
		return Job{}, storageError()
	}
	b.wakeScan()
	return j, nil
}
