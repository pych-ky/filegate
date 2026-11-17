package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

func (b *Broker) verifyObject(path, digest string, size int64) error {
	f, err := openPrivate(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() != size || size < 0 || size > MaxInputBytes {
		return failure("INPUT_HASH_MISMATCH", 409)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxInputBytes+1))
	if err != nil || n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return failure("INPUT_HASH_MISMATCH", 409)
	}
	return nil
}
func (b *Broker) publishObject(objectID, digest string, size int64) error {
	tmp := filepath.Join(b.config.DataDir, "partial", objectID)
	final := filepath.Join(b.config.DataDir, "objects", objectID)
	_, err := os.Lstat(final)
	if errors.Is(err, os.ErrNotExist) {
		if err = b.verifyObject(tmp, digest, size); err != nil {
			return failure("RECOVERY_REQUIRED", 503)
		}
		if err = os.Link(tmp, final); err != nil {
			return failure("RECOVERY_REQUIRED", 503)
		}
	} else if err != nil {
		return failure("RECOVERY_REQUIRED", 503)
	}
	if err = b.verifyObject(final, digest, size); err != nil {
		return failure("RECOVERY_REQUIRED", 503)
	}
	if err = syncDirectory(filepath.Dir(final)); err != nil {
		return storageError()
	}
	if _, err = os.Lstat(tmp); err == nil {
		if err = b.verifyObject(tmp, digest, size); err != nil {
			return failure("RECOVERY_REQUIRED", 503)
		}
		if err = os.Remove(tmp); err != nil {
			return failure("CLEANUP_PENDING", 503)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return storageError()
	}
	if syncDirectory(filepath.Dir(tmp)) != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) recover() error {
	rows, err := b.db.Query("SELECT job_id,object_id,complete_sha,complete_size,cancel_requested FROM reservations")
	if err != nil {
		return storageError()
	}
	type reserved struct {
		job, object, digest string
		size                int64
		cancelled           int
	}
	var unfinished []reserved
	for rows.Next() {
		var r reserved
		if rows.Scan(&r.job, &r.object, &r.digest, &r.size, &r.cancelled) != nil {
			rows.Close()
			return storageError()
		}
		unfinished = append(unfinished, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, r := range unfinished {
		j, err := readJob(context.Background(), b.db, r.job)
		if err != nil {
			return err
		}
		terminal := j.IntakeStatus == "FAILED" || j.IntakeStatus == "CANCELLED"
		if !terminal && r.digest != "" && r.cancelled == 0 {
			if err = b.publishObject(r.object, r.digest, r.size); err != nil {
				b.recoveryBlocked = true
				continue
			}
			if _, err = b.commitInput(r.job, r.object, r.digest, r.size); err != nil {
				return err
			}
		} else {
			code := "INTERRUPTED"
			if r.cancelled != 0 {
				code = "CANCELLED"
			}
			_, err = b.failIntakeLocked(r.job, r.object, failure(code, 409), false)
			var expected *Error
			if !errors.As(err, &expected) || expected.Receipt == nil {
				return storageError()
			}
		}
	}
	rows, err = b.db.Query("SELECT object_id,job_id FROM object_deletions")
	if err != nil {
		return storageError()
	}
	type deletion struct{ object, job string }
	var deletions []deletion
	for rows.Next() {
		var d deletion
		if rows.Scan(&d.object, &d.job) != nil {
			rows.Close()
			return storageError()
		}
		deletions = append(deletions, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, d := range deletions {
		if _, err = b.finishDeletion(context.Background(), d.job, d.object); err != nil {
			b.recoveryBlocked = true
		}
	}
	partials := make(map[string]bool)
	objects := make(map[string]bool)
	rows, err = b.db.Query("SELECT object_id FROM reservations")
	if err != nil {
		return storageError()
	}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return storageError()
		}
		partials[id] = true
		objects[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	type stored struct {
		id, job string
		size    int64
	}
	var originals []stored
	rows, err = b.db.Query("SELECT id,job_id,size FROM objects WHERE available=1")
	if err != nil {
		return storageError()
	}
	for rows.Next() {
		var o stored
		if rows.Scan(&o.id, &o.job, &o.size) != nil {
			rows.Close()
			return storageError()
		}
		originals = append(originals, o)
		objects[o.id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, o := range originals {
		info, e := os.Lstat(filepath.Join(b.config.DataDir, "objects", o.id))
		code := ""
		if errors.Is(e, os.ErrNotExist) {
			code = "INPUT_MISSING"
		} else if e != nil || !info.Mode().IsRegular() || info.Size() != o.size {
			code = "RECOVERY_REQUIRED"
		}
		if code != "" {
			b.recoveryBlocked = true
			j, e := readJob(context.Background(), b.db, o.job)
			if e != nil {
				return e
			}
			if j.InputReceipt != nil {
				j.InputReceipt.ContentAvailable = false
			}
			found := false
			for _, reason := range j.ReasonCodes {
				if reason == code {
					found = true
				}
			}
			if !found {
				j.ReasonCodes = append(j.ReasonCodes, code)
			}
			if _, e = b.db.Exec("UPDATE jobs SET data=? WHERE id=?", encode(j), o.job); e != nil {
				return storageError()
			}
		}
	}
	for dir, known := range map[string]map[string]bool{"partial": partials, "objects": objects} {
		entries, err := os.ReadDir(filepath.Join(b.config.DataDir, dir))
		if err != nil {
			return storageError()
		}
		for _, entry := range entries {
			if !known[entry.Name()] || entry.Type()&os.ModeType != 0 {
				b.recoveryBlocked = true
			}
		}
	}
	return nil
}

func (b *Broker) Cancel(ctx context.Context, id string) (Job, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return Job{}, failure("SERVICE_STOPPING", 503)
	}
	j, err := readJob(ctx, b.db, id)
	if err != nil {
		b.mu.Unlock()
		return Job{}, err
	}
	if j.Terminal() {
		b.mu.Unlock()
		return j, nil
	}
	for index, queued := range b.urlQueue {
		if queued.job.JobID == id {
			b.urlQueue = append(b.urlQueue[:index], b.urlQueue[index+1:]...)
			receipt, cancelErr := b.failIntakeLocked(id, queued.objectID, failure("CANCELLED", 409), false)
			b.mu.Unlock()
			if receipt.JobID == id {
				return receipt.Job, nil
			}
			return Job{}, cancelErr
		}
	}
	if j.Phase == "WAITING_FOR_UPDATE" || j.Phase == "QUEUED_FOR_SCAN" && j.WaitReason == "DEFINITION_UPDATE" {
		err = b.settleUpdateJobLocked(id, j.AttemptID, j.UpdateID, false, "CANCELLED")
		if err == nil {
			j, err = readJob(ctx, b.db, id)
		}
		b.mu.Unlock()
		return j, err
	}
	if j.IntakeStatus == "COMMITTED" {
		if run := b.scanActive; run != nil && run.job.JobID == id {
			if _, err = b.db.ExecContext(ctx, "UPDATE runtime_runs SET cancel_requested=1 WHERE attempt_id=?", j.AttemptID); err != nil {
				b.mu.Unlock()
				return Job{}, storageError()
			}
			run.stop()
		} else {
			if err = b.finishQueued(id, "CANCELLED"); err == nil {
				j, err = readJob(ctx, b.db, id)
			}
		}
		b.mu.Unlock()
		return j, err
	}
	if _, err = b.db.ExecContext(ctx, "UPDATE reservations SET cancel_requested=1 WHERE job_id=?", id); err != nil {
		b.mu.Unlock()
		return Job{}, storageError()
	}
	var closer io.Closer
	if run := b.active[id]; run != nil {
		run.cancel()
		closer = run.closer
	}
	b.mu.Unlock()
	if closer != nil {
		closer.Close()
	}
	return j, nil
}

func (b *Broker) Rescan(ctx context.Context, id string) (Job, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Job{}, failure("SERVICE_STOPPING", 503)
	}
	if b.recoveryBlocked {
		return Job{}, failure("RECOVERY_REQUIRED", 503)
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, storageError()
	}
	defer tx.Rollback()
	j, err := readJob(ctx, tx, id)
	if err != nil {
		return Job{}, err
	}
	if !j.Terminal() {
		return Job{}, failure("RESOURCE_BUSY", 429)
	}
	if j.InputReceipt == nil || !j.InputReceipt.ContentAvailable {
		return Job{}, failure("INPUT_MISSING", 409)
	}
	if err = b.verifyObject(filepath.Join(b.config.DataDir, "objects", j.InputReceipt.ObjectID), j.InputReceipt.SHA256, j.InputReceipt.ByteSize); err != nil {
		return Job{}, failure("INPUT_HASH_MISMATCH", 409)
	}
	if b.config.VM != nil {
		var queued int
		if tx.QueryRow("SELECT (SELECT count(*) FROM scan_queue)+(SELECT count(*) FROM update_waiters)").Scan(&queued) != nil {
			return Job{}, storageError()
		}
		var acquiring int
		if tx.QueryRow("SELECT count(*) FROM reservations").Scan(&acquiring) != nil {
			return Job{}, storageError()
		}
		if queued+acquiring >= 20 {
			return Job{}, failure("RESOURCE_BUSY", 429)
		}
	}
	// A rescan reuses the stored original, so it charges no new original bytes but passes the same management checks.
	if err = b.admission(tx, 0); err != nil {
		return Job{}, err
	}
	j.AttemptID = newID("attempt")
	j.UpdateID, j.WaitReason = "", ""
	j.Phase = "FINISHED"
	j.Verdict = "HOLD"
	j.ReasonCodes = []string{"INCOMPLETE_REQUIRED_CHECKS"}
	j.ExecutionErrors = []string{}
	j.FinishedAt = nowText()
	j.Release.Eligible = false
	j.Coverage = pendingCoverage()
	j.ScanDetails = nil
	j.ConfirmedRejections = []RejectionEvidence{}
	j.RuntimeCleanupComplete = true
	if b.config.VM != nil {
		j.Phase = "QUEUED_FOR_SCAN"
		j.Verdict = "UNDECIDED"
		j.ReasonCodes = []string{}
		j.FinishedAt = ""
		j.RuntimeCleanupComplete = false
		if _, err = tx.Exec("INSERT INTO scan_queue(job_id,attempt_id) VALUES(?,?)", id, j.AttemptID); err != nil {
			return Job{}, storageError()
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO attempts(id,job_id,data) VALUES(?,?,?)", j.AttemptID, id, encode(j)); err != nil {
		return Job{}, storageError()
	}
	if writeJob(ctx, tx, j) != nil || tx.Commit() != nil {
		return Job{}, storageError()
	}
	b.wakeScan()
	return j, nil
}

func (b *Broker) Prune(ctx context.Context) (PruneResult, error) {
	return b.prune(ctx, false)
}

func (b *Broker) prune(ctx context.Context, scheduled bool) (PruneResult, error) {
	out, ids, cutoff, err := b.pruneStart(ctx, scheduled)
	if err != nil {
		return out, err
	}
	for _, id := range ids {
		err = b.pruneJob(ctx, id, cutoff, scheduled, &out)
		// A transient-page refusal skips only this job; a WAL or SHM refusal would refuse every later unit too.
		if errors.Is(err, errMaintenanceTransient) {
			out.Deferred = true
			continue
		}
		if errors.Is(err, errMaintenanceBudget) {
			out.Deferred = true
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func (b *Broker) pruneStart(ctx context.Context, scheduled bool) (PruneResult, []string, time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := PruneResult{SchemaVersion: "4"}
	if err := b.pruneAllowedLocked(scheduled); err != nil {
		return out, nil, time.Time{}, err
	}
	now := time.Now()
	// Retention uses elapsed process time so a wall-clock jump cannot expire objects.
	cutoff := b.openedAt.Add(now.Sub(b.openedAt)).UTC()
	// A WAL or SHM refusal of release or update-retention units ends this pass with a deferred, normal result.
	if err := b.pruneReleases(ctx, cutoff); errors.Is(err, errMaintenanceBudget) {
		out.Deferred = true
		return out, nil, cutoff, nil
	} else if err != nil {
		return out, nil, time.Time{}, err
	}
	updates, err := b.updateRetention(ctx, cutoff, false)
	out.DefinitionsRemoved, out.UpdateRuntimesRemoved, out.UpdateHistoriesRemoved, out.UpdateCleanupPending = updates.DefinitionsRemoved, updates.RuntimesRemoved, updates.HistoriesRemoved, updates.Pending
	if errors.Is(err, errMaintenanceBudget) {
		out.Deferred = true
		return out, nil, cutoff, nil
	}
	if err != nil {
		return out, nil, time.Time{}, err
	}
	rows, err := b.db.QueryContext(ctx, "SELECT id FROM jobs WHERE created<? ORDER BY created", cutoff.Add(-7*24*time.Hour).UnixNano())
	if err != nil {
		return out, nil, time.Time{}, storageError()
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return out, nil, time.Time{}, storageError()
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, nil, time.Time{}, storageError()
	}
	return out, ids, cutoff, nil
}

// pruneJob re-reads the job, its references and its retention on every call. Past the 30-day retention its old attempts
// and evidence go first in admitted units, so the original-deletion copy can reuse the freed pages.
func (b *Broker) pruneJob(ctx context.Context, id string, cutoff time.Time, scheduled bool, out *PruneResult) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.pruneAllowedLocked(scheduled); err != nil {
		return err
	}
	j, err := readJob(ctx, b.db, id)
	var missing *Error
	if errors.As(err, &missing) && missing.Code == "NOT_FOUND" {
		return nil
	}
	if err != nil {
		return err
	}
	if !j.Terminal() {
		return nil
	}
	var references int
	if b.db.QueryRowContext(ctx, "SELECT count(*) FROM reservations WHERE job_id=?", id).Scan(&references) != nil {
		return storageError()
	}
	if references > 0 {
		return nil
	}
	if j.InputReceipt != nil {
		if b.db.QueryRowContext(ctx, "SELECT count(*) FROM resource_pins WHERE object_id=?", j.InputReceipt.ObjectID).Scan(&references) != nil {
			return storageError()
		}
		if references > 0 {
			return nil
		}
	}
	expired, err := b.jobRetentionExpired(ctx, j, cutoff)
	if err != nil {
		return err
	}
	if !expired {
		if proceed, err := b.pruneOriginalLocked(ctx, &j, out, false); err != nil || !proceed {
			return err
		}
		if err = b.pruneReports(ctx, id); err != nil {
			if !maintenanceDeferred(err) {
				b.recoveryBlocked = true
			}
			return err
		}
		return nil
	}
	if j.InputReceipt != nil && j.InputReceipt.ContentAvailable {
		if _, err = b.originalDeletionJob(ctx, id); err != nil {
			var reason *Error
			if errors.As(err, &reason) && reason.Code == "RESOURCE_BUSY" {
				return nil
			}
			return err
		}
	}
	for _, step := range []func(context.Context, string) error{b.pruneReports, b.pruneRuntimes} {
		if err = step(ctx, id); err != nil {
			if !maintenanceDeferred(err) {
				b.recoveryBlocked = true
			}
			return err
		}
	}
	if err = b.pruneHistory(ctx, j); err != nil {
		return err
	}
	if proceed, err := b.pruneOriginalLocked(ctx, &j, out, true); err != nil || !proceed {
		return err
	}
	err = b.maintenanceTx(ctx, 0, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO tombstones(key_hash,job_id,state) SELECT key_hash,job_id,? FROM intakes WHERE job_id=?", j.Phase, id); err != nil {
			return err
		}
		for _, query := range []string{"DELETE FROM rejection_evidence WHERE job_id=?", "DELETE FROM intake_metadata WHERE job_id=?", "DELETE FROM attempts WHERE job_id=?", "DELETE FROM objects WHERE job_id=?", "DELETE FROM intakes WHERE job_id=?", "DELETE FROM jobs WHERE id=?"} {
			if _, err := tx.ExecContext(ctx, query, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	out.JobsRemoved++
	return nil
}

// jobRetentionExpired applies the 30-day job, attempt and evidence retention from the later of FinishedAt and the newest
// runtime finalization; a job that any release references is kept.
func (b *Broker) jobRetentionExpired(ctx context.Context, j Job, cutoff time.Time) (bool, error) {
	finished, err := time.Parse(time.RFC3339Nano, j.FinishedAt)
	if err != nil {
		return false, nil
	}
	var resolved int64
	if b.db.QueryRowContext(ctx, "SELECT coalesce(max(resolved_at),0) FROM runtime_finalizations JOIN runtime_runs USING(attempt_id) WHERE job_id=?", j.JobID).Scan(&resolved) != nil {
		return false, storageError()
	}
	if resolved > finished.UnixNano() {
		finished = time.Unix(0, resolved)
	}
	if !finished.Before(cutoff.Add(-30 * 24 * time.Hour)) {
		return false, nil
	}
	var references int
	if b.db.QueryRowContext(ctx, "SELECT count(*) FROM releases WHERE job_id=?", j.JobID).Scan(&references) != nil {
		return false, storageError()
	}
	return references == 0, nil
}

// pruneOriginalLocked deletes a still available original: busy references skip the job (false), a new intent is admitted
// in its own transaction, and an already durable intent always completes.
func (b *Broker) pruneOriginalLocked(ctx context.Context, j *Job, out *PruneResult, expired bool) (bool, error) {
	if j.InputReceipt == nil || !j.InputReceipt.ContentAvailable {
		return true, nil
	}
	current, err := b.originalDeletionJob(ctx, j.JobID)
	if err != nil {
		var reason *Error
		if errors.As(err, &reason) && reason.Code == "RESOURCE_BUSY" {
			return false, nil
		}
		return false, err
	}
	if err = b.beginOriginalDeletion(ctx, current, expired); err != nil {
		return false, err
	}
	*j, err = b.finishDeletion(ctx, j.JobID, j.InputReceipt.ObjectID)
	if err != nil {
		b.recoveryBlocked = true
		return false, err
	}
	out.ObjectsRemoved++
	return true, nil
}

// pruneHistory deletes the non-current attempts of an expired job one per unit (their scan snapshots cascade), then its
// rejection evidence 200 rows per unit; neither is read outside pruning, and the job row and key stay until the tombstone.
func (b *Broker) pruneHistory(ctx context.Context, j Job) error {
	rows, err := b.db.QueryContext(ctx, "SELECT id FROM attempts WHERE job_id=? AND id<>?", j.JobID, j.AttemptID)
	if err != nil {
		return storageError()
	}
	var old []string
	for rows.Next() {
		var attempt string
		if rows.Scan(&attempt) != nil {
			rows.Close()
			return storageError()
		}
		old = append(old, attempt)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, attempt := range old {
		if err = b.maintenanceTx(ctx, 0, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "DELETE FROM attempts WHERE id=? AND job_id=?", attempt, j.JobID)
			return err
		}); err != nil {
			return err
		}
	}
	for removed := int64(200); removed == 200; {
		if err = b.maintenanceTx(ctx, 0, func(tx *sql.Tx) error {
			result, err := tx.ExecContext(ctx, "DELETE FROM rejection_evidence WHERE rowid IN (SELECT rowid FROM rejection_evidence WHERE job_id=? LIMIT 200)", j.JobID)
			if err == nil {
				removed, err = result.RowsAffected()
			}
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

func (b *Broker) finishDeletion(ctx context.Context, jobID, objectID string) (Job, error) {
	return b.finishOriginalDeletion(ctx, jobID, objectID)
}
