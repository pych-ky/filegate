package broker

import (
	"context"
	updatecontrol "filegate.local/filegate/internal/update"
)

// A false result removes this job from the scan queue before the caller continues.
func (b *Broker) prepareUpdateScanLocked(id string) (bool, error) {
	if b.updates == nil || !b.updates.enabled {
		return true, nil
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return false, failure(err.Error(), 503)
	}
	control, err := b.updates.store.Read(now)
	if err != nil {
		return false, failure(err.Error(), 503)
	}
	fresh, err := b.freshScanDefinition(control)
	if err != nil {
		return false, err
	}
	if b.updates.active != nil {
		return false, b.parkUpdateJobLocked(id, b.updates.active.id)
	}
	if fresh && control.ActiveUpdateID == "" {
		return true, nil
	}
	if control.ActiveUpdateID != "" && (fresh || control.State == "IN_FLIGHT") {
		return false, b.parkUpdateJobLocked(id, control.ActiveUpdateID)
	}
	if control.State == "READY" && control.ActiveUpdateID == "" {
		updateID, err := b.startUpdateLocked(now)
		if err == nil {
			return false, b.parkUpdateJobLocked(id, updateID)
		}
		return false, b.settleUpdateJobLocked(id, "", control.LastUpdateID, false, errorReason(err))
	}
	reason := "DEFINITION_UPDATE"
	switch control.State {
	case "COOLDOWN":
		reason = "UPDATE_COOLDOWN"
	case "UNKNOWN":
		reason = "UPDATE_STATE_UNKNOWN"
	}
	if control.Reason != "" {
		reason = control.Reason
	}
	return false, b.settleUpdateJobLocked(id, "", control.LastUpdateID, false, reason)
}

func (b *Broker) parkUpdateJobLocked(id, updateID string) error {
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
	if j.Terminal() {
		return failure("STALE_ATTEMPT", 409)
	}
	j.Phase, j.WaitReason, j.UpdateID = "QUEUED_FOR_SCAN", "DEFINITION_UPDATE", updateID
	if _, err = tx.Exec("INSERT INTO update_waiters(attempt_id,job_id,update_id) VALUES(?,?,?)", j.AttemptID, id, updateID); err != nil {
		return storageError()
	}
	if _, err = tx.Exec("INSERT INTO resource_pins(owner_id,object_id) VALUES(?,?)", j.AttemptID, j.InputReceipt.ObjectID); err != nil {
		return storageError()
	}
	if _, err = tx.Exec("DELETE FROM scan_queue WHERE job_id=? AND attempt_id=?", id, j.AttemptID); err != nil {
		return storageError()
	}
	if writeJob(ctx, tx, j) != nil {
		return storageError()
	}
	if _, err = tx.Exec("UPDATE attempts SET data=? WHERE id=?", encode(j), j.AttemptID); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) settleUpdateJobLocked(id, attemptID, updateID string, fresh bool, reason string) error {
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
	if attemptID == "" {
		attemptID = j.AttemptID
	}
	if !j.Terminal() && j.AttemptID == attemptID {
		j.UpdateID = updateID
		j.WaitReason = ""
		if fresh {
			j.Phase, j.RuntimeCleanupComplete = "QUEUED_FOR_SCAN", false
			if _, err = tx.Exec("INSERT OR IGNORE INTO scan_queue(job_id,attempt_id) VALUES(?,?)", id, attemptID); err != nil {
				return storageError()
			}
		} else {
			j.Phase, j.FinishedAt, j.RuntimeCleanupComplete = "FAILED", nowText(), true
			if len(j.ConfirmedRejections) == 0 {
				j.Verdict = "HOLD"
			}
			if reason == "CANCELLED" {
				j.Phase = "CANCELLED"
				j.ExecutionErrors = append(j.ExecutionErrors, reason)
				j.ReasonCodes = append(j.ReasonCodes, reason)
			} else {
				j.ExecutionErrors = append(j.ExecutionErrors, "DATABASE_STALE", reason)
				j.ReasonCodes = append(j.ReasonCodes, "DATABASE_STALE", reason)
			}
			j.Coverage.AVResult = "inconclusive"
			if _, err = tx.Exec("DELETE FROM scan_queue WHERE job_id=? AND attempt_id=?", id, attemptID); err != nil {
				return storageError()
			}
		}
		if writeJob(ctx, tx, j) != nil {
			return storageError()
		}
		if _, err = tx.Exec("UPDATE attempts SET data=? WHERE id=?", encode(j), attemptID); err != nil {
			return storageError()
		}
	}
	if _, err = tx.Exec("DELETE FROM resource_pins WHERE owner_id=?", attemptID); err != nil {
		return storageError()
	}
	if _, err = tx.Exec("DELETE FROM update_waiters WHERE attempt_id=?", attemptID); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) resolveUpdateWaitersLocked(control updatecontrol.Control, now updatecontrol.Clock) error {
	rows, err := b.db.Query("SELECT job_id,attempt_id,update_id FROM update_waiters ORDER BY rowid")
	if err != nil {
		return storageError()
	}
	type waiter struct{ job, attempt, update string }
	var waiters []waiter
	for rows.Next() {
		var w waiter
		if rows.Scan(&w.job, &w.attempt, &w.update) != nil {
			rows.Close()
			return storageError()
		}
		waiters = append(waiters, w)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	fresh, err := b.freshScanDefinition(control)
	if err != nil {
		return err
	}
	if fresh && control.ActiveUpdateID != "" {
		return nil
	}
	reason := control.Reason
	if control.LastUpdateID != "" && control.ActiveUpdateID == "" {
		attempt, err := b.updates.store.Attempt(control.LastUpdateID)
		if err != nil {
			return storageError()
		}
		if attempt.Reason != "" {
			reason = attempt.Reason
		}
	}
	if reason == "" {
		if control.State == "COOLDOWN" {
			reason = "UPDATE_COOLDOWN"
		} else {
			reason = "DEFINITION_UPDATE"
		}
	}
	for _, w := range waiters {
		if err := b.settleUpdateJobLocked(w.job, w.attempt, w.update, fresh, reason); err != nil {
			return err
		}
	}
	b.wakeScan()
	return nil
}
