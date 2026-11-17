package broker

import (
	"context"
	"errors"
	updatecontrol "filegate.local/filegate/internal/update"
	"os"
	"path/filepath"
	"time"
)

type updateRun struct {
	id     string
	cancel context.CancelCauseFunc
	done   chan struct{}
}

func (b *Broker) startUpdateLocked(now updatecontrol.Clock) (string, error) {
	u := b.updates
	if u.runtime == nil {
		return "", failure("DEFINITION_UPDATE", 503)
	}
	if u.active != nil {
		return u.active.id, nil
	}
	if b.scanActive != nil || b.closed || b.recoveryBlocked {
		return "", failure("RESOURCE_BUSY", 503)
	}
	if err := b.pressureGateLocked(); err != nil {
		return "", err
	}
	pending, err := b.pendingRuntime(b.db)
	if err != nil {
		return "", err
	}
	inputs, err := b.pendingInputs(b.db)
	if err != nil {
		return "", err
	}
	if err = checkFree(b.config.DataDir, pending+inputs+updatecontrol.WorkspaceReservation); err != nil {
		return "", err
	}
	root := filepath.Join(b.config.DataDir, "updates")
	if err = os.MkdirAll(root, 0700); err != nil {
		return "", storageError()
	}
	id := newID("update")
	_, attempt, err := u.store.BeginRuntime(u.runtime, filepath.Join(root, id), id, now, b.updateStartAdmission)
	if err != nil {
		var updateError updatecontrol.Error
		if errors.As(err, &updateError) {
			return "", failure(string(updateError), 503)
		}
		var brokerError *Error
		if errors.As(err, &brokerError) {
			return "", err
		}
		return "", storageError()
	}
	if attempt.ID != id {
		return attempt.ID, nil
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	run := &updateRun{id: id, cancel: cancel, done: make(chan struct{})}
	u.active = run
	go b.executeUpdate(ctx, run)
	return id, nil
}

func (b *Broker) executeUpdate(ctx context.Context, run *updateRun) {
	defer close(run.done)
	defer run.cancel(nil)
	u := b.updates
	capacity := func(written int64) error {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed {
			return updatecontrol.Error("INTERRUPTED")
		}
		if err := b.pressureGateLocked(); err != nil {
			return updatecontrol.Error(errorReason(err))
		}
		pending, err := b.pendingRuntime(b.db)
		if err != nil || pending < written {
			return updatecontrol.Error("RESOURCE_MONITOR_FAILED")
		}
		inputs, err := b.pendingInputs(b.db)
		if err != nil {
			return updatecontrol.Error("RESOURCE_MONITOR_FAILED")
		}
		if err = checkFree(b.config.DataDir, inputs+pending-written); err != nil {
			return updatecontrol.Error(errorReason(err))
		}
		return nil
	}
	result, executionErr := u.store.ExecuteRuntime(ctx, u.runtime, run.id, capacity)
	if !result.StopConfirmed {
		if now, err := updatecontrol.ReadClock(); err == nil {
			_, _ = u.store.Stop(run.id, "INTERRUPTED", now)
		}
		result, _ = u.store.RecoverRuntime(u.runtime, run.id)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if result.StopConfirmed && !result.CleanupConfirmed && executionErr == nil {
		if b.closed {
			executionErr = updatecontrol.Error("INTERRUPTED")
		} else if ctx.Err() != nil {
			executionErr = context.Cause(ctx)
		} else if err := b.pressureGateLocked(); err != nil {
			executionErr = err
		}
	}
	if result.StopConfirmed && !result.CleanupConfirmed && executionErr == nil {
		_, executionErr = u.store.AdoptRuntime(ctx, u.runtime, run.id)
		if executionErr == nil {
			result.CleanupConfirmed = true
		}
	}
	if result.StopConfirmed && !result.CleanupConfirmed && executionErr != nil {
		_ = u.store.AbortRuntime(u.runtime, run.id, updateFailureReason(executionErr))
		cleaned, cleanupErr := u.store.RecoverRuntime(u.runtime, run.id)
		if cleanupErr == nil {
			result = cleaned
		}
	}
	u.active = nil
	if !result.StopConfirmed {
		b.recoveryBlocked = true
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		b.recoveryBlocked = true
		return
	}
	control, err := u.store.Read(now)
	if err != nil {
		b.recoveryBlocked = true
		return
	}
	if executionErr != nil && control.Reason == "" {
		control.Reason = updateFailureReason(executionErr)
	}
	if b.resolveUpdateWaitersLocked(control, now) != nil {
		b.recoveryBlocked = true
	}
	b.wakeScan()
}

func (b *Broker) stopUpdateRun() error {
	b.mu.Lock()
	run := b.updates.active
	if run != nil {
		run.cancel(updatecontrol.Error("INTERRUPTED"))
	}
	b.mu.Unlock()
	if run != nil {
		select {
		case <-run.done:
		case <-time.After(40 * time.Second):
			return failure("VM_STOP_FAILED", 503)
		}
	}
	return nil
}

func updateFailureReason(err error) string {
	var updateErr updatecontrol.Error
	if errors.As(err, &updateErr) {
		return string(updateErr)
	}
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return "WORKSPACE_IO_ERROR"
}
