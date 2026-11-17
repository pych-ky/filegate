package broker

import (
	"context"
	"database/sql"
	"errors"
	updatecontrol "filegate.local/filegate/internal/update"
	"os"
)

type UpdateConfig struct{ LibrarySHA256 string }

type updateCoordinator struct {
	store       *updatecontrol.Store
	enabled     bool
	initialized bool
	runtime     *updatecontrol.Runtime
	active      *updateRun
}

type UpdateStatus struct {
	ControlState           string `json:"control_state"`
	ActiveUpdateID         string `json:"active_update_id,omitempty"`
	LastUpdateID           string `json:"last_update_id,omitempty"`
	NextAllowedUTC         *int64 `json:"next_allowed_utc,omitempty"`
	DefinitionFresh        bool   `json:"definition_fresh"`
	NetworkUpdateAvailable bool   `json:"network_update_available"`
	Reason                 string `json:"reason,omitempty"`
}

func (b *Broker) configureUpdates() error {
	store, err := updatecontrol.OpenHostClock(b.db)
	if err != nil {
		return storageError()
	}
	b.updates = &updateCoordinator{store: store, enabled: b.config.Update != nil}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return failure(err.Error(), 503)
	}
	control, err := store.Read(now)
	if errors.Is(err, sql.ErrNoRows) {
		if b.config.Update == nil {
			return nil
		}
		control, err = store.Initialize(updatecontrol.Binding{LibrarySHA256: b.config.Update.LibrarySHA256}, now)
	}
	if err != nil {
		return failure(err.Error(), 503)
	}
	if control.Binding.FixtureOnly || b.config.Update != nil && control.Binding.LibrarySHA256 != b.config.Update.LibrarySHA256 {
		return failure("INVALID_UPDATE_CONFIGURATION", 503)
	}
	b.updates.initialized = true
	if b.updates.enabled {
		runtime, err := updatecontrol.RegisteredRuntime(b.config.DataDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return failure("INVALID_UPDATE_CONFIGURATION", 503)
		}
		if runtime != nil && runtime.LibrarySHA256() != control.Binding.LibrarySHA256 {
			return failure("INVALID_UPDATE_CONFIGURATION", 503)
		}
		b.updates.runtime = runtime
	}
	return nil
}

func (b *Broker) recoverUpdates() error {
	if b.updates == nil || !b.updates.initialized {
		return nil
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return failure(err.Error(), 503)
	}
	control, err := b.updates.store.Recover(now)
	if err != nil {
		return failure(err.Error(), 503)
	}
	rows, err := b.db.Query("SELECT update_id FROM update_runtime WHERE state!='FINISHED' ORDER BY rowid")
	if err != nil {
		return storageError()
	}
	var pending []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return storageError()
		}
		pending = append(pending, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, id := range pending {
		result, _ := b.updates.store.RecoverRuntime(b.updates.runtime, id)
		if !result.StopConfirmed {
			b.recoveryBlocked = true
		}
	}
	now, err = updatecontrol.ReadClock()
	if err != nil {
		return failure(err.Error(), 503)
	}
	control, err = b.updates.store.Read(now)
	if err != nil {
		return failure(err.Error(), 503)
	}
	if control.ActiveUpdateID != "" {
		b.recoveryBlocked = true
	}
	return b.resolveUpdateWaitersLocked(control, now)
}

func (b *Broker) pendingUpdates(q queryer) (int64, error) {
	if b.updates == nil {
		return 0, nil
	}
	var pending int64
	if q.QueryRowContext(context.Background(), "SELECT coalesce(sum(reserved_bytes),0) FROM update_attempts").Scan(&pending) != nil {
		return 0, storageError()
	}
	return pending, nil
}

func (b *Broker) UpdateState() (UpdateStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.updateStateLocked(nil)
}

func (b *Broker) updateStateLocked(view *releaseView) (UpdateStatus, error) {
	status := UpdateStatus{ControlState: "UNINITIALIZED"}
	if b.updates == nil || !b.updates.initialized {
		return status, nil
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return status, failure(err.Error(), 503)
	}
	// Status display is optional, so its control writes stay within the management database start budget.
	admit := func(tx *sql.Tx) error { return b.databaseBudget(tx) }
	var control updatecontrol.Control
	var definition updatecontrol.ScanDefinitionState
	if view == nil {
		control, err = b.updates.store.ReadAdmitted(now, admit)
	} else {
		definition, err = view.readDefinition(b, now, admit)
		control = definition.Control
	}
	if err != nil {
		var denied *Error
		if errors.As(err, &denied) {
			return status, err
		}
		return status, failure(err.Error(), 503)
	}
	status.ControlState, status.ActiveUpdateID, status.LastUpdateID = control.State, control.ActiveUpdateID, control.LastUpdateID
	if view == nil {
		status.DefinitionFresh, err = b.freshScanDefinition(control, admit)
	} else if updatecontrol.Fresh(control, control.Clock) {
		status.DefinitionFresh, err = currentDefinitionAvailable(definition.DefinitionError)
	}
	if err != nil {
		return status, err
	}
	status.Reason = control.Reason
	status.NetworkUpdateAvailable = b.updates.enabled && b.updates.runtime != nil
	if control.State != "UNKNOWN" {
		nextAllowed := max(control.NextAllowedUTC, control.Clock.UTC+control.RemainingSeconds)
		status.NextAllowedUTC = &nextAllowed
	}
	return status, nil
}

func (b *Broker) closeUpdates() error {
	if b.updates == nil || !b.updates.initialized {
		return nil
	}
	if err := b.stopUpdateRun(); err != nil {
		return err
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return failure(err.Error(), 503)
	}
	control, err := b.updates.store.Read(now)
	if err != nil {
		return failure(err.Error(), 503)
	}
	if control.ActiveUpdateID == "" {
		return nil
	}
	if _, err := b.updates.store.Stop(control.ActiveUpdateID, "INTERRUPTED", now); err != nil {
		return failure(err.Error(), 503)
	}
	return failure("VM_STOP_FAILED", 503)
}
