package broker

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func (b *Broker) pruneAllowedLocked(scheduled bool) error {
	if b.closed {
		return failure("SERVICE_STOPPING", 503)
	}
	if len(b.active) > 0 || b.scanActive != nil || b.releaseActive != nil || (b.updates != nil && b.updates.active != nil) || b.recoveryBlocked {
		return failure("RESOURCE_BUSY", 429)
	}
	if scheduled {
		return b.pressureGateLocked()
	}
	return nil
}

func (b *Broker) retentionLoop() {
	defer close(b.retentionDone)
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	// A WAL length above the admission threshold refuses users, so it is reclaimed every minute between hourly prunes.
	walTicker := time.NewTicker(time.Minute)
	defer walTicker.Stop()
	for {
		select {
		case <-b.scanStop:
			return
		case <-walTicker.C:
			if b.idleCheckpoint() != nil {
				b.mu.Lock()
				if b.closed {
					b.mu.Unlock()
					return
				}
				b.recoveryBlocked = true
				b.mu.Unlock()
			}
			continue
		case <-timer.C:
		}
		out, err := b.prune(context.Background(), true)
		delay := time.Hour
		if err == nil && out.Deferred {
			delay = time.Minute
		}
		if err != nil {
			b.mu.Lock()
			if b.closed {
				b.mu.Unlock()
				return
			}
			var reason *Error
			if errors.As(err, &reason) && (reason.Code == "RESOURCE_BUSY" || reason.Code == "HOST_RESOURCE_PRESSURE" || reason.Code == "RESOURCE_MONITOR_FAILED") {
				delay = time.Minute
			} else {
				b.recoveryBlocked = true
			}
			b.mu.Unlock()
		}
		timer.Reset(delay)
	}
}

// A new optional maintenance unit refused by the database budget; both carry the public MAINTENANCE_DEFERRED code.
// errMaintenanceBudget (WAL or SHM over the start threshold) stops a prune pass, errMaintenanceTransient skips one job.
var (
	errMaintenanceBudget    = &Error{Code: "MAINTENANCE_DEFERRED", Status: 507}
	errMaintenanceTransient = &Error{Code: "MAINTENANCE_DEFERRED", Status: 507}
)

func maintenanceDeferred(err error) bool {
	return errors.Is(err, errMaintenanceBudget) || errors.Is(err, errMaintenanceTransient)
}

// maintenanceUnitAdmit admits one new optional maintenance unit in the transaction that writes it; it reads only tx and
// file sizes, and a temporary row copy must fit under the start threshold or in the current freelist.
func (b *Broker) maintenanceUnitAdmit(tx *sql.Tx, transientPages int64) error {
	for name, max := range map[string]int64{"state.sqlite-wal": 28 << 20, "state.sqlite-shm": 1 << 20} {
		info, err := os.Lstat(filepath.Join(b.config.DataDir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return storageError()
		}
		if info.Size() > max {
			return errMaintenanceBudget
		}
	}
	if transientPages <= 0 {
		return nil
	}
	var pages, free, size, limit int64
	ctx := context.Background()
	if tx.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || tx.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free) != nil ||
		tx.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size) != nil || tx.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&limit) != nil ||
		size != 4096 || limit != 32768 || pages < 1 || free < 0 || free > pages {
		return storageError()
	}
	if (pages-free+transientPages)*size > limit*size-(16<<20) && free < transientPages {
		return errMaintenanceTransient
	}
	return nil
}

// quiescentCopyAdmit lets a fully expired prune use the remaining page headroom for one original-deletion copy when no
// already-owed writer or deletion intent exists (b.mu is held and tx is the writing transaction), so no owed tail needs it.
func (b *Broker) quiescentCopyAdmit(tx *sql.Tx, transientPages int64) error {
	if b.recoveryBlocked || len(b.active) > 0 || len(b.urlQueue) > 0 || b.scanActive != nil || b.releaseActive != nil || b.updates != nil && b.updates.active != nil {
		return errMaintenanceTransient
	}
	var owed, pages, free int64
	ctx := context.Background()
	if tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM reservations)+(SELECT count(*) FROM scan_queue)+(SELECT count(*) FROM update_waiters)+(SELECT count(*) FROM release_reservations)"+
		"+(SELECT count(*) FROM runtime_runs WHERE state!='FINISHED')+(SELECT count(*) FROM update_runtime WHERE state!='FINISHED')+(SELECT count(*) FROM object_deletions)"+
		"+(SELECT count(*) FROM update_retention WHERE pending IS NOT NULL)").Scan(&owed) != nil ||
		tx.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || tx.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free) != nil {
		return storageError()
	}
	if owed != 0 || transientPages > free+32768-pages {
		return errMaintenanceTransient
	}
	return nil
}

// maintenanceTx writes one new optional maintenance unit after admitting it in the same immediate transaction.
func (b *Broker) maintenanceTx(ctx context.Context, transientPages int64, write func(*sql.Tx) error) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	if err = b.maintenanceUnitAdmit(tx, transientPages); err != nil {
		return err
	}
	if write(tx) != nil || tx.Commit() != nil {
		return storageError()
	}
	return nil
}

// rewritePages is the temporary page need of rewriting a stored row of n bytes: the new overflow chain (4,092 bytes per
// page, 64 for the record header, key and integers) exists before the old one is freed, plus two splits and a spare page.
func rewritePages(n int) int64 { return int64(n+64+4091)/4092 + 3 }

// idleCheckpoint truncates a WAL longer than the admission threshold while the prune gate excludes every product writer,
// so a high-water mark left by earlier work stops refusing admission without a restart.
func (b *Broker) idleCheckpoint() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	info, err := os.Lstat(filepath.Join(b.config.DataDir, "state.sqlite-wal"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return storageError()
	}
	if info.Size() <= 28<<20 || b.pruneAllowedLocked(true) != nil {
		return nil
	}
	ctx := context.Background()
	conn, err := b.db.Conn(ctx)
	if err != nil {
		return storageError()
	}
	defer conn.Close()
	// A reader pinning the WAL makes TRUNCATE wait for the busy timeout; this pass reports busy at once instead of holding b.mu.
	var busy, logFrames, checkpointed, timeout int64
	_, err = conn.ExecContext(ctx, "PRAGMA busy_timeout=0")
	if err == nil {
		err = conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed)
	}
	_, restoreErr := conn.ExecContext(ctx, "PRAGMA busy_timeout=5000")
	if restoreErr == nil {
		restoreErr = conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout)
	}
	if restoreErr != nil || timeout != 5000 {
		conn.Raw(func(any) error { return driver.ErrBadConn })
		return storageError()
	}
	if err != nil {
		return storageError()
	}
	return nil
}
