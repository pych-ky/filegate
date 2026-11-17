package broker

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
)

func (b *Broker) pruneReports(ctx context.Context, jobID string) error {
	rows, err := b.db.QueryContext(ctx, "SELECT attempt_id,directory,state,raw_reserved FROM runtime_runs WHERE job_id=? AND report_reserved>0", jobID)
	if err != nil {
		return storageError()
	}
	type retained struct {
		id, directory, state string
		raw                  int64
	}
	var all []retained
	for rows.Next() {
		var r retained
		if rows.Scan(&r.id, &r.directory, &r.state, &r.raw) != nil {
			rows.Close()
			return storageError()
		}
		all = append(all, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, r := range all {
		if r.raw != 0 || r.state != "FINISHED" || r.directory != filepath.Join(b.config.DataDir, "runtime", r.id) {
			return failure("RECOVERY_REQUIRED", 503)
		}
		if err = b.maintenanceTx(ctx, 0, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "UPDATE runtime_runs SET state='REPORT_PRUNING' WHERE attempt_id=?", r.id)
			return err
		}); err != nil {
			return err
		}
		if err = b.finishReportDeletion(r.id, r.directory); err != nil {
			return err
		}
	}
	return nil
}

func (b *Broker) finishReportDeletion(attempt, directory string) error {
	if directory != filepath.Join(b.config.DataDir, "runtime", attempt) || !identifier(attempt) {
		return failure("RECOVERY_REQUIRED", 503)
	}
	if _, _, err := runtimeCharges(directory); err != nil {
		return failure("CLEANUP_PENDING", 503)
	}
	path := filepath.Join(directory, "output", "report.json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return failure("CLEANUP_PENDING", 503)
	}
	if syncDirectory(filepath.Dir(path)) != nil {
		return failure("CLEANUP_PENDING", 503)
	}
	// 停止・回収証拠と確定済み判定は、詳細レポートの期限削除から分離する。
	if _, err := b.db.Exec("UPDATE runtime_runs SET state='FINISHED',report_reserved=0 WHERE attempt_id=? AND state='REPORT_PRUNING'", attempt); err != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) pruneRuntimes(ctx context.Context, jobID string) error {
	rows, err := b.db.QueryContext(ctx, "SELECT attempt_id,directory,state,raw_reserved FROM runtime_runs WHERE job_id=?", jobID)
	if err != nil {
		return storageError()
	}
	type retained struct {
		id, directory, state string
		raw                  int64
	}
	var all []retained
	for rows.Next() {
		var r retained
		if rows.Scan(&r.id, &r.directory, &r.state, &r.raw) != nil {
			rows.Close()
			return storageError()
		}
		all = append(all, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, r := range all {
		if r.raw != 0 || (r.state != "FINISHED" && r.state != "PRUNING") || r.directory != filepath.Join(b.config.DataDir, "runtime", r.id) {
			return failure("RECOVERY_REQUIRED", 503)
		}
		// A resumed PRUNING intent only finishes; a new one is admitted first.
		if r.state == "FINISHED" {
			if err = b.maintenanceTx(ctx, 0, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, "UPDATE runtime_runs SET state='PRUNING' WHERE attempt_id=?", r.id)
				return err
			}); err != nil {
				return err
			}
		}
		if err = b.finishRuntimeDeletion(r.id, r.directory); err != nil {
			return err
		}
	}
	return nil
}

func (b *Broker) finishRuntimeDeletion(attempt, directory string) error {
	if directory != filepath.Join(b.config.DataDir, "runtime", attempt) || !identifier(attempt) {
		return failure("RECOVERY_REQUIRED", 503)
	}
	if _, _, err := runtimeCharges(directory); err != nil {
		return failure("CLEANUP_PENDING", 503)
	}
	if os.RemoveAll(directory) != nil || syncDirectory(filepath.Dir(directory)) != nil {
		return failure("CLEANUP_PENDING", 503)
	}
	if _, err := b.db.Exec("DELETE FROM runtime_runs WHERE attempt_id=? AND state='PRUNING'", attempt); err != nil {
		return storageError()
	}
	return nil
}

func runtimeCharges(directory string) (int64, int64, error) {
	var report, control int64
	count := 0
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if os.IsNotExist(walkErr) && path == directory {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 4096 {
			return failure("RECOVERY_REQUIRED", 503)
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Mode().Perm()&0077 != 0 || (!entry.IsDir() && !info.Mode().IsRegular()) {
			return failure("RECOVERY_REQUIRED", 503)
		}
		if !entry.IsDir() {
			if path == filepath.Join(directory, "output", "report.json") {
				report += info.Size()
			} else {
				control += info.Size()
			}
			if report > reportLimit || control > controlReservation {
				return failure("RECOVERY_REQUIRED", 503)
			}
		}
		return nil
	})
	return report, control, err
}
