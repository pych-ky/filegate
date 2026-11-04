package broker

import (
	"context"
	"time"

	updatecontrol "filegate.local/filegate/internal/update"
)

func (b *Broker) updateRetention(ctx context.Context, cutoff time.Time, resumeOnly bool) (updatecontrol.RetentionResult, error) {
	var result updatecontrol.RetentionResult
	if b.updates == nil || !b.updates.initialized {
		return result, nil
	}
	protected := map[string]bool{}
	queries := []string{
		"SELECT DISTINCT update_id FROM scan_definition_snapshots WHERE active=1",
		"SELECT DISTINCT s.update_id FROM release_authorizations a JOIN releases r ON r.id=a.release_id JOIN scan_definition_snapshots s ON s.attempt_id=a.attempt_id WHERE r.state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED') OR r.finalized_at=0",
	}
	for _, query := range queries {
		rows, err := b.db.QueryContext(ctx, query)
		if err != nil {
			return result, storageError()
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			protected[id] = true
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return result, storageError()
		}
	}
	var missing int
	if b.db.QueryRowContext(ctx, "SELECT count(*) FROM releases r WHERE (r.state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED') OR r.finalized_at=0) AND (NOT EXISTS(SELECT 1 FROM release_authorizations a WHERE a.release_id=r.id) OR EXISTS(SELECT 1 FROM release_authorizations a LEFT JOIN scan_definition_snapshots s ON s.attempt_id=a.attempt_id WHERE a.release_id=r.id AND s.attempt_id IS NULL))").Scan(&missing) != nil {
		return result, storageError()
	}
	if missing != 0 {
		rows, err := b.db.QueryContext(ctx, "SELECT update_id FROM update_adoptions")
		if err != nil {
			return result, storageError()
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			protected[id] = true
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return result, storageError()
		}
	}
	result, err := b.updates.store.Prune(b.config.DataDir, cutoff.Unix(), protected, resumeOnly)
	if err != nil {
		return result, storageError()
	}
	return result, nil
}
