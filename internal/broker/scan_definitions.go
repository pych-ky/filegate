package broker

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"

	"filegate.local/filegate/internal/av"
	updatecontrol "filegate.local/filegate/internal/update"
)

func (b *Broker) scanDefinition() (*updatecontrol.ScanDefinition, error) {
	if b.updates == nil || !b.updates.enabled {
		return nil, nil
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return nil, failure("UPDATE_CLOCK_UNCERTAIN", 503)
	}
	definition, err := b.updates.store.ScanDefinition(now)
	if err != nil {
		var updateError updatecontrol.Error
		if errors.As(err, &updateError) {
			return nil, failure(string(updateError), 503)
		}
		return nil, storageError()
	}
	return &definition, nil
}

func (b *Broker) readScanDefinition(attemptID string) (*updatecontrol.ScanDefinition, error) {
	var body []byte
	var updateID string
	err := b.db.QueryRowContext(context.Background(), "SELECT update_id,data FROM scan_definition_snapshots WHERE attempt_id=?", attemptID).Scan(&updateID, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	var definition updatecontrol.ScanDefinition
	if err != nil || strictJSON(body, &definition) != nil || definition.UpdateID != updateID || !identifier(updateID) ||
		!validDigest(definition.ManifestSHA256) || !validDigest(definition.ImageManifestSHA256) || definition.Binding.FixtureDefinitionsOnly ||
		definition.ImagePath != filepath.Join(b.config.DataDir, "definitions", updateID, "definitions.ext4") {
		return nil, storageError()
	}
	return &definition, nil
}

func (r *scanRun) definitionBinding() *av.Binding {
	if r.definition == nil {
		return nil
	}
	return &r.definition.Binding
}

// A time-fresh historical image remains an update cache, not a current scan input.
func (b *Broker) freshScanDefinition(control updatecontrol.Control) (bool, error) {
	if !updatecontrol.Fresh(control, control.Clock) {
		return false, nil
	}
	_, err := b.updates.store.CurrentScanDefinition(control.Clock)
	if errors.Is(err, updatecontrol.Error("REVALIDATION_REQUIRED")) || errors.Is(err, updatecontrol.Error("DEFINITION_CACHE_MISSING")) {
		return false, nil
	}
	if err != nil {
		var updateError updatecontrol.Error
		if errors.As(err, &updateError) {
			return false, failure(string(updateError), 503)
		}
		return false, storageError()
	}
	return true, nil
}
