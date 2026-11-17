package update

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
)

type normalRuntimeRequest struct {
	runtimeRequest
	DefinitionCache *ScanDefinition `json:"definition_cache"`
}

// The attempt owns this immutable input reference until stop and cleanup settle.
func snapshotDefinitionCache(tx *sql.Tx, id string, control Control) error {
	var cache *ScanDefinition
	if control.Definition != nil {
		cache = &ScanDefinition{}
		if err := readScanDefinition(tx, control.Definition, cache, control.Clock.Boot); err != nil {
			if !errors.Is(err, Error("DEFINITION_CACHE_MISSING")) {
				return err
			}
			cache = nil
		}
	} else {
		var adopted int
		if err := tx.QueryRow("SELECT count(*) FROM update_adoptions").Scan(&adopted); err != nil {
			return err
		}
		if adopted != 0 {
			return Invalid
		}
	}
	_, err := tx.Exec("INSERT INTO update_definition_caches(update_id,data,data_sha256) VALUES(?,?,?)", id, encoded(cache), sha256Text(encoded(cache)))
	return err
}

func loadDefinitionCache(q interface {
	QueryRow(string, ...any) *sql.Row
}, id string) (*ScanDefinition, error) {
	var body []byte
	var digest string
	if err := q.QueryRow("SELECT data,data_sha256 FROM update_definition_caches WHERE update_id=?", id).Scan(&body, &digest); err != nil {
		return nil, err
	}
	var cache *ScanDefinition
	if len(body) > 16384 || sha256Text(body) != digest {
		return nil, Invalid
	}
	if bytes.Equal(body, []byte("null")) {
		return nil, nil
	}
	if decodeStored(body, &cache) != nil || !bytes.Equal(body, encoded(cache)) {
		return nil, Invalid
	}
	if cache != nil && (!identifier.MatchString(cache.UpdateID) || cache.Generation <= 0 || !cache.Confirmed.Valid() ||
		!digestPattern.MatchString(cache.ManifestSHA256) || !digestPattern.MatchString(cache.ImageManifestSHA256) ||
		cache.Image.Name != "definitions.ext4" || cache.Image.Bytes != DefinitionImageBytes ||
		!digestPattern.MatchString(cache.Image.SHA256) || cache.Profile.FixtureDefinitionsOnly || cache.Binding.FixtureDefinitionsOnly) {
		return nil, Invalid
	}
	return cache, nil
}

func currentDefinitionCache(cache *ScanDefinition, directory string, attempt Attempt) error {
	if cache == nil {
		return nil
	}
	path := filepath.Join(filepath.Dir(filepath.Dir(directory)), "definitions", cache.UpdateID, "definitions.ext4")
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path || cache.ImagePath != path || cache.Generation > attempt.BaseGeneration {
		return Invalid
	}
	return candidateIdentity(context.Background(), path, cache.Image)
}

func (s *Store) validateDefinitionCacheRequest(body []byte, request normalRuntimeRequest) error {
	cache, cacheErr := loadDefinitionCache(s.db, request.AttemptID)
	var fields map[string]json.RawMessage
	if runtimeJSON(body, &fields) != nil {
		return Invalid
	}
	_, hasCache := fields["definition_cache"]
	if request.Schema == 1 {
		if !errors.Is(cacheErr, sql.ErrNoRows) || hasCache {
			return Invalid
		}
	} else if request.Schema != 2 || !hasCache || cacheErr != nil || !bytes.Equal(encoded(cache), encoded(request.DefinitionCache)) {
		return Invalid
	}
	return nil
}

func pinDefinitionCaches(tx *sql.Tx, all []retainedUpdate, pins map[string]bool) error {
	for _, runtime := range all {
		cache, err := loadDefinitionCache(tx, runtime.attempt.ID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		attempt := runtime.attempt
		if cache != nil && (attempt.State != "FINISHED" || !attempt.StopConfirmed || !attempt.CleanupConfirmed ||
			attempt.ReservedBytes != 0 || runtime.state != "FINISHED") {
			pins[cache.UpdateID] = true
		}
	}
	return nil
}
