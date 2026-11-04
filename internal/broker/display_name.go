package broker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"unicode"
)

func (b *Broker) projectDisplayName(ctx context.Context, job *Job) error {
	job.DisplayName = ""
	if !b.config.ShareNames {
		return nil
	}
	var body []byte
	err := b.db.QueryRowContext(ctx, "SELECT data FROM intake_metadata WHERE job_id=?", job.JobID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	var metadata scanMetadata
	if err != nil || len(body) > 16<<10 || json.Unmarshal(body, &metadata) != nil || len(metadata.DisplayName) > 2048 {
		return storageError()
	}
	if metadata.DisplayName != "" {
		job.DisplayName = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, filepath.Base(metadata.DisplayName))
	}
	return nil
}
