package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type JobReleasePage struct {
	SchemaVersion string           `json:"schema_version"`
	Releases      []ReleaseReceipt `json:"releases"`
	NextCursor    string           `json:"next_cursor,omitempty"`
}

type releaseHistoryCursor struct {
	Version   int    `json:"v"`
	JobID     string `json:"job_id"`
	ReleaseID string `json:"release_id"`
}

func releaseHistoryID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+32 {
		return false
	}
	decoded, err := hex.DecodeString(id[len(prefix):])
	return err == nil && hex.EncodeToString(decoded) == id[len(prefix):]
}

func (b *Broker) JobReleases(ctx context.Context, jobID, cursor string, limit int) (JobReleasePage, error) {
	out := JobReleasePage{SchemaVersion: "4", Releases: []ReleaseReceipt{}}
	if !releaseHistoryID(jobID, "job_") || limit < 1 || limit > 100 {
		return out, failure("INVALID_REQUEST", 400)
	}
	if len(cursor) > 256 {
		return out, failure("INVALID_CURSOR", 400)
	}
	query := "SELECT id FROM releases WHERE job_id=?"
	args := []any{jobID}
	if cursor != "" {
		body, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		var point releaseHistoryCursor
		if err != nil || strictJSON(body, &point) != nil || point.Version != 1 || point.JobID != jobID ||
			!releaseHistoryID(point.ReleaseID, "release_") || !bytes.Equal(body, encode(point)) ||
			base64.RawURLEncoding.EncodeToString(body) != cursor {
			return out, failure("INVALID_CURSOR", 400)
		}
		query += " AND id<?"
		args = append(args, point.ReleaseID)
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit+1)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return out, failure("SERVICE_STOPPING", 503)
	}
	if _, err := readJob(ctx, b.db, jobID); err != nil {
		return out, err
	}
	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return out, storageError()
	}
	defer rows.Close()
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !releaseHistoryID(id, "release_") {
			return out, storageError()
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return out, storageError()
	}
	if len(ids) > limit {
		ids = ids[:limit]
		out.NextCursor = base64.RawURLEncoding.EncodeToString(encode(releaseHistoryCursor{Version: 1, JobID: jobID, ReleaseID: ids[len(ids)-1]}))
	}
	for _, id := range ids {
		r, err := readRelease(ctx, b.db, id)
		if err != nil {
			return out, err
		}
		if r.Receipt.JobID != jobID {
			return out, storageError()
		}
		// 履歴は保存した公開事実を返し、現在の出力ファイルを再照合しない。
		out.Releases = append(out.Releases, r.Receipt)
	}
	return out, nil
}
