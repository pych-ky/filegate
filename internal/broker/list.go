package broker

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// MaxClientResponseBytes is the largest complete JSON response, including the encoder's trailing newline, that the
// local CLI and MCP client accept; a job list page is cut to fit it.
const MaxClientResponseBytes = 2 << 20

type listCursor struct {
	Version int    `json:"v"`
	Created int64  `json:"created"`
	JobID   string `json:"job_id"`
	State   string `json:"state,omitempty"`
}

func ValidListState(state string) bool {
	switch state {
	case "all", "active", "PASS", "HOLD", "BLOCK", "stale":
		return true
	}
	return false
}

func matchesListState(job Job, state string) bool {
	switch state {
	case "all":
		return true
	case "active":
		return !job.Terminal()
	case "stale":
		for _, codes := range [][]string{job.ReasonCodes, job.Release.ReasonCodes} {
			for _, code := range codes {
				if code == "RESULT_STALE" || code == "REVALIDATION_REQUIRED" {
					return true
				}
			}
		}
		return false
	}
	return job.Verdict == state
}

func (b *Broker) ListPage(ctx context.Context, cursor string, limit int) (JobPage, error) {
	return b.ListStatePage(ctx, "all", cursor, limit)
}

func (b *Broker) ListStatePage(ctx context.Context, state, cursor string, limit int) (JobPage, error) {
	out := JobPage{SchemaVersion: "4", Jobs: []Job{}}
	if state == "" {
		state = "all"
	}
	if !ValidListState(state) || limit < 1 || limit > 100 {
		return out, failure("INVALID_REQUEST", 400)
	}
	if len(cursor) > 256 {
		return out, failure("INVALID_CURSOR", 400)
	}
	point := listCursor{Version: 2, State: state}
	if cursor != "" {
		point = listCursor{}
		body, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		if err != nil || base64.RawURLEncoding.EncodeToString(body) != cursor || strictJSON(body, &point) != nil || point.Created <= 0 || !strings.HasPrefix(point.JobID, "job_") || len(point.JobID) != 36 {
			return out, failure("INVALID_CURSOR", 400)
		}
		if (point.Version != 1 || point.State != "" || state != "all") && (point.Version != 2 || point.State != state) {
			return out, failure("INVALID_CURSOR", 400)
		}
		decoded, err := hex.DecodeString(point.JobID[4:])
		if err != nil || hex.EncodeToString(decoded) != point.JobID[4:] {
			return out, failure("INVALID_CURSOR", 400)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return out, failure("SERVICE_STOPPING", 503)
	}
	last := listCursor{Version: 2, State: state}
	var cursors []listCursor
	view := newReleaseView()
	batchLimit := 100
	if state == "all" {
		batchLimit = min(limit+1, 100)
	}
	for {
		batch, err := b.listBatch(ctx, point, batchLimit)
		if err != nil {
			return out, err
		}
		if len(batch) == 0 {
			break
		}
		for _, row := range batch {
			point = row.point
			job := row.job
			if state != "stale" && !matchesListState(job, state) {
				continue
			}
			if err = b.projectReleaseEligibility(ctx, &job, view); err != nil {
				return out, err
			}
			if !matchesListState(job, state) {
				continue
			}
			if len(out.Jobs) == limit {
				out.NextCursor = base64.RawURLEncoding.EncodeToString(encode(last))
				break
			}
			out.Jobs = append(out.Jobs, job)
			last.Created, last.JobID = row.point.Created, row.point.JobID
			cursors = append(cursors, last)
		}
		if out.NextCursor != "" {
			break
		}
	}
	// Only this request's decodes are kept (at most displayRequestAttempts), so history never accumulates.
	b.displaySnapshots = view.snapshots
	jobs := make([]*Job, len(out.Jobs))
	for i := range out.Jobs {
		jobs[i] = &out.Jobs[i]
		if err := b.projectDisplayName(ctx, jobs[i]); err != nil {
			return out, err
		}
	}
	if err := b.projectNextAllowedAt(view, jobs...); err != nil {
		return out, err
	}
	return boundListPage(out, cursors)
}

// boundListPage keeps the longest prefix of the projected page whose encoded response, with the encoder's trailing
// newline, fits MaxClientResponseBytes. A cut page continues after its last retained job, so the excluded jobs come on
// the next page; a first job that cannot fit alone is refused rather than skipped, emptied or truncated.
func boundListPage(page JobPage, cursors []listCursor) (JobPage, error) {
	// The empty envelope with the actual cursor, the encoded jobs, their separating commas and the trailing newline.
	size := func(cursor string, jobs, encoded int) int {
		return len(encode(JobPage{SchemaVersion: page.SchemaVersion, Jobs: []Job{}, NextCursor: cursor})) + encoded + max(jobs-1, 0) + 1
	}
	sizes := make([]int, len(page.Jobs))
	total := 0
	for i := range page.Jobs {
		sizes[i] = len(encode(page.Jobs[i]))
		total += sizes[i]
	}
	if size(page.NextCursor, len(sizes), total) <= MaxClientResponseBytes {
		return page, nil
	}
	kept, used, next := 0, 0, ""
	for kept < len(sizes) {
		cursor := base64.RawURLEncoding.EncodeToString(encode(cursors[kept]))
		if size(cursor, kept+1, used+sizes[kept]) > MaxClientResponseBytes {
			break
		}
		used += sizes[kept]
		kept, next = kept+1, cursor
	}
	if kept == 0 {
		return JobPage{SchemaVersion: page.SchemaVersion, Jobs: []Job{}}, failure("LIMIT_EXCEEDED", 409)
	}
	page.Jobs, page.NextCursor = page.Jobs[:kept], next
	return page, nil
}

type listRow struct {
	point listCursor
	job   Job
}

// Close the bounded query before current eligibility reads the same SQLite connection.
func (b *Broker) listBatch(ctx context.Context, point listCursor, limit int) ([]listRow, error) {
	query := "SELECT created,id,data FROM jobs"
	var args []any
	if point.Created != 0 {
		query += " WHERE created<? OR (created=? AND id<?)"
		args = []any{point.Created, point.Created, point.JobID}
	}
	query += " ORDER BY created DESC,id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, storageError()
	}
	defer rows.Close()
	var batch []listRow
	for rows.Next() {
		var body []byte
		var row listRow
		if rows.Scan(&row.point.Created, &row.point.JobID, &body) != nil || json.Unmarshal(body, &row.job) != nil || row.job.JobID != row.point.JobID {
			return nil, storageError()
		}
		row.job.Release.Eligible = false
		if !Stage0Passed && row.job.Verdict == "PASS" {
			return nil, failure("UNADOPTED_SCAN_RESULT", 503)
		}
		batch = append(batch, row)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, storageError()
	}
	return batch, nil
}
