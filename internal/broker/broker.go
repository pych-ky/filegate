package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"filegate.local/filegate/internal/acquire"
	updatecontrol "filegate.local/filegate/internal/update"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// stateDriver configures every physical connection to the management database and reads the settings back before use.
// database/sql discards a connection whose transaction context is cancelled (the driver has no session reset), so settings
// applied once through the pool would be lost on the replacement connection.
const stateDriver = "sqlite3-filegate-state"

const statePragmas = "PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA max_page_count=32768; PRAGMA journal_size_limit=67108864; PRAGMA wal_autocheckpoint=256;"

func init() { sql.Register(stateDriver, &sqlite3.SQLiteDriver{ConnectHook: configureStateConnection}) }

func configureStateConnection(c *sqlite3.SQLiteConn) error {
	if _, err := c.Exec(statePragmas, nil); err != nil {
		return err
	}
	for pragma, want := range map[string]driver.Value{"journal_mode": "wal", "synchronous": int64(2), "foreign_keys": int64(1), "busy_timeout": int64(5000), "fullfsync": int64(1), "checkpoint_fullfsync": int64(1), "max_page_count": int64(32768), "journal_size_limit": int64(67108864), "wal_autocheckpoint": int64(256), "page_size": int64(4096)} {
		rows, err := c.Query("PRAGMA "+pragma, nil)
		if err != nil {
			return err
		}
		got := make([]driver.Value, 1)
		err = rows.Next(got)
		rows.Close()
		if text, ok := got[0].([]byte); ok {
			got[0] = string(text)
		}
		if err != nil || got[0] != want {
			return errors.New("STATE_CONNECTION_SETTINGS_INVALID")
		}
	}
	return nil
}

type ingestRun struct {
	written   int64
	cancel    context.CancelFunc
	stopCause context.CancelCauseFunc
	closer    io.Closer
	done      chan struct{}
}

type Broker struct {
	urlQueue        []urlIntake
	mu              sync.Mutex
	db              *sql.DB
	config          Config
	lock            *os.File
	active          map[string]*ingestRun
	closed          bool
	recoveryBlocked bool
	openedAt        time.Time
	scanWake        chan struct{}
	scanStop        chan struct{}
	scanDone        chan struct{}
	scanActive      *scanRun
	runnerSHA       string
	proofSHA        string
	releaseActive   *releaseRun
	updates         *updateCoordinator
	pressure        *hostPressure
	retentionDone   chan struct{}
	qemuDisplay     qemuDisplayVerified // guarded by mu; list and detail only
	// Guarded by mu; the latest list request's decoded snapshots only (at most a 100-job page), replaced by the next list request.
	displaySnapshots map[string]displaySnapshot
}

const schema = `
CREATE TABLE IF NOT EXISTS config (name TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created INTEGER NOT NULL, finished INTEGER NOT NULL DEFAULT 0, data BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS jobs_created_id ON jobs(created DESC,id DESC);
CREATE TABLE IF NOT EXISTS intakes (key_hash TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id));
CREATE TABLE IF NOT EXISTS objects (id TEXT PRIMARY KEY, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id), sha256 TEXT NOT NULL, size INTEGER NOT NULL, available INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reservations (job_id TEXT PRIMARY KEY REFERENCES jobs(id), object_id TEXT NOT NULL UNIQUE, complete_sha TEXT NOT NULL DEFAULT '', complete_size INTEGER NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS tombstones (key_hash TEXT PRIMARY KEY, job_id TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS object_deletions (object_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id));
CREATE TABLE IF NOT EXISTS object_deletion_bindings (object_id TEXT PRIMARY KEY REFERENCES object_deletions(object_id) ON DELETE CASCADE, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS resource_pins (owner_id TEXT NOT NULL, object_id TEXT NOT NULL, PRIMARY KEY(owner_id,object_id));
CREATE TABLE IF NOT EXISTS intake_metadata (job_id TEXT PRIMARY KEY REFERENCES jobs(id), data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scan_queue (job_id TEXT PRIMARY KEY REFERENCES jobs(id), attempt_id TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS runtime_runs (attempt_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), state TEXT NOT NULL, directory TEXT NOT NULL, raw_reserved INTEGER NOT NULL, raw_written INTEGER NOT NULL DEFAULT 0, report_reserved INTEGER NOT NULL, control_reserved INTEGER NOT NULL, report_sha256 TEXT NOT NULL DEFAULT '', cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS runtime_finalizations (attempt_id TEXT PRIMARY KEY REFERENCES runtime_runs(attempt_id) ON DELETE CASCADE, resolved_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scan_release_snapshots (attempt_id TEXT PRIMARY KEY REFERENCES attempts(id) ON DELETE CASCADE, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scan_definition_snapshots (attempt_id TEXT PRIMARY KEY REFERENCES attempts(id) ON DELETE CASCADE, update_id TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS rejection_evidence (evidence_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, job_id TEXT NOT NULL REFERENCES jobs(id), object_id TEXT NOT NULL, input_sha256 TEXT NOT NULL, report_sha256 TEXT NOT NULL, reason_code TEXT NOT NULL, validated_at TEXT NOT NULL);
`

func randomID() string {
	var p [16]byte
	if _, err := rand.Read(p[:]); err != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(p[:])
}

func Open(c Config) (*Broker, error) {
	if c.DataDir == "" || !filepath.IsAbs(c.DataDir) {
		return nil, failure("INVALID_CONFIGURATION", 400)
	}
	c.DataDir = filepath.Clean(c.DataDir)
	roots := make(map[string]string, len(c.InputRoots))
	for id, p := range c.InputRoots {
		if !identifier(id) || !filepath.IsAbs(p) {
			return nil, failure("INVALID_CONFIGURATION", 400)
		}
		roots[id] = filepath.Clean(p)
	}
	c.InputRoots = roots
	if err := privateDirectory(c.DataDir); err != nil {
		return nil, err
	}
	for _, name := range []string{"objects", "partial", "runtime"} {
		if err := privateDirectory(filepath.Join(c.DataDir, name)); err != nil {
			return nil, err
		}
	}
	lock, err := openPrivate(filepath.Join(c.DataDir, "broker.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, storageError()
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, failure("RESOURCE_BUSY", 429)
	}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	if err := updatecontrol.CheckRuntimeTransition(c.DataDir); err != nil {
		return nil, failure("UPDATE_RUNTIME_TRANSITION_PENDING", 503)
	}
	for _, name := range []string{"state.sqlite", "state.sqlite-wal", "state.sqlite-shm", "state.sqlite-journal"} {
		p := filepath.Join(c.DataDir, name)
		if info, e := os.Lstat(p); e == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return nil, failure("INVALID_STORE_PERMISSIONS", 503)
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, storageError()
		}
	}
	f, err := openPrivate(filepath.Join(c.DataDir, "state.sqlite"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, storageError()
	}
	if err = f.Close(); err != nil {
		return nil, storageError()
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(c.DataDir, "state.sqlite")}
	q := u.Query()
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "FULL")
	q.Set("_foreign_keys", "on")
	q.Set("_busy_timeout", "5000")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open(stateDriver, u.String())
	if err != nil {
		return nil, storageError()
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	if _, err = db.Exec(schema + releaseSchema); err != nil {
		return nil, storageError()
	}
	for pragma, want := range map[string]int{"synchronous": 2, "foreign_keys": 1, "fullfsync": 1, "max_page_count": 32768, "page_size": 4096} {
		var got int
		if db.QueryRow("PRAGMA "+pragma).Scan(&got) != nil || got != want {
			return nil, storageError()
		}
	}
	var mode string
	if db.QueryRow("PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
		return nil, storageError()
	}
	rootJSON, _ := json.Marshal(roots)
	var saved []byte
	err = db.QueryRow("SELECT value FROM config WHERE name='input_roots'").Scan(&saved)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = db.Exec("INSERT INTO config(name,value) VALUES('input_roots',?)", rootJSON)
	} else if err == nil && string(saved) != string(rootJSON) {
		return nil, failure("INPUT_ROOT_CONFIGURATION_CHANGED", 409)
	}
	if err != nil {
		return nil, storageError()
	}
	b := &Broker{db: db, config: c, lock: lock, active: make(map[string]*ingestRun), openedAt: time.Now(), scanWake: make(chan struct{}, 1), scanStop: make(chan struct{}), scanDone: make(chan struct{}), retentionDone: make(chan struct{})}
	defer func() {
		if !ok && b.pressure != nil {
			b.pressure.monitor.Close()
		}
	}()
	if err = b.configurePressure(); err != nil {
		return nil, err
	}
	if err = b.configureVM(); err != nil {
		return nil, err
	}
	if err = b.configureUpdates(); err != nil {
		return nil, err
	}
	if err = b.recover(); err != nil {
		return nil, err
	}
	if err = b.recoverScans(); err != nil {
		return nil, err
	}
	if err = b.recoverUpdates(); err != nil {
		return nil, err
	}
	if err = b.configureReleaseDestinations(); err != nil {
		return nil, err
	}
	if err = b.recoverReleases(); err != nil {
		return nil, err
	}
	if _, err = b.updateRetention(context.Background(), time.Now(), true); err != nil {
		return nil, err
	}
	// 旧版に回収解決時刻がない実行は、今回の確認時刻から履歴を保持する。
	if _, err = db.Exec("INSERT OR IGNORE INTO runtime_finalizations(attempt_id,resolved_at) SELECT attempt_id,? FROM runtime_runs WHERE state='FINISHED' AND raw_reserved=0 AND raw_written=0", time.Now().UnixNano()); err != nil {
		return nil, storageError()
	}
	if err = syncDirectory(c.DataDir); err != nil {
		return nil, storageError()
	}
	ok = true
	go b.pressureLoop()
	go b.scanLoop()
	go b.retentionLoop()
	b.wakeScan()
	return b, nil
}

func (b *Broker) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	release := b.releaseActive
	if release != nil {
		release.cancel()
	}
	for _, queued := range b.urlQueue {
		receipt, _ := b.failIntakeLocked(queued.job.JobID, queued.objectID, failure("INTERRUPTED", 409), false)
		if receipt.JobID == "" {
			b.recoveryBlocked = true
		}
	}
	b.urlQueue = nil
	close(b.scanStop)
	if b.scanActive != nil {
		b.scanActive.stop()
	}
	runs := make([]*ingestRun, 0, len(b.active))
	for _, run := range b.active {
		run.cancel()
		runs = append(runs, run)
	}
	b.mu.Unlock()
	defer b.closePressure()
	<-b.retentionDone
	if release != nil {
		select {
		case <-release.done:
		case <-time.After(10 * time.Second):
			return failure("RELEASE_STOP_FAILED", 503)
		}
	}
	for _, run := range runs {
		b.mu.Lock()
		closer := run.closer
		b.mu.Unlock()
		if closer != nil {
			closer.Close()
		}
		<-run.done
	}
	select {
	case <-b.scanDone:
	case <-time.After(40 * time.Second):
		return failure("VM_STOP_FAILED", 503)
	}
	updateErr := b.closeUpdates()
	b.mu.Lock()
	defer b.mu.Unlock()
	var pending int
	stopFailed := b.db.QueryRow("SELECT count(*) FROM runtime_runs WHERE state NOT IN ('FINISHED','PRUNING','REPORT_PRUNING')").Scan(&pending) != nil || pending != 0
	err := b.db.Close()
	lockErr := b.lock.Close()
	if err != nil || lockErr != nil {
		return storageError()
	}
	if updateErr != nil {
		return updateErr
	}
	if stopFailed {
		return failure("VM_STOP_FAILED", 503)
	}
	return nil
}

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func encode(v any) []byte  { p, _ := json.Marshal(v); return p }
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func nowText() string      { return time.Now().UTC().Format(time.RFC3339Nano) }

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readJob(ctx context.Context, q queryer, id string) (Job, error) {
	var body []byte
	if err := q.QueryRowContext(ctx, "SELECT data FROM jobs WHERE id=?", id).Scan(&body); errors.Is(err, sql.ErrNoRows) {
		return Job{}, failure("NOT_FOUND", 404)
	} else if err != nil {
		return Job{}, storageError()
	}
	var j Job
	if json.Unmarshal(body, &j) != nil {
		return Job{}, storageError()
	}
	j.Release.Eligible = false
	if !Stage0Passed && j.Verdict == "PASS" {
		return Job{}, failure("UNADOPTED_SCAN_RESULT", 503)
	}
	return j, nil
}
func writeJob(ctx context.Context, tx *sql.Tx, j Job) error {
	finished := int64(0)
	if j.FinishedAt != "" {
		t, e := time.Parse(time.RFC3339Nano, j.FinishedAt)
		if e != nil {
			return storageError()
		}
		finished = t.UnixNano()
	}
	_, err := tx.ExecContext(ctx, "UPDATE jobs SET data=?,finished=? WHERE id=?", encode(j), finished, j.JobID)
	return err
}

func (b *Broker) Get(ctx context.Context, id string) (Job, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Job{}, failure("SERVICE_STOPPING", 503)
	}
	j, err := readJob(ctx, b.db, id)
	view := newReleaseView()
	if err == nil {
		err = b.projectReleaseEligibility(ctx, &j, view)
	}
	if err == nil {
		err = b.projectNextAllowedAt(view, &j)
	}
	if err == nil {
		err = b.projectDisplayName(ctx, &j)
	}
	return j, err
}
func (b *Broker) List(ctx context.Context) ([]Job, error) {
	page, err := b.ListPage(ctx, "", 100)
	return page.Jobs, err
}

// admission checks pressure, recovery, the management database files and free space; newOriginalBytes is the
// original storage the caller is about to write (an intake reserves MaxInputBytes, a rescan reuses its stored original).
func (b *Broker) admission(q queryer, newOriginalBytes int64) error {
	if err := b.pressureGateLocked(); err != nil {
		return err
	}
	if b.recoveryBlocked {
		return failure("RECOVERY_REQUIRED", 503)
	}
	if err := b.databaseBudget(q); err != nil {
		return err
	}
	pending, err := b.pendingRuntime(q)
	if err != nil {
		return err
	}
	inputs, err := b.pendingInputs(q)
	if err != nil {
		return err
	}
	return checkFree(b.config.DataDir, newOriginalBytes+inputs+pending)
}

// databaseBudget checks the management database files and allocated pages against the start budget. It reads only q and
// file sizes, so an optional control write can be refused inside its own transaction.
func (b *Broker) databaseBudget(q queryer) error {
	for name, max := range map[string]int64{"state.sqlite": 112 << 20, "state.sqlite-wal": 28 << 20, "state.sqlite-shm": 1 << 20} {
		info, err := os.Lstat(filepath.Join(b.config.DataDir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return storageError()
		}
		if info.Size() > max {
			return failure("QUOTA_EXCEEDED", 507)
		}
	}
	// A separate reader can keep committed pages in the WAL while the main file stays short, so the allocated pages seen by
	// this transaction (page_count without reusable freelist pages) must also leave the 16 MiB terminal reserve.
	var pages, free, size, limit int64
	ctx := context.Background()
	if q.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || q.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free) != nil ||
		q.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size) != nil || q.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&limit) != nil ||
		size != 4096 || limit != 32768 || pages < 1 || free < 0 || free > pages {
		return storageError()
	}
	if (pages-free)*size > limit*size-(16<<20) {
		return failure("QUOTA_EXCEEDED", 507)
	}
	return nil
}

func (b *Broker) validateRequest(r Request) (Request, string, error) {
	if !identifier(r.IdempotencyKey) {
		return r, "", failure("INVALID_IDEMPOTENCY_KEY", 400)
	}
	for _, field := range []struct {
		value *string
		limit int
	}{{r.DisplayName, 1024}, {r.DeclaredMediaType, 256}, {r.ExpectedType, 32}, {r.ExpectedSHA256, 1024}} {
		p := field.value
		if p != nil && (len(*p) > field.limit || strings.IndexByte(*p, 0) >= 0) {
			return r, "", failure("INVALID_REQUEST", 400)
		}
	}
	if r.ExpectedSHA256 != nil {
		v := *r.ExpectedSHA256
		decoded, err := hex.DecodeString(v)
		if err != nil || len(decoded) != 32 || v != strings.ToLower(v) {
			return r, "", failure("INVALID_EXPECTED_SHA256", 400)
		}
	}
	if r.SourceKind == "local" {
		if r.URL != "" {
			return r, "", failure("INVALID_REQUEST", 400)
		}
		if _, ok := b.config.InputRoots[r.RootID]; !ok {
			return r, "", failure("INPUT_ROOT_NOT_ALLOWED", 403)
		}
		if !identifier(r.RootID) || r.Source == "" || len(r.Source) > 4096 || filepath.IsAbs(r.Source) || strings.ContainsRune(r.Source, 0) {
			return r, "", failure("INVALID_INPUT_PATH", 400)
		}
		r.Source = filepath.Clean(r.Source)
		if r.Source == "." || r.Source == ".." || strings.HasPrefix(r.Source, ".."+string(filepath.Separator)) {
			return r, "", failure("INVALID_INPUT_PATH", 400)
		}
	} else if r.SourceKind == "upload" {
		if r.RootID != "" || r.Source != "" || r.URL != "" {
			return r, "", failure("INVALID_REQUEST", 400)
		}
	} else if r.SourceKind == "url" {
		if r.RootID != "" || r.Source != "" || r.DisplayName != nil || r.DeclaredMediaType != nil {
			return r, "", failure("INVALID_REQUEST", 400)
		}
		if r.ExpectedType == nil || *r.ExpectedType == "" || len(*r.ExpectedType) > 32 {
			return r, "", failure("EXPECTED_TYPE_REQUIRED", 400)
		}
		if err := acquire.ValidateURL(r.URL); err != nil {
			return r, "", failure(err.Error(), 400)
		}
	} else {
		return r, "", failure("UNSUPPORTED_SOURCE_KIND", 400)
	}
	fingerprint := r
	fingerprint.IdempotencyKey = ""
	return r, hash("intake-v1\x00" + string(encode(fingerprint))), nil
}
