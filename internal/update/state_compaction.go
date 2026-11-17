package update

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	compactionPages   = 32768     // the broker's max_page_count
	compactionHeap    = 320 << 20 // SQLite allocations for the in-memory VACUUM copy and the uncommitted main pages
	compactionLimit   = 112 << 20 // the broker refuses admission while state.sqlite is longer
	compactionJournal = 128 << 20 // the fixed rollback-journal pool
)

// rowidIncompatible counts schema objects for which plain VACUUM would renumber rowids or copy only the schema row:
// VACUUM keeps a rowid only for an INTEGER PRIMARY KEY or a table that has an index.
const rowidIncompatible = `SELECT (SELECT count(*) FROM sqlite_schema WHERE type NOT IN ('table','index'))
 + (SELECT count(*) FROM pragma_table_list t WHERE t.schema='main' AND t.name NOT IN ('sqlite_schema','sqlite_master')
    AND (t.type!='table' OR t.wr!=0 OR t.name LIKE 'sqlite%' OR NOT EXISTS (SELECT 1 FROM pragma_index_list(t.name))))`

type StateCompaction struct {
	Schema              int    `json:"schema"`
	Outcome             string `json:"outcome"`
	OldPages            int64  `json:"old_pages"`
	OldFreelistPages    int64  `json:"old_freelist_pages"`
	OldBytes            int64  `json:"old_bytes"`
	NewPages            int64  `json:"new_pages"`
	NewBytes            int64  `json:"new_bytes"`
	JournalLimitBytes   int64  `json:"journal_limit_bytes"`
	ContentSHA256       string `json:"content_sha256"`
	MainFileWithinLimit bool   `json:"main_file_within_limit"`
}

// CompactState runs VACUUM in place on a stopped state.sqlite under broker.lock. It sets SQLite's process-wide heap
// limit, so only the offline state-compact command calls it.
func CompactState(directory string) (StateCompaction, error) {
	result := StateCompaction{Schema: 1}
	dir, err := replacementDirectory(directory)
	if err != nil {
		return result, Error("UNSAFE_DATA_DIRECTORY")
	}
	defer dir.Close()
	lockFD, err := unix.Openat(int(dir.Fd()), "broker.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, Error("UNSAFE_LOCK_FILE")
	}
	lock := os.NewFile(uintptr(lockFD), "broker.lock")
	defer lock.Close()
	var info unix.Stat_t
	if unix.Fstat(lockFD, &info) != nil || !replacementFile(info) {
		return result, Error("UNSAFE_LOCK_FILE")
	}
	if unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return result, Error("BROKER_LOCK_HELD")
	}
	if replacementLocked(dir, lock) != nil {
		return result, Error("UNSAFE_DATA_DIRECTORY")
	}
	if CheckRuntimeTransition(directory) != nil {
		return result, Error("UPDATE_RUNTIME_TRANSITION_PENDING")
	}
	// Only stat calls touch the database names: closing a native descriptor on state.sqlite would release the POSIX locks
	// SQLite holds for this process.
	stat := func(name string) (unix.Stat_t, bool, error) {
		var s unix.Stat_t
		err := unix.Fstatat(int(dir.Fd()), name, &s, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return s, false, nil
		}
		return s, err == nil, err
	}
	if s, ok, _ := stat("state.sqlite"); !ok || !replacementFile(s) {
		return result, Error("UNSAFE_STATE_FILE")
	}
	for _, name := range []string{"state.sqlite-wal", "state.sqlite-shm"} {
		if _, ok, err := stat(name); ok || err != nil {
			return result, Error("STATE_NOT_CLEANLY_CLOSED")
		}
	}
	if s, ok, err := stat("state.sqlite-journal"); err != nil || ok && !replacementFile(s) {
		return result, Error("UNSAFE_JOURNAL_FILE")
	}
	path := filepath.Join(directory, "state.sqlite")
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "rw")
	q.Set("_busy_timeout", "0")
	q.Set("_txlock", "exclusive")
	// The driver reads the schema while opening, so exclusive locking must already apply to take SQLite's EXCLUSIVE lock
	// on that first read; set later, the first read opens the WAL in normal mode.
	q.Set("_locking_mode", "EXCLUSIVE")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return result, Error("STATE_IN_USE")
	}
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return result, Error("STATE_IN_USE")
	}
	// The dedicated connection goes back to the pool and the pool closes the SQLite connection before broker.lock is
	// released on every exit.
	closed := false
	closeState := func() error {
		if closed {
			return nil
		}
		closed = true
		err := conn.Close()
		if closeErr := db.Close(); err == nil {
			err = closeErr
		}
		return err
	}
	defer closeState()
	for _, setting := range []string{"PRAGMA fullfsync=ON", "PRAGMA synchronous=EXTRA", "PRAGMA temp_store=MEMORY",
		"PRAGMA cache_spill=OFF", fmt.Sprintf("PRAGMA hard_heap_limit=%d", compactionHeap), fmt.Sprintf("PRAGMA max_page_count=%d", compactionPages)} {
		if _, err = conn.ExecContext(ctx, setting); err != nil {
			return result, Error("STATE_IN_USE")
		}
	}
	var lockingMode string
	if err = conn.QueryRowContext(ctx, "PRAGMA locking_mode").Scan(&lockingMode); err != nil || lockingMode != "exclusive" {
		return result, Error("STATE_SETTINGS_FAILED")
	}
	for setting, want := range map[string]int64{"busy_timeout": 0, "fullfsync": 1, "synchronous": 3, "temp_store": 2, "cache_spill": 0,
		"hard_heap_limit": compactionHeap, "max_page_count": compactionPages, "page_size": 4096} {
		var got int64
		if err = conn.QueryRowContext(ctx, "PRAGMA "+setting).Scan(&got); err != nil || got != want {
			return result, Error("STATE_SETTINGS_FAILED")
		}
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return result, Error("STATE_IN_USE")
	}
	before, err := compactionCheck(tx, &result)
	if err != nil {
		tx.Rollback()
		return result, err
	}
	if tx.Commit() != nil {
		return result, Error("STATE_UNREADABLE")
	}
	result.ContentSHA256 = before
	// A journal SQLite did not need to roll back means an earlier run stopped after its commit and before closing.
	main, ok, _ := stat("state.sqlite")
	if !ok {
		return result, Error("UNSAFE_STATE_FILE")
	}
	_, journal, err := stat("state.sqlite-journal")
	if err != nil {
		return result, Error("UNSAFE_JOURNAL_FILE")
	}
	result.OldBytes = main.Size
	if main.Size <= compactionLimit && !journal {
		return result, Error("COMPACTION_NOT_NEEDED")
	}
	// The rollback journal holds one sector-sized header and one 4104-byte record per overwritten original page.
	result.JournalLimitBytes = 4096 + result.OldPages*(4096+8)
	if result.JournalLimitBytes > compactionJournal {
		return result, Error("STATE_COMPACTION_JOURNAL_BUDGET_EXCEEDED")
	}
	if err = runtimeCapacity(directory, result.JournalLimitBytes); err != nil {
		return result, err
	}
	var mode string
	if err = conn.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode); err != nil || mode != "delete" {
		return result, Error("STATE_IN_USE")
	}
	stopped, err := compactionVacuum(ctx, conn, directory, result.JournalLimitBytes)
	free, verifyErr := compactionVerify(ctx, conn, before, &result)
	if err != nil {
		if verifyErr != nil {
			return result, Error("STATE_COMPACTION_UNVERIFIED")
		}
		if stopped {
			return result, Error("STATE_COMPACTION_STOPPED")
		}
		return result, Error("STATE_COMPACTION_FAILED")
	}
	compacted, ok, _ := stat("state.sqlite")
	if verifyErr != nil || free != 0 || !ok || compacted.Size != result.NewPages*4096 {
		return result, Error("STATE_COMPACTION_VERIFY_FAILED")
	}
	if closeState() != nil {
		return result, Error("STATE_COMPACTION_CLOSE_FAILED")
	}
	for _, name := range []string{"state.sqlite-journal", "state.sqlite-wal", "state.sqlite-shm"} {
		if _, ok, err := stat(name); ok || err != nil {
			return result, Error("STATE_COMPACTION_CLOSE_FAILED")
		}
	}
	result.NewBytes = compacted.Size
	result.MainFileWithinLimit = compacted.Size <= compactionLimit
	result.Outcome = "COMPACTED"
	if stopped {
		// SQLite does not check cancellation during the final copy-back, so the stop request did not take effect.
		result.Outcome = "COMPACTED_RESOURCE_STOP_UNCONFIRMED"
	}
	return result, nil
}

// compactionCheck refuses work-in-progress, rowid-renumbering schemas and damaged state, then digests the content.
func compactionCheck(tx *sql.Tx, result *StateCompaction) (string, error) {
	c, err := loadControl(tx)
	if err != nil {
		return "", Error("STATE_INVALID")
	}
	if err = quiescentState(tx, c); errors.Is(err, Busy) {
		return "", Error("STATE_NOT_QUIESCENT")
	} else if errors.Is(err, Invalid) {
		return "", Error("STATE_INVALID")
	} else if err != nil {
		return "", Error("STATE_UNREADABLE")
	}
	var unsupported int64
	if tx.QueryRow(rowidIncompatible).Scan(&unsupported) != nil {
		return "", Error("STATE_UNREADABLE")
	}
	if unsupported != 0 {
		return "", Error("STATE_SCHEMA_UNSUPPORTED")
	}
	if err = compactionIntegrity(tx); err != nil {
		return "", err
	}
	if tx.QueryRow("PRAGMA page_count").Scan(&result.OldPages) != nil || tx.QueryRow("PRAGMA freelist_count").Scan(&result.OldFreelistPages) != nil {
		return "", Error("STATE_UNREADABLE")
	}
	digest, err := stateDigest(tx)
	if err != nil {
		return "", Error("STATE_UNREADABLE")
	}
	return digest, nil
}

func compactionIntegrity(tx *sql.Tx) error {
	results, err := sqlStrings(tx, "PRAGMA integrity_check")
	if err != nil {
		return Error("STATE_UNREADABLE")
	}
	if len(results) != 1 || results[0] != "ok" {
		return Error("STATE_INTEGRITY_FAILED")
	}
	rows, err := tx.Query("PRAGMA foreign_key_check")
	if err != nil {
		return Error("STATE_UNREADABLE")
	}
	defer rows.Close()
	violation := rows.Next()
	if rows.Err() != nil || rows.Close() != nil {
		return Error("STATE_UNREADABLE")
	}
	if violation {
		return Error("STATE_FOREIGN_KEY_FAILED")
	}
	return nil
}

// compactionVacuum checks free space every second and cancels VACUUM when the journal reservation no longer fits or
// cannot be measured; the cancellation takes effect only before the final copy-back.
func compactionVacuum(ctx context.Context, conn *sql.Conn, directory string, limit int64) (bool, error) {
	vacuumCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	stopped := make(chan bool, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				stopped <- false
				return
			case <-ticker.C:
			}
			// A journal not yet created has written nothing; any other failure leaves the written length unknown.
			var journal unix.Stat_t
			err := unix.Lstat(filepath.Join(directory, "state.sqlite-journal"), &journal)
			if errors.Is(err, unix.ENOENT) {
				journal.Size, err = 0, nil
			}
			if err != nil || journal.Size > limit || runtimeCapacity(directory, limit-journal.Size) != nil {
				cancel()
				stopped <- true
				return
			}
		}
	}()
	// SQLite clears an earlier interrupt when a statement starts, so a stop already requested skips VACUUM itself.
	err := vacuumCtx.Err()
	if err == nil {
		_, err = conn.ExecContext(vacuumCtx, "VACUUM")
	}
	close(done)
	return <-stopped, err
}

// compactionVerify checks the result through the same connection while it still holds the EXCLUSIVE lock. After a
// commit it detects damage but cannot restore the previous content.
func compactionVerify(ctx context.Context, conn *sql.Conn, before string, result *StateCompaction) (int64, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = compactionIntegrity(tx); err != nil {
		return 0, err
	}
	var free, pageSize int64
	if tx.QueryRow("PRAGMA page_count").Scan(&result.NewPages) != nil || tx.QueryRow("PRAGMA freelist_count").Scan(&free) != nil ||
		tx.QueryRow("PRAGMA page_size").Scan(&pageSize) != nil || pageSize != 4096 {
		return 0, Invalid
	}
	if after, err := stateDigest(tx); err != nil || after != before {
		return 0, Invalid
	}
	return free, tx.Commit()
}

// stateDigest hashes every table's rowid and typed column values in rowid order, the schema rows without root pages and
// the header values VACUUM keeps. Unary plus drops declared types so the driver returns stored values unconverted.
func stateDigest(tx *sql.Tx) (string, error) {
	h := sha256.New()
	tables, err := sqlStrings(tx, "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
	if err != nil {
		return "", err
	}
	for _, table := range tables {
		columns, err := sqlStrings(tx, "SELECT name FROM pragma_table_info(?) ORDER BY cid", table)
		if err != nil || len(columns) == 0 {
			return "", Invalid
		}
		selection := "rowid"
		for _, column := range columns {
			selection += ",+" + quoteIdentifier(column)
		}
		fmt.Fprintf(h, "table %d:%s\n", len(table), table)
		if err = digestRows(h, tx, "SELECT "+selection+" FROM "+quoteIdentifier(table)+" ORDER BY rowid", len(columns)+1); err != nil {
			return "", err
		}
	}
	h.Write([]byte("schema\n"))
	if err = digestRows(h, tx, "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name", 4); err != nil {
		return "", err
	}
	h.Write([]byte("header\n"))
	if err = digestRows(h, tx, "SELECT (SELECT user_version FROM pragma_user_version),(SELECT application_id FROM pragma_application_id),"+
		"(SELECT page_size FROM pragma_page_size),(SELECT encoding FROM pragma_encoding),(SELECT auto_vacuum FROM pragma_auto_vacuum)", 5); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestRows(h hash.Hash, tx *sql.Tx, query string, width int) error {
	rows, err := tx.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	values, pointers := make([]any, width), make([]any, width)
	for i := range values {
		pointers[i] = &values[i]
	}
	for rows.Next() {
		if err = rows.Scan(pointers...); err != nil {
			return err
		}
		for _, value := range values {
			switch v := value.(type) {
			case nil:
				h.Write([]byte("n;"))
			case int64:
				fmt.Fprintf(h, "i%d;", v)
			case float64:
				fmt.Fprintf(h, "f%x;", math.Float64bits(v))
			case string:
				fmt.Fprintf(h, "s%d:%s;", len(v), v)
			case []byte:
				fmt.Fprintf(h, "b%d:%s;", len(v), v)
			default:
				return Invalid
			}
		}
		h.Write([]byte{'\n'})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return rows.Close()
}

func sqlStrings(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, rows.Close()
}

func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
