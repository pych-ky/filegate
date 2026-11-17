package update

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"filegate.local/filegate/internal/av"
	"golang.org/x/sys/unix"
)

const transitionName = "update-runtime-transition.json"

type RuntimeReplacement struct {
	Schema      int    `json:"schema"`
	PreviousSHA string `json:"previous_sha256"`
	CurrentSHA  string `json:"current_sha256"`
	ControlSHA  string `json:"control_sha256"`
	Complete    bool   `json:"complete"`
}

type runtimeTransition struct {
	RuntimeReplacement
	Previous []byte `json:"previous"`
	Current  []byte `json:"current"`
	Control  []byte `json:"control"`
}

func readTransition(path string) (runtimeTransition, error) {
	var t runtimeTransition
	body, err := replacementRead(path, 3<<20)
	if err != nil {
		return t, err
	}
	if runtimeJSON(body, &t) != nil || t.Schema != 1 || !digestPattern.MatchString(t.PreviousSHA) ||
		!digestPattern.MatchString(t.CurrentSHA) || !digestPattern.MatchString(t.ControlSHA) ||
		sha256Text(t.Previous) != t.PreviousSHA || sha256Text(t.Current) != t.CurrentSHA ||
		sha256Text(t.Control) != t.ControlSHA || len(t.Previous) == 0 || len(t.Current) == 0 || len(t.Control) == 0 {
		return t, Invalid
	}
	return t, nil
}

// CheckRuntimeTransition runs before opening the DB so an interrupted replacement cannot advance its clock.
func CheckRuntimeTransition(directory string) error {
	for _, name := range []string{"." + transitionName + ".pending", "." + RuntimeRegistration + ".pending"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			return Invalid
		}
	}
	t, err := readTransition(filepath.Join(directory, transitionName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !t.Complete {
		return Invalid
	}
	body, err := readRegistration(filepath.Join(directory, RuntimeRegistration))
	if err != nil || sha256Text(body) != t.CurrentSHA {
		return Invalid
	}
	return nil
}

func replacementRead(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !replacementFile(before) || before.Size < 0 || before.Size > limit {
		return nil, Invalid
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil ||
		pinIdentity(before) != pinIdentity(after) || pinIdentity(before) != pinIdentity(named) {
		return nil, Invalid
	}
	return body, nil
}

func replacementFile(s unix.Stat_t) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFREG && s.Uid == uint32(os.Getuid()) && s.Mode&0777 == 0600 && s.Nlink == 1
}

func replacementDirectory(path string) (*os.File, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || canonical != path {
		return nil, Invalid
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || s.Uid != uint32(os.Getuid()) || s.Mode&0777 != 0700 {
		f.Close()
		return nil, Invalid
	}
	return f, nil
}

func replacementLocked(directory, lock *os.File) error {
	var held, named unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &held) != nil || unix.Lstat(directory.Name(), &named) != nil ||
		held.Dev != named.Dev || held.Ino != named.Ino || held.Mode != named.Mode || held.Uid != named.Uid ||
		named.Mode&unix.S_IFMT != unix.S_IFDIR || named.Mode&0777 != 0700 || named.Uid != uint32(os.Getuid()) {
		return Invalid
	}
	canonical, err := filepath.EvalSymlinks(directory.Name())
	if err != nil || canonical != directory.Name() || unix.Fstat(int(lock.Fd()), &held) != nil ||
		unix.Fstatat(int(directory.Fd()), "broker.lock", &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!replacementFile(named) || pinIdentity(held) != pinIdentity(named) {
		return Invalid
	}
	return nil
}

// Only the exact interrupted prefix may be completed; an unrelated pending file is retained.
func replacementWrite(directory *os.File, name string, body []byte) error {
	fd := int(directory.Fd())
	pending := "." + name + ".pending"
	fileFD, err := unix.Openat(fd, pending, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if errors.Is(err, unix.EEXIST) {
		fileFD, err = unix.Openat(fd, pending, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fileFD), pending)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || !replacementFile(before) || before.Size < 0 || before.Size > int64(len(body)) {
		return Invalid
	}
	existing := make([]byte, before.Size)
	if len(existing) > 0 {
		if _, err := f.ReadAt(existing, 0); err != nil {
			return err
		}
	}
	if !bytes.Equal(existing, body[:len(existing)]) {
		return Invalid
	}
	if _, err = f.WriteAt(body[len(existing):], int64(len(existing))); err != nil || runtimeSyncFile(f) != nil {
		return Invalid
	}
	if unix.Fstat(fileFD, &after) != nil || !replacementFile(after) || after.Size != int64(len(body)) ||
		unix.Fstatat(fd, pending, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || pinIdentity(named) != pinIdentity(after) || before.Ino != after.Ino || before.Dev != after.Dev {
		return Invalid
	}
	if err = unix.Renameat(fd, pending, fd, name); err != nil {
		return err
	}
	return directory.Sync()
}

func replacementState(directory, library string) ([]byte, error) {
	path := filepath.Join(directory, "state.sqlite")
	var databaseIdentity runtimePinIdentity
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		var s unix.Stat_t
		err := unix.Lstat(path+suffix, &s)
		if suffix != "" {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, Invalid
			}
			continue
		}
		if err != nil || !replacementFile(s) {
			return nil, Invalid
		}
		databaseIdentity = pinIdentity(s)
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	q.Set("_query_only", "1")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	foreign, err := tx.Query("PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	invalidReferences := foreign.Next()
	err = foreign.Err()
	foreign.Close()
	if err != nil || invalidReferences {
		return nil, Invalid
	}
	c, err := loadControl(tx)
	if err != nil || c.Binding.FixtureOnly || c.Binding.LibrarySHA256 != library {
		return nil, Invalid
	}
	if err := quiescentState(tx, c); err != nil {
		return nil, err
	}
	var control []byte
	if tx.QueryRow("SELECT data FROM update_control WHERE scope=?", Scope).Scan(&control) != nil {
		return nil, Invalid
	}
	var final unix.Stat_t
	if unix.Lstat(path, &final) != nil || pinIdentity(final) != databaseIdentity {
		return nil, Invalid
	}
	return control, nil
}

// quiescentState requires no active update and no pending intake, scan, deletion, release, update or definition-cache
// work; runtime replacement and offline state compaction both depend on it.
func quiescentState(tx *sql.Tx, c Control) error {
	if c.ActiveUpdateID != "" || c.State == "IN_FLIGHT" {
		return Invalid
	}
	for _, query := range []string{
		"SELECT count(*) FROM update_control WHERE scope!='official-definitions-installation'",
		"SELECT count(*) FROM reservations", "SELECT count(*) FROM resource_pins", "SELECT count(*) FROM scan_queue",
		"SELECT count(*) FROM object_deletions", "SELECT count(*) FROM object_deletion_bindings",
		"SELECT count(*) FROM runtime_runs WHERE state!='FINISHED' OR raw_reserved!=0 OR raw_written!=0",
		"SELECT count(*) FROM jobs WHERE finished<=0",
		"SELECT count(*) FROM scan_definition_snapshots WHERE active!=0",
		"SELECT count(*) FROM release_reservations",
		"SELECT count(*) FROM releases WHERE state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED') OR finalized_at<=0",
		"SELECT count(*) FROM releases WHERE coalesce(json_extract(data,'$.receipt.resources_finalized'),0)!=1 OR coalesce(json_extract(data,'$.receipt.state'),'')!=state",
		"SELECT count(*) FROM release_publication_attempts WHERE state='INTENT'",
		"SELECT count(*) FROM update_waiters",
		"SELECT count(*) FROM update_runtime WHERE state!='FINISHED'",
		"SELECT count(*) FROM update_runtime WHERE update_id NOT IN (SELECT id FROM update_attempts)",
		"SELECT count(*) FROM update_adoptions WHERE update_id NOT IN (SELECT id FROM update_attempts)",
		"SELECT count(*) FROM update_retention WHERE pending IS NOT NULL",
	} {
		var count int
		if tx.QueryRow(query).Scan(&count) != nil || count != 0 {
			return Busy
		}
	}
	rows, err := tx.Query("SELECT id FROM update_attempts")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return Invalid
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		a, err := loadAttempt(tx, id)
		if err != nil || a.State != "FINISHED" || !a.StopConfirmed || !a.CleanupConfirmed || a.ReservedBytes != 0 {
			return Busy
		}
	}
	var hasCache int
	if tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='update_definition_caches'").Scan(&hasCache) != nil {
		return Invalid
	}
	if hasCache != 0 {
		var orphan int
		if tx.QueryRow("SELECT count(*) FROM update_definition_caches WHERE update_id NOT IN (SELECT update_id FROM update_runtime)").Scan(&orphan) != nil || orphan != 0 {
			return Invalid
		}
		for _, id := range ids {
			if _, err := loadDefinitionCache(tx, id); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
	}
	return nil
}

func ReplaceRuntime(directory, candidate, expected string) (RuntimeReplacement, error) {
	var empty RuntimeReplacement
	if !digestPattern.MatchString(expected) || !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
		return empty, Invalid
	}
	dir, err := replacementDirectory(directory)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	lockFD, err := unix.Openat(int(dir.Fd()), "broker.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	lock := os.NewFile(uintptr(lockFD), "broker.lock")
	defer lock.Close()
	var lockInfo unix.Stat_t
	if unix.Fstat(lockFD, &lockInfo) != nil || !replacementFile(lockInfo) || unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return empty, Busy
	}
	if err := replacementLocked(dir, lock); err != nil {
		return empty, err
	}
	if canonical, err := filepath.EvalSymlinks(candidate); err != nil || canonical != candidate {
		return empty, Invalid
	}
	body, err := replacementRead(candidate, 1<<20)
	if err != nil {
		return empty, err
	}
	path := filepath.Join(directory, RuntimeRegistration)
	next, err := registeredRuntime(path, body, false)
	if err != nil {
		return empty, err
	}
	current, err := readRegistration(path)
	if err != nil {
		return empty, err
	}
	t, intentErr := readTransition(filepath.Join(directory, transitionName))
	if intentErr != nil && !errors.Is(intentErr, os.ErrNotExist) {
		return empty, intentErr
	}
	if intentErr == nil && t.Complete && t.CurrentSHA == next.digest && t.PreviousSHA == expected && bytes.Equal(current, body) {
		if err := CheckRuntimeTransition(directory); err != nil {
			return empty, err
		}
		return t.RuntimeReplacement, nil
	}
	var previous []byte
	if intentErr == nil && !t.Complete {
		if t.PreviousSHA != expected || t.CurrentSHA != next.digest || !bytes.Equal(t.Current, body) ||
			!bytes.Equal(current, t.Previous) && !bytes.Equal(current, t.Current) {
			return empty, Invalid
		}
		previous = t.Previous
	} else {
		if sha256Text(current) != expected || intentErr == nil && t.CurrentSHA != expected {
			return empty, Invalid
		}
		previous = current
	}
	old, err := registeredRuntime(path, previous, true)
	if err != nil || old.manifest.LibrarySHA256 != next.manifest.LibrarySHA256 || old.manifest.Engine != next.manifest.Engine ||
		old.manifest.Adapter != next.manifest.Adapter || old.manifest.Origin != next.manifest.Origin || !av.CompatibleRevision(old.manifest.ImageProfile, next.manifest.ImageProfile) {
		return empty, Invalid
	}
	control, err := replacementState(directory, next.manifest.LibrarySHA256)
	if err != nil {
		return empty, err
	}
	if intentErr == nil && !t.Complete {
		if !bytes.Equal(control, t.Control) {
			return empty, Invalid
		}
	} else {
		if intentErr == nil {
			history := "update-runtime-history-" + sha256Text(encoded(t)) + ".json"
			if saved, err := replacementRead(filepath.Join(directory, history), 3<<20); errors.Is(err, os.ErrNotExist) {
				if err = replacementWrite(dir, history, encoded(t)); err != nil {
					return empty, err
				}
			} else if err != nil || !bytes.Equal(saved, encoded(t)) {
				return empty, Invalid
			}
		}
		t = runtimeTransition{RuntimeReplacement: RuntimeReplacement{Schema: 1, PreviousSHA: expected, CurrentSHA: next.digest, ControlSHA: sha256Text(control)}, Previous: previous, Current: body, Control: control}
		if err := replacementWrite(dir, transitionName, encoded(t)); err != nil {
			return empty, err
		}
	}
	// Both manifests remain pinned until the new registration and its directory are durable.
	for _, runtime := range []*Runtime{old, next} {
		for path, identity := range runtime.pins {
			var named unix.Stat_t
			if unix.Lstat(path, &named) != nil || pinIdentity(named) != identity {
				return empty, Invalid
			}
		}
	}
	if actual, err := readRegistration(path); err != nil || !bytes.Equal(actual, current) {
		return empty, Invalid
	}
	if err := replacementLocked(dir, lock); err != nil {
		return empty, err
	}
	if err = replacementWrite(dir, RuntimeRegistration, body); err != nil {
		return empty, err
	}
	if latest, err := replacementState(directory, next.manifest.LibrarySHA256); err != nil || !bytes.Equal(latest, control) {
		return empty, Invalid
	}
	t.Complete = true
	if err = replacementWrite(dir, transitionName, encoded(t)); err != nil {
		return empty, err
	}
	if err := replacementLocked(dir, lock); err != nil {
		return empty, err
	}
	return t.RuntimeReplacement, nil
}
