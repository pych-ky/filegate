package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type originalIdentity struct {
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Links      uint64 `json:"links"`
	Bytes      int64  `json:"bytes"`
	ModifiedNS int64  `json:"modified_ns"`
	ChangedNS  int64  `json:"changed_ns"`
}

type originalDeletion struct {
	Schema    int              `json:"schema"`
	JobID     string           `json:"job_id"`
	ObjectID  string           `json:"object_id"`
	SHA256    string           `json:"sha256"`
	Bytes     int64            `json:"bytes"`
	ParentDev uint64           `json:"parent_device"`
	ParentIno uint64           `json:"parent_inode"`
	File      originalIdentity `json:"file"`
}

func originalStat(st unix.Stat_t) originalIdentity {
	return originalIdentity{uint64(st.Dev), st.Ino, uint32(st.Mode), st.Uid, st.Gid, uint64(st.Nlink), st.Size, st.Mtim.Nano(), st.Ctim.Nano()}
}

// DeleteOriginal is called only by the local UI after its explicit delete action.
func (b *Broker) DeleteOriginal(ctx context.Context, jobID string) (Job, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Job{}, failure("SERVICE_STOPPING", 503)
	}
	if b.recoveryBlocked {
		return Job{}, failure("RECOVERY_REQUIRED", 503)
	}
	if !identifier(jobID) || !strings.HasPrefix(jobID, "job_") {
		return Job{}, failure("INVALID_JOB_ID", 400)
	}
	j, err := b.originalDeletionJob(ctx, jobID)
	if err != nil {
		return Job{}, err
	}
	if err = b.beginOriginalDeletion(ctx, j); err != nil {
		return Job{}, err
	}
	// The durable intent survives a UI disconnect, and settles only after unlink+sync.
	j, err = b.finishDeletion(context.Background(), jobID, j.InputReceipt.ObjectID)
	if err != nil {
		b.recoveryBlocked = true
	}
	return j, err
}

func (b *Broker) originalDeletionJob(ctx context.Context, jobID string) (Job, error) {
	j, err := readJob(ctx, b.db, jobID)
	if err != nil {
		return j, err
	}
	if j.JobID != jobID || j.InputReceipt == nil || !identifier(j.InputReceipt.ObjectID) || !strings.HasPrefix(j.InputReceipt.ObjectID, "object_") ||
		!validDigest(j.InputReceipt.SHA256) || j.InputReceipt.ByteSize < 0 || j.InputReceipt.ByteSize > MaxInputBytes {
		return j, failure("INPUT_MISSING", 409)
	}
	if !j.Terminal() || !j.RuntimeCleanupComplete || b.active[jobID] != nil || b.scanActive != nil && b.scanActive.job.JobID == jobID {
		return j, failure("RESOURCE_BUSY", 409)
	}
	if b.releaseActive != nil {
		var activeJob string
		if b.db.QueryRowContext(ctx, "SELECT job_id FROM releases WHERE id=?", b.releaseActive.id).Scan(&activeJob) != nil {
			return j, failure("RECOVERY_REQUIRED", 503)
		}
		if activeJob == jobID {
			return j, failure("RESOURCE_BUSY", 409)
		}
	}
	var objectJob, digest string
	var size int64
	var available int
	if b.db.QueryRowContext(ctx, "SELECT job_id,sha256,size,available FROM objects WHERE id=?", j.InputReceipt.ObjectID).Scan(&objectJob, &digest, &size, &available) != nil ||
		objectJob != jobID || digest != j.InputReceipt.SHA256 || size != j.InputReceipt.ByteSize || available != 0 && available != 1 || (available == 1) != j.InputReceipt.ContentAvailable {
		return j, failure("RECOVERY_REQUIRED", 503)
	}
	var references int
	queries := []struct {
		text string
		args []any
	}{
		{"SELECT count(*) FROM reservations WHERE job_id=? OR object_id=?", []any{jobID, j.InputReceipt.ObjectID}},
		{"SELECT count(*) FROM resource_pins WHERE object_id=?", []any{j.InputReceipt.ObjectID}},
		{"SELECT count(*) FROM scan_queue WHERE job_id=?", []any{jobID}},
		{"SELECT count(*) FROM update_waiters WHERE job_id=?", []any{jobID}},
		{"SELECT count(*) FROM runtime_runs r WHERE job_id=? AND (state!='FINISHED' OR raw_reserved!=0 OR raw_written!=0 OR NOT EXISTS(SELECT 1 FROM runtime_finalizations f WHERE f.attempt_id=r.attempt_id AND resolved_at>0))", []any{jobID}},
		{"SELECT count(*) FROM scan_definition_snapshots s JOIN attempts a ON a.id=s.attempt_id WHERE a.job_id=? AND s.active!=0", []any{jobID}},
		{"SELECT count(*) FROM release_reservations s JOIN releases r ON r.id=s.release_id WHERE r.job_id=?", []any{jobID}},
	}
	for _, query := range queries {
		if b.db.QueryRowContext(ctx, query.text, query.args...).Scan(&references) != nil {
			return j, storageError()
		}
		if references != 0 {
			return j, failure("RESOURCE_BUSY", 409)
		}
	}
	rows, err := b.db.QueryContext(ctx, "SELECT id,job_id FROM releases WHERE job_id=? OR json_extract(data,'$.object_id')=?", jobID, j.InputReceipt.ObjectID)
	if err != nil {
		return j, storageError()
	}
	var releases []string
	for rows.Next() {
		var id, owner string
		if rows.Scan(&id, &owner) != nil || owner != jobID {
			rows.Close()
			return j, failure("RECOVERY_REQUIRED", 503)
		}
		releases = append(releases, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return j, storageError()
	}
	for _, id := range releases {
		r, e := readRelease(ctx, b.db, id)
		if e != nil || r.Receipt.JobID != jobID || r.ObjectID != j.InputReceipt.ObjectID || r.SHA256 != digest || r.ByteSize != size {
			return j, failure("RECOVERY_REQUIRED", 503)
		}
		if !r.terminal() || !r.Receipt.ResourcesFinalized {
			return j, failure("RESOURCE_BUSY", 409)
		}
		publications, e := b.publicationAttempts(ctx, r)
		if e != nil {
			return j, failure("RECOVERY_REQUIRED", 503)
		}
		for _, publication := range publications {
			if publication.State == "INTENT" {
				return j, failure("RESOURCE_BUSY", 409)
			}
		}
	}
	return j, nil
}

func (b *Broker) originalDirectory() (*os.File, unix.Stat_t, error) {
	var identity unix.Stat_t
	root, err := unix.Open(b.config.DataDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, identity, failure("RECOVERY_REQUIRED", 503)
	}
	defer unix.Close(root)
	fd, err := unix.Openat(root, "objects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, identity, failure("RECOVERY_REQUIRED", 503)
	}
	f := os.NewFile(uintptr(fd), "objects")
	if unix.Fstat(fd, &identity) != nil || identity.Mode&unix.S_IFMT != unix.S_IFDIR || identity.Uid != uint32(os.Geteuid()) || identity.Mode&0077 != 0 {
		f.Close()
		return nil, identity, failure("RECOVERY_REQUIRED", 503)
	}
	return f, identity, nil
}

func captureOriginal(dir *os.File, receipt InputReceipt, missing bool) (originalIdentity, error) {
	var before, after, named unix.Stat_t
	fd, err := unix.Openat(int(dir.Fd()), receipt.ObjectID, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && missing {
		return originalIdentity{}, nil
	}
	if err != nil {
		return originalIdentity{}, failure("RECOVERY_REQUIRED", 503)
	}
	f := os.NewFile(uintptr(fd), receipt.ObjectID)
	defer f.Close()
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Mode&0777 != 0400 || before.Size != receipt.ByteSize {
		return originalIdentity{}, failure("RECOVERY_REQUIRED", 503)
	}
	h := sha256.New()
	n, err := io.CopyN(h, f, receipt.ByteSize)
	if err != nil || n != receipt.ByteSize || hex.EncodeToString(h.Sum(nil)) != receipt.SHA256 || unix.Fstat(fd, &after) != nil ||
		unix.Fstatat(int(dir.Fd()), receipt.ObjectID, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || originalStat(before) != originalStat(after) || originalStat(before) != originalStat(named) {
		return originalIdentity{}, failure("RECOVERY_REQUIRED", 503)
	}
	return originalStat(before), nil
}

func (b *Broker) beginOriginalDeletion(ctx context.Context, j Job) error {
	var owner string
	err := b.db.QueryRowContext(ctx, "SELECT job_id FROM object_deletions WHERE object_id=?", j.InputReceipt.ObjectID).Scan(&owner)
	if err == nil {
		if owner != j.JobID {
			return failure("RECOVERY_REQUIRED", 503)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return storageError()
	}
	dir, parent, err := b.originalDirectory()
	if err != nil {
		return err
	}
	defer dir.Close()
	if !j.InputReceipt.ContentAvailable {
		absent, e := releaseAbsent(dir, j.InputReceipt.ObjectID)
		if e != nil || !absent {
			return failure("RECOVERY_REQUIRED", 503)
		}
		return nil
	}
	identity, err := captureOriginal(dir, *j.InputReceipt, false)
	if err != nil {
		return err
	}
	record := originalDeletion{1, j.JobID, j.InputReceipt.ObjectID, j.InputReceipt.SHA256, j.InputReceipt.ByteSize, uint64(parent.Dev), parent.Ino, identity}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO object_deletions(object_id,job_id) VALUES(?,?)", record.ObjectID, record.JobID); err != nil {
		return storageError()
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO object_deletion_bindings(object_id,data) VALUES(?,?)", record.ObjectID, encode(record)); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		b.recoveryBlocked = true
		return storageError()
	}
	return nil
}

func (b *Broker) finishOriginalDeletion(ctx context.Context, jobID, objectID string) (Job, error) {
	j, err := b.originalDeletionJob(ctx, jobID)
	if err != nil || j.InputReceipt.ObjectID != objectID {
		return Job{}, failure("RECOVERY_REQUIRED", 503)
	}
	var owner string
	err = b.db.QueryRowContext(ctx, "SELECT job_id FROM object_deletions WHERE object_id=?", objectID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) && !j.InputReceipt.ContentAvailable {
		return j, nil
	}
	if err != nil || owner != jobID {
		return Job{}, failure("RECOVERY_REQUIRED", 503)
	}
	dir, parent, err := b.originalDirectory()
	if err != nil {
		return Job{}, err
	}
	defer dir.Close()
	var raw []byte
	var record originalDeletion
	err = b.db.QueryRowContext(ctx, "SELECT data FROM object_deletion_bindings WHERE object_id=?", objectID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		// Old durable intents may have unlinked already; absence never authorizes a later inode.
		identity, e := captureOriginal(dir, *j.InputReceipt, true)
		if e != nil {
			return Job{}, e
		}
		record = originalDeletion{1, jobID, objectID, j.InputReceipt.SHA256, j.InputReceipt.ByteSize, uint64(parent.Dev), parent.Ino, identity}
		if _, err = b.db.ExecContext(ctx, "INSERT INTO object_deletion_bindings(object_id,data) VALUES(?,?)", objectID, encode(record)); err != nil {
			return Job{}, storageError()
		}
	} else if err != nil || strictJSON(raw, &record) != nil {
		return Job{}, failure("RECOVERY_REQUIRED", 503)
	}
	if record.Schema != 1 || record.JobID != jobID || record.ObjectID != objectID || record.SHA256 != j.InputReceipt.SHA256 || record.Bytes != j.InputReceipt.ByteSize || record.ParentDev != uint64(parent.Dev) || record.ParentIno != parent.Ino {
		return Job{}, failure("RECOVERY_REQUIRED", 503)
	}
	var named unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), objectID, &named, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if record.File.Inode == 0 || originalStat(named) != record.File || named.Mode&unix.S_IFMT != unix.S_IFREG || named.Uid != uint32(os.Geteuid()) || named.Nlink != 1 || named.Mode&0777 != 0400 {
			return Job{}, failure("RECOVERY_REQUIRED", 503)
		}
		if unix.Unlinkat(int(dir.Fd()), objectID, 0) != nil {
			return Job{}, failure("CLEANUP_PENDING", 503)
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return Job{}, failure("CLEANUP_PENDING", 503)
	}
	if dir.Sync() != nil {
		return Job{}, failure("CLEANUP_PENDING", 503)
	}
	absent, err := releaseAbsent(dir, objectID)
	if err != nil || !absent {
		return Job{}, failure("CLEANUP_PENDING", 503)
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, storageError()
	}
	defer tx.Rollback()
	j.InputReceipt.ContentAvailable = false
	if _, err = tx.ExecContext(ctx, "UPDATE objects SET available=0 WHERE id=? AND job_id=?", objectID, jobID); err != nil || writeJob(ctx, tx, j) != nil {
		return Job{}, storageError()
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM object_deletions WHERE object_id=? AND job_id=?", objectID, jobID); err != nil {
		return Job{}, storageError()
	}
	if tx.Commit() != nil {
		return Job{}, storageError()
	}
	return j, nil
}
