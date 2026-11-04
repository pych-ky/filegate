package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func releaseFileState(dir *os.File, name string, identity *releaseIdentity, digest string, size int64) (string, *os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return "MISSING", nil, nil
	}
	if err != nil {
		return "UNAVAILABLE", nil, failure("RECOVERY_REQUIRED", 409)
	}
	f := os.NewFile(uintptr(fd), "release-file")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		f.Close()
		return "UNAVAILABLE", nil, failure("RECOVERY_REQUIRED", 409)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || identity == nil || releaseStatIdentity(st) != *identity || st.Size != size {
		f.Close()
		return "MODIFIED", nil, nil
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, size+1))
	var after unix.Stat_t
	if err != nil || unix.Fstat(fd, &after) != nil {
		f.Close()
		return "UNAVAILABLE", nil, failure("RECOVERY_REQUIRED", 409)
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest || releaseStatIdentity(after) != *identity || after.Size != size || after.Mtim != st.Mtim || after.Ctim != st.Ctim {
		f.Close()
		return "MODIFIED", nil, nil
	}
	return "MATCH", f, nil
}

func releaseAbsent(dir *os.File, name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, failure("RECOVERY_REQUIRED", 409)
	}
	return false, nil
}

func (b *Broker) publicationAttempts(ctx context.Context, r releaseRecord) ([]releasePublicationAttempt, error) {
	rows, err := b.db.QueryContext(ctx, "SELECT sequence,state,data FROM release_publication_attempts WHERE release_id=? ORDER BY sequence", r.Receipt.ReleaseID)
	if err != nil {
		return nil, storageError()
	}
	defer rows.Close()
	var result []releasePublicationAttempt
	for rows.Next() {
		var body []byte
		var state string
		var sequence int
		var attempt releasePublicationAttempt
		if rows.Scan(&sequence, &state, &body) != nil || strictJSON(body, &attempt) != nil || attempt.ReleaseID != r.Receipt.ReleaseID || sequence != len(result)+1 || attempt.Sequence != sequence || attempt.State != state || attempt.OutputName != r.Receipt.OutputName || attempt.Destination != *r.Destination.Identity || attempt.Generation < 1 || attempt.Generation > r.Generation || attempt.Boot == "" || (state != "INTENT" && state != "NO_PUBLICATION_PROVEN" && state != "PUBLISHED") {
			return nil, storageError()
		}
		if len(result) > 0 && result[len(result)-1].State != "NO_PUBLICATION_PROVEN" {
			return nil, storageError()
		}
		if state != "NO_PUBLICATION_PROVEN" && (r.TempIdentity == nil || attempt.Temp != *r.TempIdentity || attempt.Generation != r.Generation) {
			return nil, storageError()
		}
		result = append(result, attempt)
	}
	if rows.Err() != nil {
		return nil, storageError()
	}
	return result, nil
}

func (b *Broker) resolvePublication(ctx context.Context, attempt *releasePublicationAttempt, state, evidence string) error {
	if attempt.State != "INTENT" {
		return failure("RECOVERY_REQUIRED", 409)
	}
	attempt.State, attempt.Evidence, attempt.ResolvedAt = state, evidence, nowText()
	result, err := b.db.ExecContext(ctx, "UPDATE release_publication_attempts SET state=?,data=? WHERE release_id=? AND sequence=? AND state='INTENT'", state, encode(attempt), attempt.ReleaseID, attempt.Sequence)
	if err != nil {
		return storageError()
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return storageError()
	}
	return nil
}

func (b *Broker) holdRelease(ctx context.Context, r *releaseRecord, code string) error {
	r.Receipt.State = "RECOVERY_REQUIRED"
	r.Receipt.ReasonCodes = []string{code}
	return b.saveRelease(ctx, *r)
}

func (b *Broker) recoverReleases() error {
	ctx := context.Background()
	ids, err := b.releaseIDs(ctx, false)
	if err != nil {
		return err
	}
	for _, id := range ids {
		r, err := readRelease(ctx, b.db, id)
		if err != nil {
			return err
		}
		if err = b.reconcileReleaseLocked(ctx, &r); err != nil {
			return err
		}
	}
	return nil
}

func (b *Broker) reconcileReleaseLocked(ctx context.Context, r *releaseRecord) error {
	if r.terminal() {
		return nil
	}
	if b.releaseActive != nil && b.releaseActive.id == r.Receipt.ReleaseID {
		return nil
	}
	attempts, err := b.publicationAttempts(ctx, *r)
	if err != nil {
		return err
	}
	root, staging, err := openReleaseDirectories(r.Destination)
	if err != nil {
		return b.holdRelease(ctx, r, "DESTINATION_UNAVAILABLE")
	}
	defer root.Close()
	defer staging.Close()
	state, final, err := releaseFileState(root, r.Receipt.OutputName, r.TempIdentity, r.SHA256, r.ByteSize)
	if final != nil {
		defer final.Close()
	}
	if err != nil {
		return b.holdRelease(ctx, r, "RECOVERY_REQUIRED")
	}
	published := len(attempts) > 0 && attempts[len(attempts)-1].State == "PUBLISHED"
	if r.Receipt.PublicationConfirmed && !published {
		return storageError()
	}
	if len(attempts) > 0 && attempts[len(attempts)-1].State == "INTENT" {
		last := &attempts[len(attempts)-1]
		absent, e := releaseAbsent(staging, r.TempName)
		if e != nil {
			return b.holdRelease(ctx, r, "RECOVERY_REQUIRED")
		}
		if state == "MATCH" && absent {
			if err = b.resolvePublication(ctx, last, "PUBLISHED", "matching_final_original_temp_consumed"); err != nil {
				return err
			}
			published = true
		} else {
			boot, e := releaseBootID()
			tempState, temp, checkErr := releaseFileState(staging, r.TempName, &last.Temp, r.SHA256, r.ByteSize)
			if temp != nil {
				temp.Close()
			}
			if e != nil || checkErr != nil || boot != last.Boot || state != "MISSING" || tempState != "MATCH" {
				r.Receipt.PublicationStatus = "UNKNOWN"
				return b.holdRelease(ctx, r, "PUBLICATION_UNKNOWN")
			}
			if err = b.resolvePublication(ctx, last, "NO_PUBLICATION_PROVEN", "same_boot_unchanged_unconsumed_exclusive_temp"); err != nil {
				return err
			}
		}
	}
	if published {
		r.Receipt.PublicationStatus = "PUBLISHED"
		r.Receipt.PublicationConfirmed = true
		if r.Receipt.AbortRequested {
			value := "TOO_LATE"
			r.Receipt.AbortOutcome = &value
		}
		if err = b.saveRelease(ctx, *r); err != nil {
			return err
		}
		if state == "MATCH" {
			absent, err := releaseAbsent(staging, r.TempName)
			if err != nil || !absent || syncFile(final) != nil || root.Sync() != nil || staging.Sync() != nil {
				return b.holdRelease(ctx, r, "RECOVERY_REQUIRED")
			}
			verified, checked, verifyErr := releaseFileState(root, r.Receipt.OutputName, r.TempIdentity, r.SHA256, r.ByteSize)
			if checked != nil {
				checked.Close()
			}
			if verifyErr != nil || verified != "MATCH" {
				return b.holdRelease(ctx, r, "RECOVERY_REQUIRED")
			}
			r.Receipt.OutputSyncConfirmation = "confirmed"
			r.Receipt.FinalValidation = "verified"
			r.Receipt.OutputState = "MATCH"
			r.Receipt.Success = true
			return b.finalizeRelease(ctx, r, "COMMITTED")
		}
		if state != "MISSING" && state != "MODIFIED" {
			return b.holdRelease(ctx, r, "RECOVERY_REQUIRED")
		}
		if err = cleanupReleaseTemp(staging, *r); err != nil {
			return b.holdRelease(ctx, r, "CLEANUP_PENDING")
		}
		r.Receipt.FinalValidation = "unverified"
		r.Receipt.OutputState = state
		r.Receipt.Success = false
		r.Receipt.ReasonCodes = []string{"RELEASE_OUTPUT_UNVERIFIED"}
		return b.finalizeRelease(ctx, r, "PUBLISHED_UNVERIFIED")
	}
	// 未公開証拠はstaging削除より先に同期確定し、削除後の再起動にも残す。
	r.Receipt.PublicationStatus = "NOT_PUBLISHED"
	if len(attempts) == 0 {
		r.Receipt.PublicationStatus = "NOT_ATTEMPTED"
	}
	if r.NoPublicationAt == "" {
		r.NoPublicationAt = nowText()
		if err = b.saveRelease(ctx, *r); err != nil {
			return err
		}
	}
	if r.Receipt.AbortRequested {
		if err = cleanupReleaseTemp(staging, *r); err != nil {
			return b.holdRelease(ctx, r, "CLEANUP_PENDING")
		}
		r.Receipt.OutputState = "NOT_PUBLISHED"
		r.Receipt.FinalValidation = "not_applicable"
		value := "ABORTED"
		r.Receipt.AbortOutcome = &value
		r.Receipt.ReasonCodes = []string{"RELEASE_ABORTED"}
		return b.finalizeRelease(ctx, r, "ABORTED")
	}
	r.Receipt.State = "REVALIDATION_REQUIRED"
	r.Receipt.ReasonCodes = []string{"REVALIDATION_REQUIRED"}
	return b.saveRelease(ctx, *r)
}

func cleanupReleaseTemp(staging *os.File, r releaseRecord) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(staging.Fd()), r.TempName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if r.TempIdentity == nil || releaseStatIdentity(st) != *r.TempIdentity || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&0077 != 0 {
			return failure("RECOVERY_REQUIRED", 409)
		}
		if unix.Unlinkat(int(staging.Fd()), r.TempName, 0) != nil {
			return failure("CLEANUP_PENDING", 503)
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return failure("CLEANUP_PENDING", 503)
	}
	if staging.Sync() != nil {
		return failure("CLEANUP_PENDING", 503)
	}
	absent, err := releaseAbsent(staging, r.TempName)
	if err != nil || !absent {
		return failure("CLEANUP_PENDING", 503)
	}
	return nil
}

func (b *Broker) finalizeRelease(ctx context.Context, r *releaseRecord, state string) error {
	if r.terminal() {
		return nil
	}
	r.Receipt.State = state
	r.Receipt.ResourcesFinalized = true
	r.Receipt.FinalizedAt = nowText()
	r.CleanupConfirmedAt = r.Receipt.FinalizedAt
	if state == "COMMITTED" {
		r.Receipt.ReasonCodes = []string{}
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	if err = writeRelease(ctx, tx, *r); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM resource_pins WHERE owner_id=? AND object_id=?", r.Receipt.ReleaseID, r.ObjectID); err != nil {
		return storageError()
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM release_reservations WHERE release_id=?", r.Receipt.ReleaseID); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) pruneReleases(ctx context.Context, cutoff time.Time) error {
	rows, err := b.db.QueryContext(ctx, "SELECT id FROM releases WHERE finalized_at>0 AND finalized_at<?", cutoff.Add(-30*24*time.Hour).UnixNano())
	if err != nil {
		return storageError()
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return storageError()
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError()
	}
	for _, id := range ids {
		r, err := readRelease(ctx, b.db, id)
		if err != nil || !r.terminal() {
			return storageError()
		}
		tx, err := b.db.BeginTx(ctx, nil)
		if err != nil {
			return storageError()
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO release_tombstones(key_hash,release_id,job_id,state) SELECT key_hash,id,job_id,state FROM releases WHERE id=?", id)
		if err == nil {
			_, err = tx.ExecContext(ctx, "DELETE FROM releases WHERE id=?", id)
		}
		if err != nil || tx.Commit() != nil {
			tx.Rollback()
			return storageError()
		}
	}
	return nil
}
