package broker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func readRelease(ctx context.Context, q queryer, id string) (releaseRecord, error) {
	var r releaseRecord
	var body []byte
	var state string
	var finalized int64
	err := q.QueryRowContext(ctx, "SELECT data,state,finalized_at FROM releases WHERE id=?", id).Scan(&body, &state, &finalized)
	if errors.Is(err, sql.ErrNoRows) {
		var old string
		if q.QueryRowContext(ctx, "SELECT state FROM release_tombstones WHERE release_id=?", id).Scan(&old) == nil {
			return r, failure("KEY_EXPIRED", 409)
		}
		return r, failure("NOT_FOUND", 404)
	}
	if err != nil || strictJSON(body, &r) != nil || r.Receipt.SchemaVersion != "4" || r.Receipt.ReleaseID != id || r.Receipt.State != state || !identifier(id) || !strings.HasPrefix(id, "release_") || !identifier(r.ObjectID) || !validDigest(r.SHA256) || r.ByteSize < 0 || r.ByteSize > MaxInputBytes || r.Generation < 1 || r.TempName != releaseTempName(id, r.Generation) || r.Receipt.DestinationID != r.Destination.ID || !identifier(r.Destination.ID) || !filepath.IsAbs(r.Destination.Path) || filepath.Clean(r.Destination.Path) != r.Destination.Path || r.Receipt.OutputName != id+"."+r.Authorization.Format || !releaseFormat(r.Authorization.Format) || r.Destination.Identity == nil || r.Destination.Staging == nil {
		return r, storageError()
	}
	if r.terminal() != (finalized != 0) || r.Receipt.ResourcesFinalized != r.terminal() || r.Receipt.AbortRequested != (r.AbortRequestedAt != "") {
		return r, storageError()
	}
	if !validReleaseRecord(r) {
		return r, storageError()
	}
	return r, nil
}

func validReleaseRecord(r releaseRecord) bool {
	for _, identity := range []*releaseIdentity{r.Destination.Identity, r.Destination.Staging} {
		if identity == nil || identity.Device == "" || identity.Inode == 0 || identity.Birth == "" {
			return false
		}
	}
	if r.Destination.Identity.Device != r.Destination.Staging.Device {
		return false
	}
	if r.Receipt.AbortRequested != (r.Receipt.AbortOutcome != nil) {
		return false
	}
	if r.Receipt.AbortOutcome != nil && *r.Receipt.AbortOutcome != "PENDING" && *r.Receipt.AbortOutcome != "ABORTED" && *r.Receipt.AbortOutcome != "TOO_LATE" {
		return false
	}
	switch r.Receipt.State {
	case "PREPARED", "READY", "ABORT_REQUESTED", "REVALIDATION_REQUIRED", "RECOVERY_REQUIRED":
		return !r.Receipt.ResourcesFinalized && r.Receipt.FinalizedAt == ""
	case "COMMITTED":
		return r.Receipt.Success && r.Receipt.PublicationConfirmed && r.Receipt.PublicationStatus == "PUBLISHED" && r.Receipt.FinalValidation == "verified" && r.Receipt.OutputState == "MATCH" && r.Receipt.OutputSyncConfirmation == "confirmed" && r.CleanupConfirmedAt != ""
	case "ABORTED":
		return !r.Receipt.Success && !r.Receipt.PublicationConfirmed && r.Receipt.AbortRequested && *r.Receipt.AbortOutcome == "ABORTED" && r.NoPublicationAt != "" && r.CleanupConfirmedAt != "" && (r.Receipt.PublicationStatus == "NOT_PUBLISHED" || r.Receipt.PublicationStatus == "NOT_ATTEMPTED")
	case "PUBLISHED_UNVERIFIED":
		return !r.Receipt.Success && r.Receipt.PublicationConfirmed && r.Receipt.PublicationStatus == "PUBLISHED" && r.Receipt.FinalValidation == "unverified" && (r.Receipt.OutputState == "MISSING" || r.Receipt.OutputState == "MODIFIED") && r.CleanupConfirmedAt != ""
	}
	return false
}

func writeRelease(ctx context.Context, tx *sql.Tx, r releaseRecord) error {
	finalized := int64(0)
	if r.Receipt.ResourcesFinalized {
		at, err := time.Parse(time.RFC3339Nano, r.Receipt.FinalizedAt)
		if err != nil || !r.terminal() {
			return storageError()
		}
		finalized = at.UnixNano()
	}
	if _, err := tx.ExecContext(ctx, "UPDATE releases SET state=?,finalized_at=?,data=? WHERE id=?", r.Receipt.State, finalized, encode(r), r.Receipt.ReleaseID); err != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) saveRelease(ctx context.Context, r releaseRecord) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	if err = writeRelease(ctx, tx, r); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func releaseTempName(id string, generation int) string {
	return fmt.Sprintf("%s.%d.partial", id, generation)
}
func releaseFormat(format string) bool {
	switch format {
	case "zip", "txt", "png", "jpeg", "pdf", "docx", "xlsx", "pptx":
		return true
	}
	return false
}

func (b *Broker) Release(ctx context.Context, jobID, destination, key string) (ReleaseReceipt, error) {
	if !identifier(jobID) || !identifier(destination) || len(key) < 1 || len(key) > 256 || strings.ContainsRune(key, 0) {
		return ReleaseReceipt{}, failure("INVALID_REQUEST", 400)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ReleaseReceipt{}, failure("SERVICE_STOPPING", 503)
	}
	keyHash := hash("release-key-v1\x00" + key)
	fingerprint := hash("release-v1\x00" + jobID + "\x00" + destination)
	var id, oldFingerprint string
	err := b.db.QueryRowContext(ctx, "SELECT id,fingerprint FROM releases WHERE key_hash=?", keyHash).Scan(&id, &oldFingerprint)
	if err == nil {
		if fingerprint != oldFingerprint {
			return ReleaseReceipt{}, failure("IDEMPOTENCY_CONFLICT", 409)
		}
		r, err := readRelease(ctx, b.db, id)
		if err != nil {
			return ReleaseReceipt{}, err
		}
		if !r.terminal() && b.releaseActive == nil {
			if err = b.reconcileReleaseLocked(ctx, &r); err != nil {
				return ReleaseReceipt{}, err
			}
			if !r.terminal() && !r.Receipt.AbortRequested && r.Receipt.State == "REVALIDATION_REQUIRED" && Stage0Passed {
				if err = b.resumeReleaseLocked(ctx, &r); err != nil {
					receipt := b.releaseReceiptLocked(r)
					receipt.Replayed = true
					return receipt, releaseFailure(errorCodeForRelease(err), 409, receipt)
				}
			}
		}
		receipt := b.releaseReceiptLocked(r)
		receipt.Replayed = true
		switch r.Receipt.State {
		case "ABORTED":
			return receipt, releaseFailure("RELEASE_ABORTED", 409, receipt)
		case "PUBLISHED_UNVERIFIED":
			return receipt, releaseFailure("RELEASE_OUTPUT_UNVERIFIED", 409, receipt)
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ReleaseReceipt{}, storageError()
	}
	if err = b.db.QueryRowContext(ctx, "SELECT release_id FROM release_tombstones WHERE key_hash=?", keyHash).Scan(&id); err == nil {
		return ReleaseReceipt{}, failure("KEY_EXPIRED", 409)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ReleaseReceipt{}, storageError()
	}
	j, err := readJob(ctx, b.db, jobID)
	if err != nil {
		return ReleaseReceipt{}, err
	}
	if !Stage0Passed {
		return ReleaseReceipt{}, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	authorization, err := b.currentReleaseAuthorization(ctx, j)
	if err != nil {
		return ReleaseReceipt{}, err
	}
	r, err := b.prepareReleaseLocked(ctx, j, destination, keyHash, fingerprint, authorization)
	if err != nil {
		return ReleaseReceipt{}, err
	}
	b.startReleaseLocked(r)
	return b.releaseReceiptLocked(r), nil
}

func (b *Broker) currentReleaseAuthorization(ctx context.Context, j Job) (releaseBinding, error) {
	if !Stage0Passed || !j.Terminal() || j.Verdict != "PASS" || !j.Coverage.RequiredChecksComplete || !j.RuntimeCleanupComplete || j.InputReceipt == nil || !j.InputReceipt.ContentAvailable {
		return releaseBinding{}, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	return b.authorizedReleaseBinding(ctx, j)
}

func (b *Broker) GetRelease(ctx context.Context, id string) (ReleaseReceipt, error) {
	if !identifier(id) {
		return ReleaseReceipt{}, failure("INVALID_REQUEST", 400)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ReleaseReceipt{}, failure("SERVICE_STOPPING", 503)
	}
	r, err := readRelease(ctx, b.db, id)
	if err != nil {
		return ReleaseReceipt{}, err
	}
	return b.releaseReceiptLocked(r), nil
}

func requestReleaseAbort(r *releaseRecord) {
	if r.terminal() || r.Receipt.AbortRequested {
		return
	}
	r.AbortRequestedAt = nowText()
	r.Receipt.AbortRequested = true
	outcome := "PENDING"
	r.Receipt.AbortOutcome = &outcome
	r.Receipt.State = "ABORT_REQUESTED"
	r.Receipt.ReasonCodes = []string{"RELEASE_ABORT_REQUESTED"}
}

func (b *Broker) AbortRelease(ctx context.Context, id string) (ReleaseReceipt, error) {
	if !identifier(id) {
		return ReleaseReceipt{}, failure("INVALID_REQUEST", 400)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ReleaseReceipt{}, failure("SERVICE_STOPPING", 503)
	}
	r, err := readRelease(ctx, b.db, id)
	if err != nil {
		return ReleaseReceipt{}, err
	}
	if !r.terminal() {
		requestReleaseAbort(&r)
		if err = b.saveRelease(ctx, r); err != nil {
			return ReleaseReceipt{}, err
		}
		if b.releaseActive != nil && b.releaseActive.id == id {
			b.releaseActive.cancel()
		} else if err = b.reconcileReleaseLocked(ctx, &r); err != nil {
			return ReleaseReceipt{}, err
		}
	}
	receipt := b.releaseReceiptLocked(r)
	if r.Receipt.PublicationConfirmed {
		return receipt, releaseFailure("RELEASE_ALREADY_PUBLISHED", 409, receipt)
	}
	return receipt, nil
}

func (b *Broker) releaseReceiptLocked(r releaseRecord) ReleaseReceipt {
	receipt := r.Receipt
	receipt.HTTPStatus = 202
	if r.terminal() {
		receipt.HTTPStatus = 200
	}
	receipt.CurrentOutputState = "UNAVAILABLE"
	root, staging, err := openReleaseDirectories(r.Destination)
	if err == nil {
		defer root.Close()
		defer staging.Close()
		state, final, e := releaseFileState(root, r.Receipt.OutputName, r.TempIdentity, r.SHA256, r.ByteSize)
		if final != nil {
			final.Close()
		}
		if e == nil {
			receipt.CurrentOutputState = state
		}
	}
	return receipt
}
