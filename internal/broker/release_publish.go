package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func (b *Broker) prepareReleaseLocked(ctx context.Context, j Job, destination, keyHash, fingerprint string, authorization releaseBinding) (releaseRecord, error) {
	var r releaseRecord
	if err := b.pressureGateLocked(); err != nil {
		return r, err
	}
	if !Stage0Passed || b.recoveryBlocked {
		return r, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	var pending int
	if b.db.QueryRowContext(ctx, "SELECT count(*) FROM releases WHERE finalized_at=0").Scan(&pending) != nil {
		return r, storageError()
	}
	if pending >= 20 {
		return r, failure("RESOURCE_BUSY", 429)
	}
	d, err := b.readReleaseDestination(ctx, destination)
	if err != nil {
		return r, err
	}
	if d.Disabled {
		return r, failure("DESTINATION_DISABLED", 409)
	}
	if d.Identity == nil {
		if err = b.initializeReleaseDestination(ctx, &d); err != nil {
			return r, err
		}
	}
	root, staging, err := openReleaseDirectories(d)
	if err != nil {
		return r, err
	}
	defer root.Close()
	defer staging.Close()
	if err = b.releaseCapacityLocked(root, MaxInputBytes); err != nil {
		return r, err
	}
	if j.InputReceipt == nil || b.verifyObject(filepath.Join(b.config.DataDir, "objects", j.InputReceipt.ObjectID), j.InputReceipt.SHA256, j.InputReceipt.ByteSize) != nil {
		return r, failure("INPUT_HASH_MISMATCH", 409)
	}
	id := newID("release")
	r = releaseRecord{Receipt: ReleaseReceipt{SchemaVersion: "4", ReleaseID: id, JobID: j.JobID, DestinationID: destination, OutputName: id + "." + authorization.Format, State: "PREPARED", PublicationStatus: "NOT_ATTEMPTED", FinalValidation: "pending", OutputState: "NOT_PUBLISHED", CurrentOutputState: "UNAVAILABLE", OutputSyncConfirmation: "unconfirmed", ReasonCodes: []string{}, CreatedAt: nowText()}, ObjectID: j.InputReceipt.ObjectID, SHA256: j.InputReceipt.SHA256, ByteSize: j.InputReceipt.ByteSize, Destination: d, TempName: releaseTempName(id, 1), Authorization: authorization, Generation: 1}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return releaseRecord{}, storageError()
	}
	defer tx.Rollback()
	// A release reuses the stored original, so it charges no new original bytes; the destination staging is charged above.
	if err = b.admission(tx, 0); err != nil {
		return releaseRecord{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO releases(id,key_hash,fingerprint,job_id,state,data) VALUES(?,?,?,?,?,?)", id, keyHash, fingerprint, j.JobID, r.Receipt.State, encode(r)); err != nil {
		return releaseRecord{}, storageError()
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO resource_pins(owner_id,object_id) VALUES(?,?)", id, r.ObjectID); err != nil {
		return releaseRecord{}, storageError()
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO release_reservations(release_id,device,reserved) VALUES(?,?,?)", id, d.Identity.Device, MaxInputBytes); err != nil {
		return releaseRecord{}, storageError()
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO release_authorizations(release_id,sequence,attempt_id,data) VALUES(?,1,?,?)", id, authorization.AttemptID, encode(authorization)); err != nil {
		return releaseRecord{}, storageError()
	}
	if tx.Commit() != nil {
		return releaseRecord{}, storageError()
	}
	return r, nil
}

func (b *Broker) initializeReleaseDestination(ctx context.Context, d *releaseDestinationRecord) error {
	// The admission check shares the transaction of the destination update and runs before any directory is created.
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	if err = b.admission(tx, 0); err != nil {
		return err
	}
	root, err := openReleaseDirectory(d.Path)
	if err != nil {
		parent, parentErr := openReleaseDirectory(filepath.Dir(d.Path))
		if parentErr != nil {
			return err
		}
		createErr := unix.Mkdirat(int(parent.Fd()), filepath.Base(d.Path), 0700)
		if createErr == nil {
			createErr = parent.Sync()
		}
		parent.Close()
		if createErr != nil {
			return failure("DESTINATION_UNAVAILABLE", 409)
		}
		root, err = openReleaseDirectory(d.Path)
		if err != nil {
			return err
		}
	}
	defer root.Close()
	identity, err := releaseDirectoryIdentity(root)
	if err != nil {
		return err
	}
	if unix.Mkdirat(int(root.Fd()), releaseStagingName, 0700) != nil {
		return failure("RECOVERY_REQUIRED", 409)
	}
	if root.Sync() != nil {
		return failure("RECOVERY_REQUIRED", 409)
	}
	fd, err := unix.Openat(int(root.Fd()), releaseStagingName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return failure("RECOVERY_REQUIRED", 409)
	}
	stage := os.NewFile(uintptr(fd), "release-staging")
	defer stage.Close()
	stageIdentity, err := releaseDirectoryIdentity(stage)
	if err != nil || identity.Device != stageIdentity.Device || stage.Sync() != nil {
		return failure("RECOVERY_REQUIRED", 409)
	}
	d.Identity, d.Staging = &identity, &stageIdentity
	if _, err = tx.ExecContext(ctx, "UPDATE release_destinations SET data=? WHERE id=?", encode(d), d.ID); err != nil {
		return storageError()
	}
	if tx.Commit() != nil {
		return storageError()
	}
	return nil
}

func (b *Broker) releaseCapacityLocked(root *os.File, additional int64) error {
	if err := b.pressureGateLocked(); err != nil {
		return err
	}
	identity, err := releaseDirectoryIdentity(root)
	if err != nil {
		return err
	}
	remaining, err := b.pendingReleaseOn(b.db, identity.Device)
	if err != nil {
		return err
	}
	var store unix.Stat_t
	if unix.Stat(b.config.DataDir, &store) != nil {
		return storageError()
	}
	if releaseStatIdentity(store).Device == identity.Device {
		inputs, err := b.pendingInputs(b.db)
		if err != nil {
			return err
		}
		runtime, err := b.pendingRuntime(b.db)
		if err != nil {
			return err
		}
		remaining = inputs + runtime
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(root.Fd()), &fs) != nil {
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	if uint64(fs.Bavail)*uint64(fs.Bsize) < uint64(remaining+additional+SafetyMargin+((128+64+1+128+128)<<20)) {
		return failure("DISK_PRESSURE", 507)
	}
	return nil
}

func (b *Broker) pendingReleaseStorage(q queryer) (int64, error) {
	var st unix.Stat_t
	if unix.Stat(b.config.DataDir, &st) != nil {
		return 0, storageError()
	}
	return b.pendingReleaseOn(q, releaseStatIdentity(st).Device)
}

// pendingReleaseOn is the unwritten release reservation on device. The active copy keeps its progress in RAM, so only the
// part beyond what its own reservation row records is credited, never more than that row's remainder.
func (b *Broker) pendingReleaseOn(q queryer, device string) (int64, error) {
	ctx := context.Background()
	var pending int64
	if q.QueryRowContext(ctx, "SELECT coalesce(sum(max(reserved-written,0)),0) FROM release_reservations WHERE device=?", device).Scan(&pending) != nil {
		return 0, storageError()
	}
	run := b.releaseActive
	if run == nil {
		return pending, nil
	}
	var reserved, written int64
	err := q.QueryRowContext(ctx, "SELECT reserved,written FROM release_reservations WHERE release_id=? AND device=?", run.id, device).Scan(&reserved, &written)
	if errors.Is(err, sql.ErrNoRows) {
		return pending, nil
	}
	if err != nil {
		return 0, storageError()
	}
	return pending - min(max(run.written-written, 0), max(reserved-written, 0)), nil
}

func (b *Broker) startReleaseLocked(r releaseRecord) {
	if b.releaseActive != nil || b.closed || b.recoveryBlocked || !Stage0Passed || r.terminal() || r.Receipt.AbortRequested || b.pressureGateLocked() != nil {
		return
	}
	ctx, stopCause := context.WithCancelCause(context.Background())
	run := &releaseRun{id: r.Receipt.ReleaseID, cancel: func() { stopCause(context.Canceled) }, stopCause: stopCause, done: make(chan struct{})}
	b.releaseActive = run
	go b.writeReleaseOutput(ctx, run, r)
}

func (b *Broker) resumeReleaseLocked(ctx context.Context, r *releaseRecord) error {
	if err := b.pressureGateLocked(); err != nil {
		return err
	}
	if !Stage0Passed || r.Receipt.AbortRequested || r.NoPublicationAt == "" || b.releaseActive != nil || b.closed {
		return failure("REVALIDATION_REQUIRED", 409)
	}
	j, err := readJob(ctx, b.db, r.Receipt.JobID)
	if err != nil {
		return err
	}
	if j.InputReceipt == nil || j.InputReceipt.ObjectID != r.ObjectID || j.InputReceipt.SHA256 != r.SHA256 || j.InputReceipt.ByteSize != r.ByteSize {
		return failure("INPUT_HASH_MISMATCH", 409)
	}
	binding, err := b.currentReleaseAuthorization(ctx, j, func(tx *sql.Tx) error { return b.databaseBudget(tx) })
	if err != nil {
		return err
	}
	if binding.Format != r.Authorization.Format {
		return failure("REVALIDATION_REQUIRED", 409)
	}
	d, err := b.readReleaseDestination(ctx, r.Receipt.DestinationID)
	if err != nil || d.Disabled {
		return failure("DESTINATION_DISABLED", 409)
	}
	root, staging, err := openReleaseDirectories(r.Destination)
	if err != nil {
		return err
	}
	defer root.Close()
	defer staging.Close()
	state, temp, err := releaseFileState(staging, r.TempName, r.TempIdentity, r.SHA256, r.ByteSize)
	if temp != nil {
		defer temp.Close()
	}
	if err != nil {
		return err
	}
	if state == "MATCH" && (syncFile(temp) != nil || staging.Sync() != nil) {
		return failure("OUTPUT_IO_ERROR", 503)
	}
	if err = b.commitResumeLocked(ctx, r, binding, staging, state); err != nil {
		return err
	}
	if state == "MATCH" {
		if err = b.publishReleaseLocked(ctx, r, root, staging); err != nil {
			return err
		}
		return b.reconcileReleaseLocked(ctx, r)
	}
	b.startReleaseLocked(*r)
	return nil
}

// commitResumeLocked admits the new authorization before any temp cleanup or record change and updates *r only after commit.
func (b *Broker) commitResumeLocked(ctx context.Context, r *releaseRecord, binding releaseBinding, staging *os.File, state string) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	if err = b.admission(tx, 0); err != nil {
		return err
	}
	next := *r
	if state != "MATCH" {
		if err = cleanupReleaseTemp(staging, next); err != nil {
			return err
		}
		next.Generation++
		next.TempName = releaseTempName(next.Receipt.ReleaseID, next.Generation)
		next.TempIdentity = nil
	}
	next.Authorization = binding
	next.Receipt.State = "PREPARED"
	if state == "MATCH" {
		next.Receipt.State = "READY"
	}
	next.Receipt.ReasonCodes = []string{}
	if err = writeRelease(ctx, tx, next); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO release_authorizations(release_id,sequence,attempt_id,data) SELECT ?,coalesce(max(sequence),0)+1,?,? FROM release_authorizations WHERE release_id=?", next.Receipt.ReleaseID, binding.AttemptID, encode(binding), next.Receipt.ReleaseID); err != nil {
		return storageError()
	}
	if state != "MATCH" {
		if _, err = tx.ExecContext(ctx, "UPDATE release_reservations SET written=0 WHERE release_id=?", next.Receipt.ReleaseID); err != nil {
			return storageError()
		}
	}
	if tx.Commit() != nil {
		return storageError()
	}
	*r = next
	return nil
}

func sameReleaseBinding(a, b releaseBinding) bool {
	a.AuthorizedAt, b.AuthorizedAt = "", ""
	return a == b
}

func (b *Broker) nextReleaseLocked() {
	if b.closed || b.recoveryBlocked || !Stage0Passed || b.releaseActive != nil {
		return
	}
	ids, err := b.releaseIDs(context.Background(), false)
	if err != nil {
		b.recoveryBlocked = true
		return
	}
	for _, id := range ids {
		r, err := readRelease(context.Background(), b.db, id)
		if err != nil {
			b.recoveryBlocked = true
			return
		}
		if r.Receipt.State == "PREPARED" && !r.Receipt.AbortRequested {
			b.startReleaseLocked(r)
			return
		}
	}
}

func (b *Broker) writeReleaseOutput(ctx context.Context, run *releaseRun, r releaseRecord) {
	var cause error
	defer func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.releaseActive = nil
		current, err := readRelease(context.Background(), b.db, run.id)
		if err == nil && !current.terminal() {
			if cause != nil && !current.Receipt.AbortRequested && errorCodeForRelease(cause) != "REVALIDATION_REQUIRED" {
				err = b.holdRelease(context.Background(), &current, errorCodeForRelease(cause))
			} else {
				err = b.reconcileReleaseLocked(context.Background(), &current)
			}
		}
		// An unrecorded release outcome blocks new work, including restarting this release, until recovery.
		if err != nil {
			b.recoveryBlocked = true
		}
		run.cancel()
		close(run.done)
		b.nextReleaseLocked()
	}()
	root, staging, err := openReleaseDirectories(r.Destination)
	if err != nil {
		cause = err
		return
	}
	defer root.Close()
	defer staging.Close()
	input, err := openPrivate(filepath.Join(b.config.DataDir, "objects", r.ObjectID), os.O_RDONLY, 0)
	if err != nil {
		cause = failure("INPUT_MISSING", 409)
		return
	}
	defer input.Close()
	b.mu.Lock()
	current, e := readRelease(context.Background(), b.db, run.id)
	if e != nil || current.Receipt.AbortRequested || b.closed || ctx.Err() != nil {
		b.mu.Unlock()
		cause = e
		if ctx.Err() != nil {
			cause = releaseContextError(ctx)
		}
		return
	}
	j, authErr := readJob(context.Background(), b.db, current.Receipt.JobID)
	var binding releaseBinding
	if authErr == nil {
		binding, authErr = b.currentReleaseAuthorization(context.Background(), j, nil)
	}
	if authErr != nil || !sameReleaseBinding(binding, current.Authorization) {
		current.Receipt.State = "REVALIDATION_REQUIRED"
		current.Receipt.ReasonCodes = []string{"REVALIDATION_REQUIRED"}
		cause = b.saveRelease(context.Background(), current)
		b.mu.Unlock()
		return
	}
	if e = b.releaseCapacityLocked(root, 0); e != nil {
		b.mu.Unlock()
		cause = e
		return
	}
	fd, err := unix.Openat(int(staging.Fd()), r.TempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		b.mu.Unlock()
		cause = failure("RECOVERY_REQUIRED", 409)
		return
	}
	output := os.NewFile(uintptr(fd), "release-output")
	defer output.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || staging.Sync() != nil {
		b.mu.Unlock()
		cause = failure("RECOVERY_REQUIRED", 409)
		return
	}
	identity := releaseStatIdentity(st)
	r.TempIdentity = &identity
	current.TempIdentity = &identity
	e = b.saveRelease(context.Background(), current)
	r = current
	b.mu.Unlock()
	if e != nil {
		cause = e
		return
	}
	monitorDone := make(chan struct{})
	monitorStop := make(chan struct{})
	var monitorErr error
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-monitorStop:
				return
			case <-ctx.Done():
				output.Close()
				return
			case <-ticker.C:
				b.mu.Lock()
				err := b.releaseCapacityLocked(root, 0)
				if err != nil {
					monitorErr = err
					run.stopCause(err)
				}
				b.mu.Unlock()
				if err != nil {
					output.Close()
					return
				}
			}
		}
	}()
	defer func() { close(monitorStop); <-monitorDone }()
	h := sha256.New()
	buf := make([]byte, 128<<10)
	var written int64
	for {
		if ctx.Err() != nil {
			cause = releaseContextError(ctx)
			break
		}
		n, readErr := input.Read(buf)
		if n > 0 {
			if written+int64(n) > r.ByteSize {
				cause = failure("INPUT_HASH_MISMATCH", 409)
				break
			}
			m, writeErr := output.Write(buf[:n])
			written += int64(m)
			if writeErr != nil || m != n {
				cause = failure("OUTPUT_IO_ERROR", 503)
				break
			}
			h.Write(buf[:n])
			// Progress stays in RAM during the copy, so the capacity checks see it without a database write per read.
			b.mu.Lock()
			run.written = written
			b.mu.Unlock()
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			cause = failure("INPUT_HASH_MISMATCH", 409)
			break
		}
	}
	b.mu.Lock()
	if monitorErr != nil {
		cause = monitorErr
	}
	if ctx.Err() != nil {
		cause = releaseContextError(ctx)
	}
	b.mu.Unlock()
	if cause != nil {
		return
	}
	if written != r.ByteSize || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		cause = failure("INPUT_HASH_MISMATCH", 409)
		return
	}
	if syncFile(output) != nil || output.Close() != nil || staging.Sync() != nil {
		cause = failure("OUTPUT_IO_ERROR", 503)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	current, err = readRelease(context.Background(), b.db, run.id)
	if err != nil {
		cause = err
		return
	}
	if ctx.Err() != nil || current.Receipt.AbortRequested || b.closed {
		if ctx.Err() != nil {
			cause = releaseContextError(ctx)
		}
		return
	}
	if monitorErr != nil {
		cause = monitorErr
		return
	}
	if err = b.releaseCapacityLocked(root, 0); err != nil {
		cause = err
		return
	}
	// The verified, synchronized copy is recorded once before READY while this run still owns the live credit.
	if _, err = b.db.Exec("UPDATE release_reservations SET written=? WHERE release_id=?", written, run.id); err != nil {
		cause = storageError()
		return
	}
	current.Receipt.State = "READY"
	if err = b.saveRelease(context.Background(), current); err != nil {
		cause = err
		return
	}
	cause = b.publishReleaseLocked(context.Background(), &current, root, staging)
}

func errorCodeForRelease(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "RECOVERY_REQUIRED"
}

func releaseContextError(ctx context.Context) error {
	cause := context.Cause(ctx)
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return failure("INTERRUPTED", 409)
	}
	return cause
}

func (b *Broker) publishReleaseLocked(ctx context.Context, r *releaseRecord, root, staging *os.File) error {
	if err := b.pressureGateLocked(); err != nil {
		return err
	}
	if !Stage0Passed || b.closed || b.recoveryBlocked || r.Receipt.AbortRequested {
		return failure("REVALIDATION_REQUIRED", 409)
	}
	j, err := readJob(ctx, b.db, r.Receipt.JobID)
	if err != nil {
		return err
	}
	binding, err := b.currentReleaseAuthorization(ctx, j, nil)
	if err != nil || !sameReleaseBinding(binding, r.Authorization) {
		return failure("REVALIDATION_REQUIRED", 409)
	}
	d, err := b.readReleaseDestination(ctx, r.Receipt.DestinationID)
	if err != nil || d.Disabled || d.Identity == nil || *d.Identity != *r.Destination.Identity {
		return failure("DESTINATION_DISABLED", 409)
	}
	checkRoot, checkStage, err := openReleaseDirectories(r.Destination)
	if err != nil {
		return err
	}
	checkRoot.Close()
	checkStage.Close()
	state, temp, err := releaseFileState(staging, r.TempName, r.TempIdentity, r.SHA256, r.ByteSize)
	if temp != nil {
		temp.Close()
	}
	if err != nil || state != "MATCH" {
		return failure("RECOVERY_REQUIRED", 409)
	}
	attempts, err := b.publicationAttempts(ctx, *r)
	if err != nil {
		return err
	}
	for _, attempt := range attempts {
		if attempt.State != "NO_PUBLICATION_PROVEN" {
			return failure("PUBLICATION_UNKNOWN", 409)
		}
	}
	if err = b.releaseCapacityLocked(root, 0); err != nil {
		return err
	}
	boot, err := releaseBootID()
	if err != nil {
		return err
	}
	attempt := releasePublicationAttempt{ReleaseID: r.Receipt.ReleaseID, Sequence: len(attempts) + 1, Generation: r.Generation, Temp: *r.TempIdentity, Destination: *r.Destination.Identity, OutputName: r.Receipt.OutputName, Boot: boot, State: "INTENT", RecordedAt: nowText()}
	r.Receipt.PublicationStatus = "UNKNOWN"
	r.NoPublicationAt = ""
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError()
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO release_publication_attempts(release_id,sequence,state,data) VALUES(?,?,?,?)", attempt.ReleaseID, attempt.Sequence, attempt.State, encode(attempt)); err != nil {
		return storageError()
	}
	if err = writeRelease(ctx, tx, *r); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return storageError()
	}
	// 同じmuで取消・再検査・定義切替を直列化し、INTENT同期に費やした間の失効も確認する。
	binding, err = b.currentReleaseAuthorization(ctx, j, nil)
	if err != nil || !sameReleaseBinding(binding, r.Authorization) {
		if e := b.resolvePublication(ctx, &attempt, "NO_PUBLICATION_PROVEN", "authorization_expired_before_syscall"); e != nil {
			return e
		}
		r.Receipt.PublicationStatus = "NOT_PUBLISHED"
		r.NoPublicationAt = nowText()
		if e := b.saveRelease(ctx, *r); e != nil {
			return e
		}
		return failure("REVALIDATION_REQUIRED", 409)
	}
	if err = b.releaseCapacityLocked(root, 0); err != nil {
		if e := b.resolvePublication(ctx, &attempt, "NO_PUBLICATION_PROVEN", "capacity_failure_before_syscall"); e != nil {
			return e
		}
		r.Receipt.PublicationStatus = "NOT_PUBLISHED"
		r.NoPublicationAt = nowText()
		if e := b.saveRelease(ctx, *r); e != nil {
			return e
		}
		return err
	}
	if err = releaseRename(int(staging.Fd()), r.TempName, int(root.Fd()), r.Receipt.OutputName); err != nil {
		if errors.Is(err, unix.EEXIST) {
			if e := b.resolvePublication(ctx, &attempt, "NO_PUBLICATION_PROVEN", "exclusive_rename_destination_exists"); e != nil {
				return e
			}
			r.Receipt.PublicationStatus = "NOT_PUBLISHED"
			r.NoPublicationAt = nowText()
			if e := b.saveRelease(ctx, *r); e != nil {
				return e
			}
			return failure("OUTPUT_ALREADY_EXISTS", 409)
		}
		return failure("RECOVERY_REQUIRED", 409)
	}
	if err = b.resolvePublication(ctx, &attempt, "PUBLISHED", "exclusive_rename_returned_success"); err != nil {
		return err
	}
	r.Receipt.PublicationStatus = "PUBLISHED"
	r.Receipt.PublicationConfirmed = true
	return b.saveRelease(ctx, *r)
}
