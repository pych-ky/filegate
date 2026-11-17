package broker

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	updatecontrol "filegate.local/filegate/internal/update"
	"golang.org/x/sys/unix"
)

// The retained update reports (final.json and its .pending) share a 16 MiB pool; the bridge caps each saved report at 1 MiB.
// Retained scan reports and run control evidence (scan rows and update runtimes alike) share the 1 GiB detailed-report pool.
const (
	updateReportPool  int64 = 16 << 20
	updateReportLimit int64 = 1 << 20
	runEvidencePool   int64 = 1 << 30
)

// updateStartAdmission admits a new update attempt inside BeginRuntime's transaction, before its first write.
func (b *Broker) updateStartAdmission(tx *sql.Tx) error {
	if err := b.admission(tx, 0); err != nil {
		return err
	}
	reports, control, err := b.retainedUpdates(tx)
	if err != nil {
		return err
	}
	if reports > updateReportPool-updateReportLimit {
		return failure("QUOTA_EXCEEDED", 507)
	}
	return runEvidenceBudget(tx, control, controlReservation)
}

// scanStartAdmission admits a new scan attempt inside prepareScan's transaction, before its runtime row and pin.
func (b *Broker) scanStartAdmission(tx *sql.Tx) error {
	if err := b.admission(tx, 0); err != nil {
		return err
	}
	_, control, err := b.retainedUpdates(tx)
	if err != nil {
		return err
	}
	return runEvidenceBudget(tx, control, reportLimit+controlReservation)
}

// runEvidenceBudget refuses new work whose reservation would push the scan rows' report and control bytes plus the retained
// update control bytes past the shared pool. Already written bytes stay out of the physical pending sum.
func runEvidenceBudget(tx *sql.Tx, updateControl, reserve int64) error {
	var scans int64
	if tx.QueryRowContext(context.Background(), "SELECT coalesce(sum(report_reserved+control_reserved),0) FROM runtime_runs").Scan(&scans) != nil || scans < 0 {
		return storageError()
	}
	if min(scans, runEvidencePool+1)+updateControl > runEvidencePool-reserve {
		return failure("QUOTA_EXCEEDED", 507)
	}
	return nil
}

// retainedUpdates returns the report bytes and the control bytes of the live update runtimes. Every entry of the updates root
// must be a runtime directory that the database has not marked removed; anything else is unaccounted.
func (b *Broker) retainedUpdates(tx *sql.Tx) (int64, int64, error) {
	rows, err := tx.QueryContext(context.Background(), "SELECT r.update_id,r.directory,coalesce(t.runtime_removed,0) FROM update_runtime r LEFT JOIN update_retention t ON t.update_id=r.update_id")
	if err != nil {
		return 0, 0, storageError()
	}
	live := map[string]bool{}
	for rows.Next() {
		var id, directory string
		var removed int64
		if err = rows.Scan(&id, &directory, &removed); err != nil {
			break
		}
		if !identifier(id) || !strings.HasPrefix(id, "update_") || directory != filepath.Join(b.config.DataDir, "updates", id) || (removed != 0 && removed != 1) {
			rows.Close()
			return 0, 0, failure("RECOVERY_REQUIRED", 503)
		}
		live[id] = removed == 0
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, 0, storageError()
	}
	data, err := openReportDirectory(unix.AT_FDCWD, b.config.DataDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, storageError()
	}
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(data)
	root, err := openReportDirectory(data, "updates", true)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	directory := os.NewFile(uintptr(root), filepath.Join(b.config.DataDir, "updates"))
	defer directory.Close()
	var entries []string
	for {
		names, err := directory.Readdirnames(256)
		for _, name := range names {
			if !live[name] {
				return 0, 0, failure("RECOVERY_REQUIRED", 503)
			}
			entries = append(entries, name)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, 0, storageError()
		}
	}
	var reports, control int64
	for _, id := range entries {
		r, c, err := retainedRuntimeBytes(int(directory.Fd()), id)
		if err != nil {
			return 0, 0, err
		}
		reports = min(reports+r, updateReportPool+1)
		control = min(control+c, runEvidencePool+1)
	}
	return reports, control, nil
}

// openReportDirectory opens one owned directory component without following a symlink; runtime directories must be mode 0700
// and the data directory only needs no group or other access.
func openReportDirectory(parent int, name string, runtime bool) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, os.ErrNotExist
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return -1, failure("RECOVERY_REQUIRED", 503)
	}
	if err != nil {
		return -1, storageError()
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		unix.Close(fd)
		return -1, storageError()
	}
	mode := uint32(st.Mode) & 0777
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || (runtime && mode != 0700) || mode&0077 != 0 {
		unix.Close(fd)
		return -1, failure("RECOVERY_REQUIRED", 503)
	}
	return fd, nil
}

// retainedRuntimeBytes counts one live runtime: the actual final.json and final.json.pending sizes for the report pool, and
// the management bytes of its other control files for the run-evidence pool. A runtime or output directory that was never
// created, or whose removal retention already finished, holds neither.
func retainedRuntimeBytes(root int, id string) (int64, int64, error) {
	runtime, err := openReportDirectory(root, id, true)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(runtime)
	control, err := updatecontrol.RetainedControlBytes(runtime)
	if errors.Is(err, updatecontrol.Invalid) {
		return 0, 0, failure("RECOVERY_REQUIRED", 503)
	}
	if err != nil {
		return 0, 0, storageError()
	}
	output, err := openReportDirectory(runtime, "output", true)
	if errors.Is(err, os.ErrNotExist) {
		return 0, control, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(output)
	var reports int64
	for _, name := range []string{"final.json", "final.json.pending"} {
		var st unix.Stat_t
		err := unix.Fstatat(output, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return 0, 0, storageError()
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&07777 != 0600 || st.Size < 0 {
			return 0, 0, failure("RECOVERY_REQUIRED", 503)
		}
		reports += min(st.Size, updateReportPool+1)
	}
	return reports, control, nil
}
