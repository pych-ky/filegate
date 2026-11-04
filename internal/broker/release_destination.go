package broker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const releaseStagingName = ".filegate-staging"

func (b *Broker) configureReleaseDestinations() error {
	configured := b.config.ReleaseDestinations
	if len(configured) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return failure("INVALID_CONFIGURATION", 400)
		}
		configured = map[string]string{"default": filepath.Join(home, "Downloads", "FileGate")}
	}
	for id, path := range configured {
		if !identifier(id) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return failure("INVALID_CONFIGURATION", 400)
		}
		old, err := b.readReleaseDestination(context.Background(), id)
		if err == nil {
			if old.Path != path {
				return failure("DESTINATION_CONFIGURATION_CHANGED", 409)
			}
			continue
		}
		var e *Error
		if !errors.As(err, &e) || e.Code != "DESTINATION_NOT_FOUND" {
			return err
		}
		d := releaseDestinationRecord{ID: id, Path: path}
		if _, err = b.db.Exec("INSERT INTO release_destinations(id,data) VALUES(?,?)", id, encode(d)); err != nil {
			return storageError()
		}
	}
	return nil
}

func (b *Broker) readReleaseDestination(ctx context.Context, id string) (releaseDestinationRecord, error) {
	var d releaseDestinationRecord
	var data []byte
	err := b.db.QueryRowContext(ctx, "SELECT data FROM release_destinations WHERE id=?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return d, failure("DESTINATION_NOT_FOUND", 404)
	}
	if err != nil || json.Unmarshal(data, &d) != nil || d.ID != id || !filepath.IsAbs(d.Path) || filepath.Clean(d.Path) != d.Path {
		return d, storageError()
	}
	return d, nil
}

func (b *Broker) ReleaseDestinations(ctx context.Context) ([]ReleaseDestination, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, failure("SERVICE_STOPPING", 503)
	}
	rows, err := b.db.QueryContext(ctx, "SELECT data FROM release_destinations ORDER BY id")
	if err != nil {
		return nil, storageError()
	}
	defer rows.Close()
	result := []ReleaseDestination{}
	for rows.Next() {
		var body []byte
		var d releaseDestinationRecord
		if rows.Scan(&body) != nil || json.Unmarshal(body, &d) != nil {
			return nil, storageError()
		}
		result = append(result, ReleaseDestination{ID: d.ID, Enabled: !d.Disabled})
	}
	if rows.Err() != nil {
		return nil, storageError()
	}
	return result, nil
}

func (b *Broker) DisableReleaseDestination(ctx context.Context, id string) (ReleaseDestination, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ReleaseDestination{}, failure("SERVICE_STOPPING", 503)
	}
	d, err := b.readReleaseDestination(ctx, id)
	if err != nil {
		return ReleaseDestination{}, err
	}
	ids, err := b.releaseIDs(ctx, false)
	if err != nil {
		return ReleaseDestination{}, err
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return ReleaseDestination{}, storageError()
	}
	defer tx.Rollback()
	d.Disabled = true
	if _, err = tx.ExecContext(ctx, "UPDATE release_destinations SET data=? WHERE id=?", encode(d), id); err != nil {
		return ReleaseDestination{}, storageError()
	}
	for _, releaseID := range ids {
		r, err := readRelease(ctx, tx, releaseID)
		if err != nil {
			return ReleaseDestination{}, err
		}
		if r.Receipt.DestinationID != id || r.terminal() {
			continue
		}
		requestReleaseAbort(&r)
		if err = writeRelease(ctx, tx, r); err != nil {
			return ReleaseDestination{}, err
		}
	}
	if tx.Commit() != nil {
		return ReleaseDestination{}, storageError()
	}
	for _, releaseID := range ids {
		r, err := readRelease(ctx, b.db, releaseID)
		if err != nil {
			return ReleaseDestination{}, err
		}
		if r.Receipt.DestinationID != id || r.terminal() {
			continue
		}
		if b.releaseActive != nil && b.releaseActive.id == releaseID {
			b.releaseActive.cancel()
		} else if err = b.reconcileReleaseLocked(ctx, &r); err != nil {
			return ReleaseDestination{}, err
		}
	}
	return ReleaseDestination{ID: id, Enabled: false}, nil
}

// 各path要素をfdから辿り、出力先へ到達する途中のsymlinkも追従しない。
func openReleaseDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, failure("DESTINATION_UNAVAILABLE", 409)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, failure("DESTINATION_UNAVAILABLE", 409)
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, failure("DESTINATION_UNAVAILABLE", 409)
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "release-directory")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 || !releaseFilesystemSupported(fd) {
		f.Close()
		return nil, failure("DESTINATION_UNSUPPORTED", 409)
	}
	return f, nil
}

func releaseDirectoryIdentity(f *os.File) (releaseIdentity, error) {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return releaseIdentity{}, failure("RECOVERY_REQUIRED", 409)
	}
	return releaseStatIdentity(st), nil
}

func openReleaseDirectories(d releaseDestinationRecord) (*os.File, *os.File, error) {
	root, err := openReleaseDirectory(d.Path)
	if err != nil {
		return nil, nil, err
	}
	identity, err := releaseDirectoryIdentity(root)
	if err != nil || d.Identity == nil || identity != *d.Identity {
		root.Close()
		return nil, nil, failure("DESTINATION_IDENTITY_CHANGED", 409)
	}
	fd, err := unix.Openat(int(root.Fd()), releaseStagingName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		root.Close()
		return nil, nil, failure("RECOVERY_REQUIRED", 409)
	}
	staging := os.NewFile(uintptr(fd), "release-staging")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || d.Staging == nil || releaseStatIdentity(st) != *d.Staging || d.Staging.Device != d.Identity.Device {
		staging.Close()
		root.Close()
		return nil, nil, failure("DESTINATION_IDENTITY_CHANGED", 409)
	}
	return root, staging, nil
}

func (b *Broker) releaseIDs(ctx context.Context, includeTerminal bool) ([]string, error) {
	query := "SELECT id FROM releases"
	if !includeTerminal {
		query += " WHERE finalized_at=0"
	}
	rows, err := b.db.QueryContext(ctx, query)
	if err != nil {
		return nil, storageError()
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return nil, storageError()
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, storageError()
	}
	sort.Strings(ids)
	return ids, nil
}
