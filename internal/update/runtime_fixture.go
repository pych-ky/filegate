package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Resource proofs bind the update snapshot; no product job or original is passed.
type runtimeRequest struct {
	Schema      int            `json:"schema"`
	Profile     string         `json:"profile"`
	FixtureOnly bool           `json:"fixture_only"`
	Attempt     Attempt        `json:"attempt"`
	Restore     RestoreRequest `json:"restore"`
	Library     string         `json:"library_sha256"`
	ManifestSHA string         `json:"manifest_sha256"`
	JobID       string         `json:"job_id"`
	AttemptID   string         `json:"attempt_id"`
	ExpectedSHA string         `json:"expected_sha256"`
	ByteSize    int64          `json:"byte_size"`
}

type runtimeLaunch struct {
	Schema     int    `json:"schema"`
	UpdateID   string `json:"update_id"`
	RequestSHA string `json:"request_sha256"`
	LockDevice uint64 `json:"lock_device"`
	LockInode  uint64 `json:"lock_inode"`
}

type RuntimeResult struct {
	UpdateID         string `json:"update_id"`
	ControlCommitted bool   `json:"control_committed"`
	StopConfirmed    bool   `json:"stop_confirmed"`
	CleanupConfirmed bool   `json:"cleanup_confirmed"`
	Reason           string `json:"reason,omitempty"`
}

// Fixture execution requires a separate marked store and cannot initialize product definitions.
func (s *Store) RunFixture(ctx context.Context, manifestPath, directory, id string) (RuntimeResult, error) {
	var result RuntimeResult
	m, err := ReadRuntimeManifest(manifestPath)
	if err != nil {
		return result, err
	}
	var marker string
	if s.db.QueryRow("SELECT value FROM filegate_update_fixture WHERE id=1").Scan(&marker) != nil || marker != "synthetic-no-product-adoption" {
		return result, Invalid
	}
	now, err := ReadClock()
	if err != nil {
		return result, err
	}
	c, err := s.Read(now)
	if err != nil || c.Binding != (Binding{LibrarySHA256: m.LibrarySHA256, FixtureOnly: true}) || c.Definition != nil {
		return result, Invalid
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !identifier.MatchString(id) {
		return result, Invalid
	}
	if _, err = os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		return result, Invalid
	}
	var pending int64
	if s.db.QueryRow("SELECT coalesce(sum(reserved_bytes),0) FROM update_attempts").Scan(&pending) != nil || pending < 0 || pending > (1<<62)-WorkspaceReservation {
		return result, Invalid
	}
	if err = runtimeCapacity(filepath.Dir(directory), pending+WorkspaceReservation); err != nil {
		return result, err
	}
	if _, err = s.db.Exec("CREATE TABLE IF NOT EXISTS update_fixture_runtime(update_id TEXT PRIMARY KEY,directory TEXT NOT NULL UNIQUE,state TEXT NOT NULL)"); err != nil {
		return result, err
	}
	if _, err = s.db.Exec("INSERT INTO update_fixture_runtime VALUES(?,?,'PLANNED')", id, directory); err != nil {
		return result, err
	}
	_, attempt, err := s.Begin(id, now)
	if err != nil {
		return result, err
	}
	if attempt.ID != id {
		return result, Busy
	}
	result.UpdateID = id
	if _, err = s.db.Exec("UPDATE update_fixture_runtime SET state='RESERVED' WHERE update_id=? AND state='PLANNED'", id); err != nil {
		return result, err
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return result, err
	}
	if err = runtimeSyncDirectory(filepath.Dir(directory)); err != nil {
		return result, err
	}
	now, err = ReadClock()
	if err != nil {
		return result, err
	}
	restore, err := s.Restore(id, now)
	if err != nil {
		return result, err
	}
	payload := encoded(restore)
	digest := sha256.Sum256(payload)
	manifestSHA, err := runtimeFileSHA(manifestPath)
	if err != nil {
		return result, err
	}
	r := runtimeRequest{1, fixtureRuntimeProfile, true, attempt, restore, m.LibrarySHA256, manifestSHA,
		"update_" + id, id, hex.EncodeToString(digest[:]), int64(len(payload))}
	if err = runtimeWrite(filepath.Join(directory, "request.json"), r); err != nil {
		return result, err
	}
	lock, err := os.OpenFile(filepath.Join(directory, "producer.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	var identity unix.Stat_t
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil || unix.Fstat(int(lock.Fd()), &identity) != nil || runtimeSyncFile(lock) != nil {
		return result, Invalid
	}
	requestSHA, err := runtimeFileSHA(filepath.Join(directory, "request.json"))
	if err != nil {
		return result, err
	}
	if err = runtimeWrite(filepath.Join(directory, "launch-intent.json"), runtimeLaunch{1, id, requestSHA, uint64(identity.Dev), identity.Ino}); err != nil {
		return result, err
	}
	if _, err = s.db.Exec("UPDATE update_fixture_runtime SET state='STARTING' WHERE update_id=? AND state='RESERVED'", id); err != nil {
		return result, err
	}
	err = s.executeRuntime(ctx, manifestPath, m, directory, r, lock, nil)
	lock.Close()
	if err != nil {
		result.Reason = err.Error()
		if now, clockErr := ReadClock(); clockErr == nil {
			_, _ = s.Stop(id, "INTERRUPTED", now)
		}
	}
	settled, recoveryErr := s.finishFixture(manifestPath, m, directory, r)
	if recoveryErr != nil {
		return result, recoveryErr
	}
	settled.Reason = result.Reason
	return settled, err
}

func runtimeCapacity(path string, reserved int64) error {
	var info unix.Statfs_t
	if unix.Statfs(path, &info) != nil || info.Bsize <= 0 {
		return Error("RESOURCE_MONITOR_FAILED")
	}
	if uint64(info.Bavail)*uint64(info.Bsize) < uint64(reserved+(2<<30)) {
		return Error("HOST_RESOURCE_PRESSURE")
	}
	return nil
}

func (s *Store) executeRuntime(ctx context.Context, manifestPath string, m RuntimeManifest, directory string, r runtimeRequest, lock *os.File, capacity func(int64) error) error {
	cmd := exec.Command(m.Runner, "--manifest", manifestPath, "--request", filepath.Join(directory, "request.json"), "--out", filepath.Join(directory, "output"), "--startup-lock-fd", "3")
	cmd.Dir, cmd.ExtraFiles, cmd.Stderr = m.Workspace, []*os.File{lock}, io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	output, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer output.Close()
	cmd.Stdout = writer
	err = cmd.Start()
	writer.Close()
	if err != nil {
		return err
	}
	stop := sync.OnceFunc(func() { input.Close() })
	monitorContext, cancelMonitor := context.WithCancel(context.Background())
	monitored := s.Monitor(monitorContext, r.Attempt, func(string) { stop() })
	defer func() { cancelMonitor(); <-monitored }()
	events := make(chan []byte, 8)
	readDone := make(chan struct{})
	defer close(readDone)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			select {
			case events <- line:
			case <-readDone:
				return
			}
		}
	}()
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var cause error
	var stopAt time.Time
	rawWritten := int64(0)
	committed, finished := false, false
	for wait != nil || events != nil {
		select {
		case <-ctx.Done():
			if cause == nil {
				cause = context.Cause(ctx)
			}
			stop()
			ctx = context.Background()
		case <-ticker.C:
			now, clockErr := ReadClock()
			if clockErr != nil {
				cause = ClockUncertain
				stop()
			} else if deadline(r.Attempt, now) != nil {
				cause = Timeout
				stop()
			}
			written := rawWritten
			if cause == nil && r.Profile == normalRuntimeProfile {
				written, cause = runtimeWritten(directory, r)
			}
			if cause == nil && capacity != nil {
				cause = capacity(written)
			}
			if cause == nil && capacity == nil {
				var pending int64
				if s.db.QueryRow("SELECT coalesce(sum(reserved_bytes),0) FROM update_attempts").Scan(&pending) != nil || pending < written {
					cause = Error("RESOURCE_MONITOR_FAILED")
				} else {
					cause = runtimeCapacity(directory, pending-written)
				}
			}
			if cause == nil {
				if _, err := io.WriteString(input, "heartbeat\n"); err != nil {
					stop()
					if !committed {
						cause = Error("INTERRUPTED")
					}
				}
			}
			if cause != nil {
				stop()
				if stopAt.IsZero() {
					stopAt = time.Now()
				}
				if time.Since(stopAt) >= 35*time.Second {
					return Error("VM_STOP_FAILED")
				}
			}
		case processErr := <-wait:
			if processErr != nil && cause == nil {
				cause = Error("INTERRUPTED")
			}
			wait = nil
		case line, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			var event struct {
				Event string `json:"event"`
			}
			if runtimeJSON(line, &event) != nil {
				cause = Invalid
				stop()
				continue
			}
			switch event.Event {
			case "PREPARING":
			case "RUNNING":
				rawWritten = 4 << 30
			case "FINAL_READY":
				if committed {
					cause = Invalid
					stop()
					continue
				}
				body, e := runtimeRead(filepath.Join(directory, "output/final.json"), 1<<20)
				now, clockErr := ReadClock()
				if e == nil {
					e = clockErr
				}
				if e == nil {
					_, e = s.Final(r.Attempt.ID, body, now)
				}
				if e != nil {
					cause = e
					stop()
					continue
				}
				committed = true
				if _, e = io.WriteString(input, "final-accepted\n"); e != nil {
					if cause == nil {
						cause = Error("INTERRUPTED")
					}
					stop()
				}
			case "FINISHED":
				finished = true
				stop()
			default:
				cause = Invalid
				stop()
			}
		}
	}
	if !finished && cause == nil {
		cause = Error("INTERRUPTED")
	}
	if !committed && cause == nil {
		cause = Unknown
	}
	if cause != nil {
		now, err := ReadClock()
		if err == nil {
			_, _ = s.Stop(r.Attempt.ID, runtimeReason(cause), now)
		}
	}
	return cause
}
