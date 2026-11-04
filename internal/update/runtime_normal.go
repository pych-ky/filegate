package update

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func (s *Store) runtimeRecord(r *Runtime, id string) (string, string, error) {
	if r == nil || r.current() != nil || !identifier.MatchString(id) {
		return "", "", Invalid
	}
	var directory, state, binding string
	if err := s.db.QueryRow("SELECT directory,state,manifest_sha256 FROM update_runtime WHERE update_id=?", id).Scan(&directory, &state, &binding); err != nil {
		return "", "", err
	}
	if binding != r.digest || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", "", Invalid
	}
	return directory, state, nil
}

func (s *Store) ExecuteRuntime(ctx context.Context, runtime *Runtime, id string, capacity func(int64) error) (RuntimeResult, error) {
	result := RuntimeResult{UpdateID: id}
	directory, state, err := s.runtimeRecord(runtime, id)
	if err != nil || state != "RESERVED" {
		return result, Invalid
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return result, err
	}
	if err = runtimeSyncDirectory(filepath.Dir(directory)); err != nil {
		return result, err
	}
	now, err := ReadClock()
	if err != nil {
		return result, err
	}
	restore, err := s.Restore(id, now)
	if err != nil {
		return result, err
	}
	a, err := s.Attempt(id)
	if err != nil {
		return result, err
	}
	payload := encoded(restore)
	m := runtime.manifest.RuntimeManifest
	r := runtimeRequest{2, normalRuntimeProfile, false, a, restore, m.LibrarySHA256, runtime.digest,
		"update_" + id, id, sha256Text(payload), int64(len(payload))}
	cache, err := loadDefinitionCache(s.db, id)
	if err != nil {
		return result, err
	}
	if err = currentDefinitionCache(cache, directory, a); err != nil {
		return result, err
	}
	if err = runtimeWrite(filepath.Join(directory, "request.json"), normalRuntimeRequest{r, cache}); err != nil {
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
	if err = runtime.current(); err != nil {
		return result, err
	}
	if _, err = s.db.Exec("UPDATE update_runtime SET state='STARTING' WHERE update_id=? AND state='RESERVED'", id); err != nil {
		return result, err
	}
	err = s.executeRuntime(ctx, runtime.path, m, directory, r, lock, capacity)
	lock.Close()
	if err != nil {
		if now, clockErr := ReadClock(); clockErr == nil {
			_, _ = s.Stop(id, runtimeReason(err), now)
		}
	}
	settled, cleanupErr := s.finishRuntime(runtime.path, m, directory, r, "update_runtime")
	if cleanupErr != nil {
		return settled, cleanupErr
	}
	if err != nil {
		settled.Reason = runtimeReason(err)
	}
	return settled, err
}

func runtimeReason(err error) string {
	if err == nil {
		return ""
	}
	switch err.Error() {
	case "UPDATE_TIMEOUT", "CANCELLED", "RESOURCE_MONITOR_FAILED", "HOST_RESOURCE_PRESSURE", "WORKSPACE_IO_ERROR", "UPDATE_CLOCK_UNCERTAIN":
		return err.Error()
	case "DISK_PRESSURE":
		return "HOST_RESOURCE_PRESSURE"
	default:
		return "INTERRUPTED"
	}
}

func (s *Store) AbortRuntime(runtime *Runtime, id, reason string) error {
	if _, _, err := s.runtimeRecord(runtime, id); err != nil {
		return err
	}
	now, err := ReadClock()
	if err != nil {
		return err
	}
	_, err = s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if a.AdoptionApproved || a.CleanupConfirmed {
			return nil
		}
		if a.Reason == "" {
			a.Reason = runtimeReason(Error(reason))
		}
		return saveAttempt(tx, a)
	})
	return err
}

func (s *Store) RecoverRuntime(runtime *Runtime, id string) (RuntimeResult, error) {
	result := RuntimeResult{UpdateID: id}
	directory, state, err := s.runtimeRecord(runtime, id)
	if err != nil {
		return result, err
	}
	a, err := s.Attempt(id)
	if err != nil {
		return result, err
	}
	if state == "FINISHED" && a.CleanupConfirmed {
		return RuntimeResult{id, a.ControlCommitted, a.StopConfirmed, true, a.Reason}, nil
	}
	if a.AdoptionApproved {
		err = s.completeAdoption(runtime, directory, id)
		a, readErr := s.Attempt(id)
		if err == nil {
			err = readErr
		}
		return RuntimeResult{id, a.ControlCommitted, a.StopConfirmed, a.CleanupConfirmed, a.Reason}, err
	}
	if state == "STOPPED" {
		if err = s.AbortRuntime(runtime, id, "INTERRUPTED"); err != nil {
			return result, err
		}
		err = s.discardRuntimeCandidates(runtime, directory, id)
		a, readErr := s.Attempt(id)
		if err == nil {
			err = readErr
		}
		return RuntimeResult{id, a.ControlCommitted, a.StopConfirmed, a.CleanupConfirmed, a.Reason}, err
	}
	if state == "RESERVED" {
		entries, e := os.ReadDir(directory)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return result, e
		}
		for _, entry := range entries {
			limit, allowed := map[string]int64{"request.json": 16384, "producer.lock": 0, "launch-intent.json": 16384}[entry.Name()]
			if !allowed {
				return result, Error("VM_STOP_FAILED")
			}
			if _, e = runtimeRead(filepath.Join(directory, entry.Name()), limit); e != nil {
				return result, e
			}
		}
		now, e := ReadClock()
		if e != nil {
			return result, e
		}
		if _, e = s.Stopped(id, true, now); e != nil {
			return result, e
		}
		_, e = s.db.Exec("UPDATE update_runtime SET state='FINISHED' WHERE update_id=?", id)
		return RuntimeResult{id, false, true, true, a.Reason}, e
	}
	body, err := runtimeRead(filepath.Join(directory, "request.json"), 16384)
	var request normalRuntimeRequest
	if err != nil || runtimeJSON(body, &request) != nil || request.Profile != normalRuntimeProfile || request.FixtureOnly ||
		request.ManifestSHA != runtime.digest || request.Library != runtime.LibrarySHA256() || request.Attempt.ID != id || request.AttemptID != id ||
		request.JobID != "update_"+id || request.Restore.UpdateID != id || request.Attempt.BaseGeneration != a.BaseGeneration {
		return result, Invalid
	}
	if s.validateDefinitionCacheRequest(body, request) != nil {
		return result, Invalid
	}
	result, err = s.finishRuntime(runtime.path, runtime.manifest.RuntimeManifest, directory, request.runtimeRequest, "update_runtime")
	if result.StopConfirmed {
		var state string
		if s.db.QueryRow("SELECT state FROM update_runtime WHERE update_id=?", id).Scan(&state) == nil && state == "STOPPED" {
			cleanupErr := s.discardRuntimeCandidates(runtime, directory, id)
			if cleanupErr != nil {
				return result, cleanupErr
			}
			result.CleanupConfirmed = true
		}
	}
	return result, err
}
