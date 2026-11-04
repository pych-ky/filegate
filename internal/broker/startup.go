package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type startupIntent struct {
	Schema        int    `json:"schema"`
	JobID         string `json:"job_id"`
	AttemptID     string `json:"attempt_id"`
	InputSHA256   string `json:"input_sha256"`
	ByteSize      int64  `json:"byte_size"`
	RequestSHA256 string `json:"request_sha256"`
	LockDevice    uint64 `json:"lock_device"`
	LockInode     uint64 `json:"lock_inode"`
}

func (b *Broker) prepareStartup(run *scanRun) (*os.File, error) {
	lock, err := openPrivate(filepath.Join(run.directory, "producer.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	var identity unix.Stat_t
	if err = unix.Fstat(int(lock.Fd()), &identity); err != nil {
		return nil, err
	}
	if err = syncFile(lock); err != nil {
		return nil, err
	}
	if err = syncDirectory(run.directory); err != nil {
		return nil, err
	}
	request, err := readPrivate(filepath.Join(run.directory, "request.json"), 16<<10)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(request)
	input := run.job.InputReceipt
	intent := startupIntent{Schema: 2, JobID: run.job.JobID, AttemptID: run.job.AttemptID,
		InputSHA256: input.SHA256, ByteSize: input.ByteSize, RequestSHA256: hex.EncodeToString(digest[:]),
		LockDevice: uint64(identity.Dev), LockInode: identity.Ino}
	if err = writePrivate(filepath.Join(run.directory, "launch-intent.json"), intent); err != nil {
		return nil, err
	}
	b.mu.Lock()
	result, err := b.db.Exec("UPDATE runtime_runs SET state='STARTING' WHERE attempt_id=? AND state='RESERVED'", run.job.AttemptID)
	b.mu.Unlock()
	if err != nil {
		return nil, storageError()
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return nil, failure("RECOVERY_REQUIRED", 503)
	}
	ok = true
	return lock, nil
}

// 起動許可前の状態、または継承lockの解放と出力未作成を、未起動の証拠にする。
func (b *Broker) recoverStartup(run *scanRun, state string) (bool, error) {
	authority := "reserved_not_dispatched"
	intentDigest := ""
	outputAbsent := true
	if state == "RESERVED" {
		if _, err := os.Lstat(run.directory); errors.Is(err, os.ErrNotExist) {
			if os.Mkdir(run.directory, 0700) != nil || syncDirectory(filepath.Dir(run.directory)) != nil {
				return true, failure("VM_STOP_FAILED", 503)
			}
		} else if err != nil {
			return true, failure("VM_STOP_FAILED", 503)
		}
	}
	if state != "RESERVED" {
		body, err := readPrivate(filepath.Join(run.directory, "launch-intent.json"), 16<<10)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		var intent startupIntent
		if err != nil || strictJSON(body, &intent) != nil || run.job.InputReceipt == nil {
			return true, failure("VM_STOP_FAILED", 503)
		}
		if _, err = requiredFields(body, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "request_sha256", "lock_device", "lock_inode"); err != nil {
			return true, failure("VM_STOP_FAILED", 503)
		}
		if intent.Schema == 1 {
			return false, nil
		}
		input := run.job.InputReceipt
		if intent.Schema != 2 || intent.JobID != run.job.JobID || intent.AttemptID != run.job.AttemptID || intent.InputSHA256 != input.SHA256 || intent.ByteSize != input.ByteSize || !validDigest(intent.RequestSHA256) {
			return true, failure("VM_STOP_FAILED", 503)
		}
		request, err := readPrivate(filepath.Join(run.directory, "request.json"), 16<<10)
		digest := sha256.Sum256(request)
		if err != nil || hex.EncodeToString(digest[:]) != intent.RequestSHA256 {
			return true, failure("VM_STOP_FAILED", 503)
		}
		lock, err := openPrivate(filepath.Join(run.directory, "producer.lock"), os.O_RDWR, 0)
		if err != nil {
			return true, failure("VM_STOP_FAILED", 503)
		}
		defer lock.Close()
		var identity unix.Stat_t
		if unix.Fstat(int(lock.Fd()), &identity) != nil || uint64(identity.Dev) != intent.LockDevice || identity.Ino != intent.LockInode || identity.Size != 0 || identity.Mode&0777 != 0600 {
			return true, failure("VM_STOP_FAILED", 503)
		}
		deadline := time.Now().Add(34 * time.Second)
		for {
			err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if err == nil {
				break
			}
			if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
				return true, failure("VM_STOP_FAILED", 503)
			}
			time.Sleep(50 * time.Millisecond)
		}
		output := filepath.Join(run.directory, "output")
		if _, err = os.Lstat(output); err == nil {
			outputAbsent = false
			if _, err = os.Lstat(filepath.Join(output, "resource-intent.json")); err == nil {
				return false, nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return true, failure("VM_STOP_FAILED", 503)
			}
			entries, err := os.ReadDir(output)
			if err != nil {
				return true, failure("VM_STOP_FAILED", 503)
			}
			for _, entry := range entries {
				if entry.Name() != "runner.lock" && entry.Name() != "resource-intent.json.pending" {
					return true, failure("VM_STOP_FAILED", 503)
				}
				if _, err = readPrivate(filepath.Join(output, entry.Name()), 16<<10); err != nil {
					return true, failure("VM_STOP_FAILED", 503)
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return true, failure("VM_STOP_FAILED", 503)
		}
		digest = sha256.Sum256(body)
		intentDigest = hex.EncodeToString(digest[:])
		authority = "producer_exited_before_resources"
	}
	allowed := map[string]int64{"request.json": 16 << 10, "producer.lock": 0, "launch-intent.json": 16 << 10, "startup-recovery.json": 16 << 10, "startup-recovery.json.pending": 16 << 10}
	entries, err := os.ReadDir(run.directory)
	if err != nil {
		return true, failure("VM_STOP_FAILED", 503)
	}
	for _, entry := range entries {
		if entry.Name() == "output" && !outputAbsent {
			continue
		}
		limit, known := allowed[entry.Name()]
		if !known {
			return true, failure("VM_STOP_FAILED", 503)
		}
		if _, err = readPrivate(filepath.Join(run.directory, entry.Name()), limit); err != nil {
			return true, failure("VM_STOP_FAILED", 503)
		}
	}
	proof := struct {
		Schema             int    `json:"schema"`
		JobID              string `json:"job_id"`
		AttemptID          string `json:"attempt_id"`
		Authority          string `json:"authority"`
		LaunchIntentSHA256 string `json:"launch_intent_sha256"`
		OutputAbsent       bool   `json:"output_absent"`
	}{1, run.job.JobID, run.job.AttemptID, authority, intentDigest, outputAbsent}
	path := filepath.Join(run.directory, "startup-recovery.json")
	body, err := readPrivate(path, 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		pending := path + ".pending"
		if err = os.Remove(pending); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, err
		}
		if err = writePrivate(pending, proof); err != nil {
			return true, err
		}
		if err = os.Rename(pending, path); err != nil {
			return true, err
		}
		err = syncDirectory(run.directory)
	} else {
		expected, _ := json.Marshal(proof)
		if err != nil || !bytes.Equal(body, expected) {
			return true, failure("VM_STOP_FAILED", 503)
		}
		err = syncDirectory(run.directory)
	}
	return true, err
}
