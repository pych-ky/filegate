package hostvm

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

func ValidateProducerLock(fd int, requestPath string, cleanup bool) error {
	if fd != 3 && !cleanup {
		return Error("STARTUP_LOCK_REQUIRED")
	}
	intent, _, e := Read(filepath.Join(filepath.Dir(requestPath), "launch-intent.json"), RequestLimit)
	if e != nil {
		return e
	}
	req, b, e := Read(requestPath, RequestLimit)
	if e != nil {
		return e
	}
	if Str(intent, "request_sha256") != HashBytes(b) {
		return Error("STARTUP_INTENT_MISMATCH")
	}
	if Str(req, "profile") == "filegate-official-update-v1" || Str(req, "profile") == "filegate-update-fixture-v1" {
		if !Fields(intent, "schema", "update_id", "request_sha256", "lock_device", "lock_inode") || Int(intent, "schema") != 1 || intent["update_id"] != req["attempt_id"] {
			return Error("UPDATE_PRODUCER_LOCK_INVALID")
		}
	} else {
		if !Fields(intent, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "request_sha256", "lock_device", "lock_inode") || Int(intent, "schema") != 2 && (!cleanup || Int(intent, "schema") != 1) || intent["job_id"] != req["job_id"] || intent["attempt_id"] != req["attempt_id"] || intent["input_sha256"] != req["expected_sha256"] || !Equal(intent["byte_size"], req["byte_size"]) {
			return Error("STARTUP_INTENT_MISMATCH")
		}
	}
	var info, path unix.Stat_t
	if unix.Fstat(fd, &info) != nil || unix.Lstat(filepath.Join(filepath.Dir(requestPath), "producer.lock"), &path) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&07777 != 0600 || info.Size != 0 || !SameDirectory(info, Object{"device": intent["lock_device"], "inode": intent["lock_inode"]}) || info.Dev != path.Dev || info.Ino != path.Ino {
		return Error("STARTUP_LOCK_CHANGED")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	unix.CloseOnExec(fd)
	return nil
}
func RecoveryLock(out string) (*os.File, error) {
	if missing(filepath.Join(filepath.Dir(out), "launch-intent.json")) {
		return nil, nil
	}
	fd, e := unix.Open(filepath.Join(filepath.Dir(out), "producer.lock"), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "producer-lock")
	until := time.Now().Add(34 * time.Second)
	for {
		e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !time.Now().Before(until) {
			f.Close()
			return nil, Error("PRODUCER_STILL_ACTIVE")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e = ValidateProducerLock(fd, filepath.Join(filepath.Dir(out), "request.json"), true); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func RunnerLock(out string, wait ...bool) (*os.File, error) {
	fd, e := unix.Open(filepath.Join(out, "runner.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "runner-lock")
	if _, e = Owned(filepath.Join(out, "runner.lock"), unix.S_IFREG, 0600); e != nil {
		f.Close()
		return nil, e
	}
	until := time.Now()
	if len(wait) > 0 && wait[0] {
		until = until.Add(34 * time.Second)
	}
	for {
		if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e == nil {
			return f, nil
		}
		if !time.Now().Before(until) {
			f.Close()
			return nil, Error("RUNNER_STILL_ACTIVE")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func (r *Runtime) ResourceIntent(out string, req Object, profile Profile) (Object, error) {
	if profile != ScanProfile && profile != UpdateProfile {
		return nil, Error("NATIVE_PROFILE_INVALID")
	}
	run, e := RandomPath("filegate-vm-")
	if e != nil {
		return nil, e
	}
	pending := filepath.Join(r.State, "active-vm."+Str(req, "attempt_id")+".pending")
	if !missing(run) || !missing(pending) {
		return nil, Error("RESOURCE_PATH_ALREADY_EXISTS")
	}
	slot := Object{"schema": 1, "broker_pid": os.Getpid(), "output_directory": out, "status": "ACTIVE"}
	body, _ := Encoded(slot)
	value := Merge(Binding(req), Object{"run_directory": run, "slot_value": slot, "slot_sha256": HashBytes(body), "slot_pending": pending})
	_, e = WriteNew(filepath.Join(out, "resource-intent.json"), value)
	return value, e
}
func (r *Runtime) ReadResources(out string, req Object) (Object, error) {
	v, _, e := Read(filepath.Join(out, "resource-intent.json"), RequestLimit)
	if e != nil {
		return nil, e
	}
	if e = Bound(v, req); e != nil {
		return nil, e
	}
	slot := Map(v, "slot_value")
	body, _ := Encoded(slot)
	if !Fields(v, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "run_directory", "slot_value", "slot_sha256", "slot_pending") || !runPattern.MatchString(Str(v, "run_directory")) || !Fields(slot, "schema", "broker_pid", "output_directory", "status") || Int(slot, "schema") != 1 || Int(slot, "broker_pid") <= 1 || Str(slot, "output_directory") != out || Str(slot, "status") != "ACTIVE" || HashBytes(body) != Str(v, "slot_sha256") || Str(v, "slot_pending") != filepath.Join(r.State, "active-vm."+Str(req, "attempt_id")+".pending") {
		return nil, Error("RESOURCE_SCOPE_INVALID")
	}
	return v, nil
}

type Slot struct {
	File     *os.File
	Intent   string
	Identity unix.Stat_t
}

func (r *Runtime) RecoverySlot() (*os.File, error) {
	if e := os.MkdirAll(r.State, 0700); e != nil {
		return nil, e
	}
	if _, e := Owned(r.State, unix.S_IFDIR, 0700); e != nil {
		return nil, e
	}
	fd, e := unix.Open(filepath.Join(r.State, "vm-slot.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "vm-slot-recovery")
	if _, e = Owned(filepath.Join(r.State, "vm-slot.lock"), unix.S_IFREG, 0600); e != nil {
		f.Close()
		return nil, e
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

func (s *Slot) Close() error {
	if s == nil || s.File == nil {
		return nil
	}
	e := s.File.Close()
	s.File = nil
	return e
}
func (r *Runtime) AcquireSlot(out string, req, resources Object) (*Slot, error) {
	if e := os.MkdirAll(r.State, 0700); e != nil {
		return nil, e
	}
	if _, e := Owned(r.State, unix.S_IFDIR, 0700); e != nil {
		return nil, e
	}
	fd, e := unix.Open(filepath.Join(r.State, "vm-slot.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "vm-slot")
	fail := func(e error) (*Slot, error) { f.Close(); return nil, e }
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(e)
	}
	intent := filepath.Join(r.State, "active-vm.json")
	if !missing(intent) {
		return fail(Error("RUNTIME_RECOVERY_REQUIRED"))
	}
	body, _ := Encoded(resources["slot_value"])
	pending := Str(resources, "slot_pending")
	if e = create(pending, body, 0600); e != nil {
		return fail(e)
	}
	if e = os.Link(pending, intent); e != nil {
		return fail(e)
	}
	if e = SyncDirectory(r.State); e != nil {
		return fail(e)
	}
	var info unix.Stat_t
	if e = unix.Lstat(intent, &info); e != nil {
		return fail(e)
	}
	if e = os.Remove(pending); e != nil {
		return fail(e)
	}
	if e = SyncDirectory(r.State); e != nil {
		return fail(e)
	}
	return &Slot{File: f, Intent: intent, Identity: info}, nil
}
func CreateRun(resources Object) (string, error) {
	run := Str(resources, "run_directory")
	if !runPattern.MatchString(run) {
		return "", Error("RESOURCE_SCOPE_INVALID")
	}
	if e := os.Mkdir(run, 0700); e != nil {
		return "", e
	}
	return run, SyncDirectory(filepath.Dir(run))
}
func CaptureSlot(out string, slot *Slot, req Object) error {
	v, b, e := Read(slot.Intent, ControlLimit)
	if e != nil {
		return e
	}
	s, e := Owned(slot.Intent, unix.S_IFREG, 0600)
	if e != nil || s.Dev != slot.Identity.Dev || s.Ino != slot.Identity.Ino || Str(v, "output_directory") != out || Int(v, "broker_pid") != int64(os.Getpid()) || Str(v, "status") != "ACTIVE" {
		return Error("SLOT_OWNER_CHANGED")
	}
	if e = SyncDirectory(filepath.Dir(slot.Intent)); e != nil {
		return e
	}
	_, e = WriteOnce(filepath.Join(out, "slot-owner.json"), Merge(Binding(req), Object{"device": uint64(s.Dev), "inode": s.Ino, "sha256": HashBytes(b), "output_directory": out}))
	return e
}
func (r *Runtime) ReleaseSlot(out string, req Object) error {
	owner, _, e := Read(filepath.Join(out, "slot-owner.json"), ControlLimit)
	if e != nil {
		return e
	}
	if e = Bound(owner, req); e != nil {
		return e
	}
	if Str(owner, "output_directory") != out {
		return Error("SLOT_OWNER_CHANGED")
	}
	path := filepath.Join(r.State, "active-vm.json")
	v, b, e := Read(path, ControlLimit)
	if os.IsNotExist(e) {
		return SyncDirectory(r.State)
	}
	if e != nil {
		return e
	}
	s, e := Owned(path, unix.S_IFREG, 0600)
	if e != nil || !SameDirectory(s, owner) || HashBytes(b) != Str(owner, "sha256") || Str(v, "output_directory") != out {
		return Error("FOREIGN_VM_SLOT_OWNER")
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	return SyncDirectory(r.State)
}
