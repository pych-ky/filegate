package hostvm

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

func producerIntent(requestPath string) (Object, Object, error) {
	intent, _, e := Read(filepath.Join(filepath.Dir(requestPath), "launch-intent.json"), RequestLimit)
	if e != nil {
		return nil, nil, e
	}
	req, b, e := Read(requestPath, RequestLimit)
	if e != nil {
		return nil, nil, e
	}
	if Str(intent, "request_sha256") != HashBytes(b) {
		return nil, nil, Error("STARTUP_INTENT_MISMATCH")
	}
	if Str(req, "profile") == "filegate-official-update-v1" || Str(req, "profile") == "filegate-update-fixture-v1" {
		if !Fields(intent, "schema", "update_id", "request_sha256", "lock_device", "lock_inode") || Int(intent, "schema") != 1 || intent["update_id"] != req["attempt_id"] {
			return nil, nil, Error("UPDATE_PRODUCER_LOCK_INVALID")
		}
	} else {
		if !Fields(intent, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "request_sha256", "lock_device", "lock_inode") || Int(intent, "schema") != 2 && Int(intent, "schema") != 1 || intent["job_id"] != req["job_id"] || intent["attempt_id"] != req["attempt_id"] || intent["input_sha256"] != req["expected_sha256"] || !Equal(intent["byte_size"], req["byte_size"]) {
			return nil, nil, Error("STARTUP_INTENT_MISMATCH")
		}
	}
	return intent, req, nil
}
func producerLockIdentity(fd int, requestPath string) (unix.Stat_t, error) {
	var info, path unix.Stat_t
	if unix.Fstat(fd, &info) != nil || unix.Lstat(filepath.Join(filepath.Dir(requestPath), "producer.lock"), &path) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&07777 != 0600 || info.Size != 0 || info.Dev != path.Dev || info.Ino != path.Ino {
		return info, Error("STARTUP_LOCK_CHANGED")
	}
	return info, nil
}
func ValidateProducerLock(fd int, requestPath string, cleanup bool) error {
	if fd != 3 && !cleanup {
		return Error("STARTUP_LOCK_REQUIRED")
	}
	intent, req, e := producerIntent(requestPath)
	if e != nil {
		return e
	}
	if Str(req, "profile") != "filegate-official-update-v1" && Str(req, "profile") != "filegate-update-fixture-v1" && !cleanup && Int(intent, "schema") != 2 {
		return Error("STARTUP_INTENT_MISMATCH")
	}
	info, e := producerLockIdentity(fd, requestPath)
	if e != nil || !SameDirectory(info, Object{"device": intent["lock_device"], "inode": intent["lock_inode"]}) {
		return Error("STARTUP_LOCK_CHANGED")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	unix.CloseOnExec(fd)
	return nil
}
func (r *Runtime) previousBootResources(out string, req Object, profile Profile) (Object, error) {
	resources, e := r.ReadResources(out, req)
	if e != nil {
		return nil, e
	}
	proof, e := r.PreviousBootProof(out, req, profile)
	if e != nil {
		return nil, e
	}
	if Str(resources, "run_directory") != Str(proof, "run_directory") || profile == UpdateProfile && Str(Map(Map(req, "attempt"), "started"), "boot") != Str(proof, "previous_boot_uuid") {
		return nil, Error("NATIVE_PREVIOUS_BOOT_RESOURCE_INVALID")
	}
	return resources, nil
}
func (r *Runtime) RecoveryLock(out string, req Object, profile Profile) (*os.File, error) {
	if missing(filepath.Join(filepath.Dir(out), "launch-intent.json")) {
		return nil, nil
	}
	requestPath := filepath.Join(filepath.Dir(out), "request.json")
	fd, e := unix.Open(filepath.Join(filepath.Dir(out), "producer.lock"), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "producer-lock")
	fail := func(e error) (*os.File, error) { f.Close(); return nil, e }
	until := time.Now().Add(34 * time.Second)
	for {
		e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !time.Now().Before(until) {
			return fail(Error("PRODUCER_STILL_ACTIVE"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	intent, actual, e := producerIntent(requestPath)
	if e != nil {
		return fail(e)
	}
	if !Equal(actual, req) {
		return fail(Error("RECOVERY_REQUEST_MISMATCH"))
	}
	if e = ValidateProducerLock(fd, requestPath, true); e == nil {
		return f, nil
	}
	if e.Error() != "STARTUP_LOCK_CHANGED" {
		return fail(e)
	}
	info, identityErr := producerLockIdentity(fd, requestPath)
	device, deviceOK := Uint(intent, "lock_device")
	inode, inodeOK := Uint(intent, "lock_inode")
	if identityErr != nil || !deviceOK || !inodeOK || device == 0 || inode == 0 || uint64(info.Dev) == device || info.Ino != inode {
		return fail(e)
	}
	if _, e = r.previousBootResources(out, req, profile); e != nil {
		return fail(e)
	}
	current, e := producerLockIdentity(fd, requestPath)
	if e != nil || !SameIdentity(info, current) {
		return fail(Error("STARTUP_LOCK_CHANGED"))
	}
	currentIntent, currentRequest, e := producerIntent(requestPath)
	if e != nil || !Equal(currentIntent, intent) || !Equal(currentRequest, req) {
		return fail(Error("STARTUP_INTENT_MISMATCH"))
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
func (r *Runtime) ReleaseSlot(out string, req Object, profile Profile) error {
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
	if e != nil || HashBytes(b) != Str(owner, "sha256") || Str(v, "output_directory") != out {
		return Error("FOREIGN_VM_SLOT_OWNER")
	}
	if !SameDirectory(s, owner) {
		device, deviceOK := Uint(owner, "device")
		inode, inodeOK := Uint(owner, "inode")
		if !deviceOK || !inodeOK || device == 0 || inode == 0 || uint64(s.Dev) == device || s.Ino != inode {
			return Error("FOREIGN_VM_SLOT_OWNER")
		}
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		file := os.NewFile(uintptr(fd), "previous-boot-slot")
		defer file.Close()
		var opened unix.Stat_t
		if unix.Fstat(fd, &opened) != nil || !SameIdentity(s, opened) {
			return Error("FOREIGN_VM_SLOT_OWNER")
		}
		proof, _, e := Read(filepath.Join(out, "stop-proof.json"), ControlLimit)
		if e != nil || Str(proof, "kind") != "native_previous_boot" {
			return Error("FOREIGN_VM_SLOT_OWNER")
		}
		if _, e = r.StopProof(out, req, nil, profile); e != nil {
			return e
		}
		resources, e := r.previousBootResources(out, req, profile)
		if e != nil {
			return e
		}
		if !Equal(v, resources["slot_value"]) || Str(owner, "sha256") != Str(resources, "slot_sha256") {
			return Error("FOREIGN_VM_SLOT_OWNER")
		}
		currentBytes, e := ReadBytes(path, ControlLimit)
		current, ownedErr := Owned(path, unix.S_IFREG, 0600)
		var held unix.Stat_t
		if e != nil || ownedErr != nil || HashBytes(currentBytes) != HashBytes(b) || unix.Fstat(fd, &held) != nil || !SameIdentity(s, held) || !SameIdentity(held, current) {
			return Error("FOREIGN_VM_SLOT_OWNER")
		}
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	return SyncDirectory(r.State)
}
