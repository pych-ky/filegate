package hostvm

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)
var runPattern = regexp.MustCompile(`^/private/tmp/filegate-vm-[0-9a-f]{32}$`)
var controlPattern = regexp.MustCompile(`^/private/tmp/fgw-[0-9a-f]{32}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (r *Runtime) Clock() (uint64, error) {
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	b, e := exec.CommandContext(ctx, r.NativeBinary, "clock").Output()
	if e != nil {
		return 0, e
	}
	v, e := json.Number(strings.TrimSpace(string(b))).Int64()
	if e != nil || v < 0 {
		return 0, Error("CONTROL_CLOCK_INVALID")
	}
	return uint64(v), nil
}
func (r *Runtime) HostVersion() (Object, error) {
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	b, e := exec.CommandContext(ctx, "/usr/bin/sw_vers").Output()
	if e != nil {
		return nil, e
	}
	return Object{"os": string(b), "machine": hostMachine(), "uid": os.Getuid()}, nil
}
func (r *Runtime) NativePlatform() (Object, error) {
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	b, e := exec.CommandContext(ctx, r.NativeBinary, "platform").Output()
	if e != nil {
		return nil, e
	}
	return Decode(b)
}
func ProcessIdentity(m Object, role string) (Object, error) {
	pid, pok := Num(m["pid"])
	start, sok := Uint(m, "start_abstime")
	if !pok || pid <= 1 || pid >= 1<<31 || !sok || start == 0 {
		return nil, Error("PROCESS_IDENTITY_INVALID")
	}
	if role == "" {
		role = Str(m, "role")
	}
	return Object{"pid": pid, "start_abstime": start, "role": role}, nil
}
func IdentityReadback(identity Object) Object {
	row := Object{"identity": identity, "same_identity_live": nil}
	actual, e := NativeIdentity(int(Int(identity, "pid")))
	if e != nil {
		row["state"] = "measurement_failed"
		if errno, ok := e.(syscall.Errno); ok {
			row["error_number"] = int(errno)
		}
		return row
	}
	row["actual"] = actual
	if actual == nil {
		row["state"] = "absent"
		row["same_identity_live"] = false
	} else if !Equal(actual["start_abstime"], identity["start_abstime"]) {
		row["state"] = "pid_reused"
		row["same_identity_live"] = false
	} else if Int(actual, "exit_abstime") != 0 {
		row["state"] = "exited"
		row["same_identity_live"] = false
	} else {
		row["state"] = "live"
		row["same_identity_live"] = true
	}
	return row
}
func ReadbackAll(identities []Object) []any {
	rows := make([]any, 0, len(identities))
	for _, id := range identities {
		rows = append(rows, IdentityReadback(id))
	}
	return rows
}
func AllExited(rows []any) bool {
	if len(rows) == 0 {
		return false
	}
	for _, v := range rows {
		m, ok := v.(Object)
		if !ok || m["same_identity_live"] != false {
			return false
		}
	}
	return true
}
func validateOwnership(m Object) error {
	leader := Map(m, "leader")
	if !Fields(m, "schema", "kind", "leader", "command_sha256") || Int(m, "schema") != 1 || Str(m, "kind") != "prepare_process_group" && Str(m, "kind") != "native_bootstrap_group" || !digestPattern.MatchString(Str(m, "command_sha256")) || !Fields(leader, "pid", "start_abstime", "process_group", "uid") || Int(leader, "pid") <= 1 || Int(leader, "pid") >= 1<<31 || Int(leader, "process_group") != Int(leader, "pid") || Int(leader, "start_abstime") <= 0 || Int(leader, "uid") != int64(os.Getuid()) {
		return Error("CONTROL_OWNERSHIP_INVALID")
	}
	return nil
}
func ReadOwnership(path string) (Object, error) {
	m, _, e := Read(path, RequestLimit)
	if e != nil {
		return nil, e
	}
	return m, validateOwnership(m)
}
func WriteOwnership(path string, pid int, args []string) (Object, string, error) {
	kind, e := CheckedArguments(args)
	if e != nil {
		return nil, "", e
	}
	actual, e := NativeIdentity(pid)
	if e != nil || actual == nil || Int(actual, "process_group") != int64(pid) || Int(actual, "uid") != int64(os.Getuid()) || Int(actual, "exit_abstime") != 0 {
		return nil, "", Error("CONTROL_PREPARER_IDENTITY_INVALID")
	}
	leader := Object{}
	for _, k := range []string{"pid", "start_abstime", "process_group", "uid"} {
		leader[k] = actual[k]
	}
	b, _ := Canonical(args)
	value := Object{"schema": 1, "kind": kind, "leader": leader, "command_sha256": HashBytes(b)}
	if e = validateOwnership(value); e != nil {
		return nil, "", e
	}
	sha, e := WriteNew(path, value)
	return value, sha, e
}
func VerifyStopped(owner Object) (Object, error) {
	if e := validateOwnership(owner); e != nil {
		return nil, e
	}
	leader := Map(owner, "leader")
	back := IdentityReadback(leader)
	if back["same_identity_live"] == nil {
		return nil, Error("CONTROL_IDENTITY_UNAVAILABLE")
	}
	empty, e := GroupEmpty(int(Int(leader, "process_group")))
	if e != nil {
		return nil, e
	}
	return Object{"stop_verified": back["same_identity_live"] == false && empty, "leader_state": back["state"], "group_empty": empty}, nil
}
func CheckedArguments(args []string) (string, error) {
	if len(args) == 4 && args[0] == "/bin/launchctl" && args[1] == "bootstrap" && args[2] == "gui/"+itoa(os.Getuid()) && filepath.Base(args[3]) == "watchdog.plist" && controlPattern.MatchString(filepath.Dir(args[3])) {
		return "native_bootstrap_group", nil
	}
	self, e := os.Executable()
	if e != nil {
		return "", e
	}
	self, e = filepath.EvalSymlinks(self)
	if e != nil {
		return "", e
	}
	if len(args) == 0 || args[0] != self {
		return "", Error("CONTROL_COMMAND_SCOPE_INVALID")
	}
	switch filepath.Base(self) {
	case "filegate-vm":
		if len(args) == 6 && args[1] == "--prepare" && args[2] == "--run-directory" && runPattern.MatchString(args[3]) && args[4] == "--fixture" && fixtureAllowed(args[5]) {
			return "prepare_process_group", nil
		}
		if len(args) == 6 && args[1] == "--prepare" && args[2] == "--run-directory" && runPattern.MatchString(args[3]) && args[4] == "--request" && validRequestPath(args[5], "runtime", "attempt_") {
			return "prepare_process_group", nil
		}
	case "filegate-update":
		if len(args) == 8 && args[1] == "--prepare" && args[2] == "--manifest" && args[4] == "--request" && args[6] == "--run-directory" && filepath.IsAbs(args[3]) && filepath.Base(args[3]) == "update-runtime.json" && validRequestPath(args[5], "updates", "update_") && filepath.Dir(filepath.Dir(filepath.Dir(args[5]))) == filepath.Dir(args[3]) && runPattern.MatchString(args[7]) {
			return "prepare_process_group", nil
		}
		if len(args) == 8 && args[1] == "--prepare" && args[2] == "--manifest" && args[4] == "--request" && args[6] == "--run-directory" && runPattern.MatchString(args[7]) && validFixturePreparation(args[3], args[5], self) {
			return "prepare_process_group", nil
		}
	}
	return "", Error("CONTROL_COMMAND_SCOPE_INVALID")
}

func validFixturePreparation(manifestPath, requestPath, self string) bool {
	if !filepath.IsAbs(manifestPath) || filepath.Clean(manifestPath) != manifestPath || filepath.Base(manifestPath) != "update-runtime.json" || filepath.Base(filepath.Dir(manifestPath)) != "build" || filepath.Base(requestPath) != "request.json" {
		return false
	}
	root := filepath.Dir(filepath.Dir(manifestPath))
	state := filepath.Join(root, "state")
	for _, path := range []string{root, state, filepath.Dir(manifestPath), filepath.Dir(requestPath)} {
		canonical, e := filepath.EvalSymlinks(path)
		if e != nil || canonical != path {
			return false
		}
		if _, e = Owned(path, unix.S_IFDIR, 0700); e != nil {
			return false
		}
	}
	marker, e := ReadBytes(filepath.Join(state, "fixture-scope.txt"), 64)
	if e != nil || string(marker) != "filegate-update-fixture-v1\n" {
		return false
	}
	manifest, body, e := Read(manifestPath, 1<<20)
	if e != nil || !Fields(manifest, "schema", "profile", "fixture_only", "library_sha256", "workspace", "runner", "helper", "proof", "sha256") || Int(manifest, "schema") != 2 || Str(manifest, "profile") != "filegate-update-fixture-v1" || manifest["fixture_only"] != true || Str(manifest, "runner") != self || self != filepath.Join(Str(manifest, "workspace"), ".build/filegate-update") || !digestPattern.MatchString(Str(manifest, "library_sha256")) {
		return false
	}
	pins := Map(manifest, "sha256")
	actual, e := HashFile(self)
	if e != nil || len(pins) < 12 || len(pins) > 512 || Str(pins, self) != actual {
		return false
	}
	request, _, e := Read(requestPath, RequestLimit)
	if e != nil || !Fields(request, "schema", "profile", "fixture_only", "attempt", "restore", "library_sha256", "manifest_sha256", "job_id", "attempt_id", "expected_sha256", "byte_size") || Int(request, "schema") != 1 || Str(request, "profile") != "filegate-update-fixture-v1" || request["fixture_only"] != true || Str(request, "library_sha256") != Str(manifest, "library_sha256") || Str(request, "manifest_sha256") != HashBytes(body) {
		return false
	}
	id := Str(request, "attempt_id")
	if !regexp.MustCompile(`^update_[0-9a-f]{32}$`).MatchString(id) || Str(request, "job_id") != "update_"+id || Str(Map(request, "attempt"), "update_id") != id || Str(Map(request, "restore"), "update_id") != id || filepath.Dir(requestPath) != filepath.Join(state, "runtime-"+id) {
		return false
	}
	return true
}
func validRequestPath(path, parent, prefix string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "request.json" || filepath.Base(filepath.Dir(filepath.Dir(path))) != parent {
		return false
	}
	n := strings.TrimPrefix(filepath.Base(filepath.Dir(path)), prefix)
	if len(n) != 32 || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(n) {
		return false
	}
	actual, e := filepath.EvalSymlinks(path)
	return e == nil && actual == path
}
func GateMain(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "--gate-locked" {
		return false, 0
	}
	if len(args) < 4 || args[1] != "3" {
		return true, 2
	}
	unix.CloseOnExec(3)
	rest := args[2:]
	dispatch := ""
	if len(rest) >= 2 && rest[0] == "--dispatch" {
		dispatch = rest[1]
		rest = rest[2:]
	}
	kind, e := CheckedArguments(rest)
	if e != nil {
		return true, 2
	}
	if dispatch != "" && (kind != "native_bootstrap_group" || !filepath.IsAbs(dispatch) || filepath.Base(dispatch) != "native-bootstrap-dispatched.json") {
		return true, 2
	}
	var ack [3]byte
	if _, e = io.ReadFull(os.Stdin, ack[:]); e != nil || string(ack[:]) != "GO\n" {
		return true, 2
	}
	if dispatch != "" {
		if _, _, e = WriteOwnership(dispatch, os.Getpid(), rest); e != nil {
			return true, 2
		}
	}
	if e = syscall.Exec(rest[0], rest, os.Environ()); e != nil {
		return true, 2
	}
	return true, 0
}
func ControlledCommand(ctx context.Context, args []string, seconds int, ownershipPath, cwd string, producerFD int, dispatchPath string) (Object, error) {
	kind, e := CheckedArguments(args)
	if e != nil {
		return nil, e
	}
	if producerFD != 3 || seconds <= 0 || seconds > 600 {
		return nil, Error("CONTROL_PRODUCER_LOCK_INVALID")
	}
	if dispatchPath != "" && kind != "native_bootstrap_group" {
		return nil, Error("CONTROL_DISPATCH_SCOPE_INVALID")
	}
	self, e := os.Executable()
	if e != nil {
		return nil, e
	}
	gate := []string{"--gate-locked", "3"}
	if dispatchPath != "" {
		gate = append(gate, "--dispatch", dispatchPath)
	}
	gate = append(gate, args...)
	cmd := exec.Command(self, gate...)
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	duplicate, e := unix.Dup(producerFD)
	if e != nil {
		return nil, e
	}
	inherited := os.NewFile(uintptr(duplicate), "producer-lock")
	cmd.ExtraFiles = []*os.File{inherited}
	inR, inW, e := os.Pipe()
	if e != nil {
		inherited.Close()
		return nil, e
	}
	outR, outW, e := os.Pipe()
	if e != nil {
		inherited.Close()
		inR.Close()
		inW.Close()
		return nil, e
	}
	cmd.Stdin = inR
	cmd.Stdout = outW
	cmd.Stderr = outW
	started := time.Now()
	e = cmd.Start()
	inherited.Close()
	inR.Close()
	outW.Close()
	if e != nil {
		inW.Close()
		outR.Close()
		return nil, e
	}
	defer inW.Close()
	defer outR.Close()
	reaped := false
	status := 0
	stop := func() error {
		if reaped {
			return nil
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		time.Sleep(2 * time.Second)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil
	}
	wait := func(limit time.Duration) error {
		until := time.Now().Add(limit)
		for {
			var s unix.WaitStatus
			pid, e := unix.Wait4(cmd.Process.Pid, &s, unix.WNOHANG, nil)
			if e != nil {
				return e
			}
			if pid == cmd.Process.Pid {
				reaped = true
				if s.Signaled() {
					status = -int(s.Signal())
				} else {
					status = s.ExitStatus()
				}
				_ = cmd.Process.Release()
				return nil
			}
			if !time.Now().Before(until) {
				return Error("CONTROL_STOP_FAILED")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	defer func() {
		if !reaped {
			_ = stop()
			_ = wait(5 * time.Second)
		}
	}()
	owner, ownerSHA, e := WriteOwnership(ownershipPath, cmd.Process.Pid, args)
	if e != nil {
		_ = stop()
		_ = wait(5 * time.Second)
		return nil, e
	}
	failure := any(nil)
	ack := false
	if ctx.Err() != nil {
		failure = "CONTROL_CANCELLED"
	} else {
		_, e = inW.Write([]byte("GO\n"))
		if e == nil {
			ack = true
		} else {
			failure = "CONTROL_CANCELLED"
		}
	}
	inW.Close()
	type chunk struct {
		body []byte
		err  error
	}
	data := make(chan chunk, 2)
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		for {
			b := make([]byte, 65536)
			n, e := outR.Read(b)
			select {
			case data <- chunk{b[:n], e}:
			case <-closed:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	output := []byte{}
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	done := false
	for !done && failure == nil {
		select {
		case <-ctx.Done():
			failure = "CONTROL_CANCELLED"
		case <-timer.C:
			failure = "CONTROL_COMMAND_TIMEOUT"
		case c := <-data:
			available := (1 << 20) - len(output)
			if len(c.body) > available {
				output = append(output, c.body[:available]...)
				failure = "CONTROL_OUTPUT_LIMIT"
			} else {
				output = append(output, c.body...)
			}
			if c.err != nil {
				if c.err != io.EOF {
					failure = "CONTROL_READ_FAILED"
				}
				done = true
			}
		}
	}
	if failure != nil {
		_ = stop()
	}
	if e = wait(15 * time.Second); e != nil {
		_ = stop()
		_ = wait(5 * time.Second)
		failure = "CONTROL_STOP_FAILED"
	}
	evidence := Object{"stop_verified": false, "leader_state": "measurement_failed", "group_empty": false}
	until := time.Now().Add(5 * time.Second)
	for {
		if v, er := VerifyStopped(owner); er == nil {
			evidence = v
		}
		if Bool(evidence, "stop_verified") || !time.Now().Before(until) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !Bool(evidence, "stop_verified") {
		failure = "CONTROL_STOP_FAILED"
	}
	return Object{"exit_status": status, "failure": failure, "elapsed_seconds": time.Since(started).Seconds(), "output_sha256": HashBytes(output), "output_bytes": len(output), "ownership_path": ownershipPath, "ownership_sha256": ownerSHA, "start_acknowledged": ack, "stop_verified": Bool(evidence, "stop_verified"), "stop_evidence": evidence}, nil
}
