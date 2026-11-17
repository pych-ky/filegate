package fixturebridge

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

// The workspace-block-io fixture sends only these literals over its private QMP socket; nothing from the guest, a caller or a file becomes command text.
const (
	qmpCapabilities = `{"execute":"qmp_capabilities"}`
	qmpBlockdevAdd  = `{"execute":"blockdev-add","arguments":{"driver":"blkdebug","node-name":"fg-work-eio","image":"work-file","inject-error":[{"event":"write_aio","iotype":"write","errno":5}]}}`
	// blockdev-reopen resets omitted options, so the fixed raw size and attributes of the work node are restated.
	qmpBlockdevReopen = `{"execute":"blockdev-reopen","arguments":{"options":[{"driver":"raw","node-name":"work","file":"fg-work-eio","read-only":false,"discard":"ignore","size":4294967296}]}}`
	qmpQueryNodes     = `{"execute":"query-named-block-nodes","arguments":{"flat":true}}`
	qmpQueryStatus    = `{"execute":"query-status"}`
)

// The client reads at most qmpTotalLimit bytes; even with six-fold JSON escaping plus per-line digests the serialized record stays below qmpRecordLimit, the bound used by the writer and the runner's capture.
const (
	qmpLineLimit   = 64 << 10
	qmpTotalLimit  = 128 << 10
	qmpLineCount   = 256
	qmpRecordLimit = 1 << 20
)

type qmpClient struct {
	conn          net.Conn
	reader        *bufio.Reader
	lines, total  int
	transcript    []object
	events        []object
	readTimeout   time.Duration
	commandsSent  int
	maximumWrites int
}

func newQMPClient(conn net.Conn, timeout time.Duration) *qmpClient {
	return &qmpClient{conn: conn, reader: bufio.NewReaderSize(conn, qmpLineLimit+1), readTimeout: timeout, maximumWrites: 5}
}

func qmpDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// line reads one bounded JSON line and records it with its digest.
func (c *qmpClient) line() (object, error) {
	if c.lines >= qmpLineCount {
		return nil, errors.New("QMP_LINE_COUNT")
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
		return nil, err
	}
	body, err := c.reader.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return nil, errors.New("QMP_BYTE_LIMIT")
	}
	if err != nil {
		return nil, errors.New("QMP_READ_FAILED")
	}
	c.lines++
	c.total += len(body)
	if len(body) > qmpLineLimit || c.total > qmpTotalLimit {
		return nil, errors.New("QMP_BYTE_LIMIT")
	}
	body = bytes.TrimRight(body, "\r\n")
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value object
	if decoder.Decode(&value) != nil || decoder.More() {
		return nil, errors.New("QMP_JSON_INVALID")
	}
	c.transcript = append(c.transcript, object{"received": string(body), "sha256": qmpDigest(body)})
	return value, nil
}

// execute sends one fixed literal and returns its return value; asynchronous events received meanwhile are kept in order.
func (c *qmpClient) execute(literal string) (any, error) {
	if c.commandsSent >= c.maximumWrites {
		return nil, errors.New("QMP_COMMAND_LIMIT")
	}
	c.commandsSent++
	c.transcript = append(c.transcript, object{"sent": literal, "sha256": qmpDigest([]byte(literal))})
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.readTimeout)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write([]byte(literal + "\n")); err != nil {
		return nil, errors.New("QMP_WRITE_FAILED")
	}
	for {
		value, err := c.line()
		if err != nil {
			return nil, err
		}
		if value["event"] != nil {
			c.events = append(c.events, value)
			continue
		}
		if value["error"] != nil {
			return nil, errors.New("QMP_COMMAND_ERROR")
		}
		result, ok := value["return"]
		if !ok || len(value) != 1 {
			return nil, errors.New("QMP_RESPONSE_INVALID")
		}
		return result, nil
	}
}

// qmpGreeting accepts only the pinned QEMU 11.1.2 greeting.
func qmpGreeting(value object) error {
	version := hostvm.Map(hostvm.Map(hostvm.Map(value, "QMP"), "version"), "qemu")
	if len(value) != 1 || hostvm.Int(version, "major") != 11 || hostvm.Int(version, "minor") != 1 || hostvm.Int(version, "micro") != 2 {
		return errors.New("QMP_GREETING_INVALID")
	}
	return nil
}

func emptyReturn(value any, err error) error {
	if err != nil {
		return err
	}
	if returned, ok := value.(map[string]any); !ok || len(returned) != 0 {
		return errors.New("QMP_RESPONSE_INVALID")
	}
	return nil
}

// qmpGraph checks the readback with the QAPI children edges of v11.1.2 BlockDeviceInfo: work.file -> fg-work-eio, fg-work-eio.image -> work-file at the canonical run/work.raw,
// read-only base and definitions over their file nodes, the explicit 4 GiB raw size, and no other writable node. Filenames are not compared with each other.
func qmpGraph(value any, run string) error {
	rows, ok := value.([]any)
	if !ok {
		return errors.New("QMP_GRAPH_INVALID")
	}
	nodes := map[string]object{}
	for _, item := range rows {
		row, ok := item.(map[string]any)
		name := hostvm.Str(row, "node-name")
		if !ok || name == "" || nodes[name] != nil {
			return errors.New("QMP_GRAPH_INVALID")
		}
		nodes[name] = row
	}
	want := map[string]struct {
		drv, child, target string
		readOnly           bool
	}{"base": {"raw", "file", "base-file", true}, "base-file": {"file", "", "", true}, "definitions": {"raw", "file", "definitions-file", true}, "definitions-file": {"file", "", "", true},
		"work": {"raw", "file", "fg-work-eio", false}, "fg-work-eio": {"blkdebug", "image", "work-file", false}, "work-file": {"file", "", "", false}}
	if len(nodes) != len(want) {
		return errors.New("QMP_GRAPH_INVALID")
	}
	for name, expected := range want {
		row := nodes[name]
		children, ok := row["children"].([]any)
		if row == nil || !ok || hostvm.Str(row, "drv") != expected.drv || row["ro"] != expected.readOnly {
			return errors.New("QMP_GRAPH_INVALID")
		}
		if expected.child == "" {
			if len(children) != 0 {
				return errors.New("QMP_GRAPH_INVALID")
			}
			continue
		}
		if len(children) != 1 {
			return errors.New("QMP_GRAPH_INVALID")
		}
		edge, _ := children[0].(map[string]any)
		if len(edge) != 2 || hostvm.Str(edge, "child") != expected.child || hostvm.Str(edge, "node-name") != expected.target {
			return errors.New("QMP_GRAPH_INVALID")
		}
	}
	if hostvm.Int(hostvm.Map(nodes["work"], "image"), "virtual-size") != 4294967296 || hostvm.Str(nodes["work-file"], "file") != filepath.Join(run, "work.raw") {
		return errors.New("QMP_GRAPH_INVALID")
	}
	return nil
}

// qmpArm performs greeting, capabilities, blkdebug insertion and readback; any failure means no FIXTURE_READY.
func qmpArm(c *qmpClient, run string) (object, error) {
	greeting, err := c.line()
	if err != nil {
		return nil, err
	}
	if err = qmpGreeting(greeting); err != nil {
		return nil, err
	}
	if err = emptyReturn(c.execute(qmpCapabilities)); err != nil {
		return nil, err
	}
	if err = emptyReturn(c.execute(qmpBlockdevAdd)); err != nil {
		return nil, err
	}
	if err = emptyReturn(c.execute(qmpBlockdevReopen)); err != nil {
		return nil, err
	}
	nodes, err := c.execute(qmpQueryNodes)
	if err != nil {
		return nil, err
	}
	if err = qmpGraph(nodes, run); err != nil {
		return nil, err
	}
	if len(c.events) != 0 {
		return nil, errors.New("QMP_EVENT_BEFORE_ARM")
	}
	return object{"armed": true, "graph": nodes}, nil
}

// qmpObserve waits for the injected write error to stop the VM: BLOCK_IO_ERROR on work (write, stop), then STOP, then status io-error.
func qmpObserve(c *qmpClient, deadline time.Time) (object, error) {
	var blockErrors []object
	stopped := false
	for !stopped {
		if time.Now().After(deadline) {
			return nil, errors.New("QMP_OBSERVATION_TIMEOUT")
		}
		value, err := c.line()
		if err != nil {
			return nil, err
		}
		switch hostvm.Str(value, "event") {
		case "BLOCK_IO_ERROR":
			data := hostvm.Map(value, "data")
			if hostvm.Str(data, "node-name") != "work" || hostvm.Str(data, "operation") != "write" || hostvm.Str(data, "action") != "stop" {
				return nil, errors.New("QMP_BLOCK_IO_ERROR_UNEXPECTED")
			}
			blockErrors = append(blockErrors, value)
		case "STOP":
			if len(blockErrors) == 0 {
				return nil, errors.New("QMP_STOP_WITHOUT_BLOCK_IO_ERROR")
			}
			stopped = true
		default:
			return nil, errors.New("QMP_EVENT_UNEXPECTED")
		}
		c.events = append(c.events, value)
	}
	status, err := c.execute(qmpQueryStatus)
	if err != nil {
		return nil, err
	}
	row, ok := status.(map[string]any)
	if !ok || row["running"] != false || hostvm.Str(row, "status") != "io-error" {
		return nil, errors.New("QMP_STATUS_NOT_IO_ERROR")
	}
	return object{"block_io_errors": len(blockErrors), "status": row}, nil
}

// qmpFixture holds one armed connection; evidence is written to fixture-qmp.json in the run directory and synced before any acknowledgement.
type qmpFixture struct {
	client   *qmpClient
	evidence object
	path     string
}

// armBlockIO connects to the QEMU-created socket of this run only after checking its type, owner, link count and path, binds the peer and run, and arms the fixed blkdebug insertion.
func armBlockIO(run string) (*qmpFixture, error) {
	socket := filepath.Join(run, "qmp.sock")
	evidence := object{"schema": 1, "fixture": "workspace-block-io", "run_directory": run, "armed": false, "observed": false}
	record := &qmpFixture{evidence: evidence, path: filepath.Join(run, "fixture-qmp.json")}
	fail := func(err error) (*qmpFixture, error) {
		evidence["failure"] = err.Error()
		if record.client != nil {
			evidence["transcript"] = record.client.transcript
		}
		if saveErr := record.save(); saveErr != nil {
			return nil, errors.Join(err, saveErr)
		}
		return nil, err
	}
	var stat unix.Stat_t
	if unix.Lstat(socket, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || os.Chmod(socket, 0600) != nil {
		return fail(errors.New("QMP_SOCKET_INVALID"))
	}
	if canonical, err := filepath.EvalSymlinks(socket); err != nil || canonical != socket {
		return fail(errors.New("QMP_SOCKET_INVALID"))
	}
	prepared, err := os.ReadFile(filepath.Join(run, "prepared.json"))
	if err != nil {
		return fail(errors.New("QMP_PREPARED_UNREADABLE"))
	}
	var raw unix.Stat_t
	if unix.Lstat(filepath.Join(run, "work.raw"), &raw) != nil || raw.Size != 4294967296 {
		return fail(errors.New("QMP_RAW_INVALID"))
	}
	evidence["prepared_sha256"] = qmpDigest(prepared)
	evidence["raw_identity"] = object{"device": int64(raw.Dev), "inode": int64(raw.Ino), "size": raw.Size}
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return fail(errors.New("QMP_CONNECT_FAILED"))
	}
	unixConn, _ := conn.(*net.UnixConn)
	peer, err := unix.GetsockoptInt(int(fdOf(unixConn)), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	identity, identityErr := hostvm.NativeIdentity(peer)
	if err != nil || identityErr != nil || identity == nil {
		conn.Close()
		return fail(errors.New("QMP_PEER_UNKNOWN"))
	}
	evidence["qmp_peer"] = identity
	credential, credentialErr := unix.GetsockoptXucred(int(fdOf(unixConn)), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if credentialErr != nil {
		conn.Close()
		return fail(errors.New("QMP_PEER_UNKNOWN"))
	}
	// The peer is bound to this run's native vm process before any byte is written to the socket.
	bound, arm, client, err := armWithPeer(conn, run, func() (object, error) {
		return verifyQMPPeer(systemPeerFacts(), run, peer, int(credential.Uid))
	})
	record.client = client
	evidence["peer_binding"] = bound
	if err != nil {
		conn.Close()
		return fail(err)
	}
	evidence["armed"], evidence["arm"], evidence["transcript"] = true, arm, record.client.transcript
	if err = record.save(); err != nil {
		conn.Close()
		return nil, err
	}
	return record, nil
}

// observe records the stop evidence; the final digest covers every QMP line exchanged after arming.
func (f *qmpFixture) observe() {
	defer f.client.conn.Close()
	start := len(f.client.transcript)
	observation, err := qmpObserve(f.client, time.Now().Add(60*time.Second))
	f.evidence["transcript"] = f.client.transcript
	if err != nil {
		f.evidence["failure"] = err.Error()
	} else {
		body, _ := json.Marshal(f.client.transcript[start:])
		f.evidence["observed"], f.evidence["observation"], f.evidence["observation_sha256"] = true, observation, qmpDigest(body)
	}
	_ = f.save()
}

// save writes the full record, or on failure a reduced record that names the write failure, and reports the original write error either way.
func (f *qmpFixture) save() error {
	err := saveBounded(f.path, f.evidence, qmpRecordLimit)
	if err == nil {
		return nil
	}
	reduced := object{"schema": 1, "fixture": "workspace-block-io", "run_directory": f.evidence["run_directory"], "armed": false, "observed": false,
		"failure": f.evidence["failure"], "record_write_error": err.Error()}
	if saveBounded(f.path, reduced, qmpRecordLimit) != nil {
		return errors.New("QMP_RECORD_WRITE_FAILED")
	}
	return errors.New("QMP_RECORD_REDUCED")
}

func fdOf(conn *net.UnixConn) uintptr {
	raw, err := conn.SyscallConn()
	if err != nil {
		return ^uintptr(0)
	}
	var fd uintptr
	if raw.Control(func(value uintptr) { fd = value }) != nil {
		return ^uintptr(0)
	}
	return fd
}

// armWithPeer runs the peer check first and only then reads or writes the socket.
func armWithPeer(conn net.Conn, run string, verify func() (object, error)) (object, object, *qmpClient, error) {
	bound, err := verify()
	if err != nil {
		return nil, nil, nil, err
	}
	client := newQMPClient(conn, 5*time.Second)
	arm, err := qmpArm(client, run)
	return bound, arm, client, err
}

// qmpPeerFacts are the kernel and native-control facts used to bind the QMP peer; tests substitute them.
type qmpPeerFacts struct {
	uid, group int
	procArgs   func(pid int) (string, []string, error)
	identity   func(pid int) (object, error)
}

func systemPeerFacts() qmpPeerFacts {
	return qmpPeerFacts{uid: os.Getuid(), group: unix.Getpgrp(), procArgs: procArgs, identity: hostvm.NativeIdentity}
}

var watchdogConfig = regexp.MustCompile(`^/private/tmp/fgw-[0-9a-f]{32}/config\.json$`)

// verifyQMPPeer binds the socket peer to this run's native vm process: the watchdog leads this helper's process group, its fixed config names this run,
// its MONITOR_READY record names the vm process, and the peer is that process (same uid and start time) running the prepared QEMU executable and hash.
func verifyQMPPeer(facts qmpPeerFacts, run string, peerPID, peerUID int) (object, error) {
	unbound := errors.New("QMP_PEER_UNBOUND")
	if peerUID != facts.uid {
		return nil, unbound
	}
	_, watchdogArgs, err := facts.procArgs(facts.group)
	if err != nil || len(watchdogArgs) != 2 || !watchdogConfig.MatchString(watchdogArgs[1]) {
		return nil, unbound
	}
	control := filepath.Dir(watchdogArgs[1])
	config, _, err := hostvm.Read(watchdogArgs[1], hostvm.ControlLimit)
	if err != nil || hostvm.Str(config, "run_directory") != run || hostvm.Str(config, "mode") != "qemu" {
		return nil, unbound
	}
	events, err := hostvm.NativeEvents(control)
	if err != nil {
		return nil, unbound
	}
	var watchdog, vm object
	for _, event := range events {
		switch hostvm.Str(event, "event") {
		case "WATCHDOG_STARTED":
			watchdog = event
		case "MONITOR_READY":
			for _, item := range hostvm.List(event, "processes") {
				if row, _ := item.(map[string]any); hostvm.Str(row, "role") == "vm" {
					vm = row
				}
			}
		}
	}
	peer, err := facts.identity(peerPID)
	if err != nil || watchdog == nil || vm == nil || hostvm.Int(watchdog, "pid") != int64(facts.group) || hostvm.Int(vm, "pid") != int64(peerPID) ||
		!hostvm.Equal(peer["start_abstime"], vm["start_abstime"]) || hostvm.Int(peer, "uid") != int64(facts.uid) || hostvm.Int(peer, "process_group") != int64(facts.group) {
		return nil, unbound
	}
	prepared, _, err := hostvm.Read(filepath.Join(run, "prepared.json"), hostvm.ControlLimit)
	argv, ok := hostvm.Strings(prepared["argv"])
	executable, _, argsErr := facts.procArgs(peerPID)
	if err != nil || !ok || len(argv) == 0 || argsErr != nil || executable != argv[0] {
		return nil, unbound
	}
	sum, err := hostvm.HashFile(executable)
	if err != nil || sum != hostvm.Str(prepared, "qemu_sha256") {
		return nil, unbound
	}
	return object{"peer": peer, "vm": vm, "watchdog_pid": facts.group, "control_directory": control, "executable": executable, "executable_sha256": sum}, nil
}

// procArgs reads a process's executable path and argv from the kern.procargs2 sysctl.
func procArgs(pid int) (string, []string, error) {
	buffer, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(buffer) < 4 {
		return "", nil, errors.New("PROCARGS_UNAVAILABLE")
	}
	argc := int(binary.LittleEndian.Uint32(buffer[:4]))
	rest := buffer[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 || argc < 0 || argc > 64 {
		return "", nil, errors.New("PROCARGS_INVALID")
	}
	executable := string(rest[:end])
	rest = bytes.TrimLeft(rest[end:], "\x00")
	argv := []string{}
	for len(argv) < argc {
		end = bytes.IndexByte(rest, 0)
		if end < 0 {
			return "", nil, errors.New("PROCARGS_INVALID")
		}
		argv = append(argv, string(rest[:end]))
		rest = rest[end+1:]
	}
	return executable, argv, nil
}
