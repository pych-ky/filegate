package broker

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"filegate.local/filegate/internal/qemuruntime"
	updatecontrol "filegate.local/filegate/internal/update"
	"golang.org/x/sys/unix"
)

type scanReleasePin struct {
	SHA256   string        `json:"sha256"`
	Device   uint64        `json:"device"`
	Inode    uint64        `json:"inode"`
	Links    uint64        `json:"links"`
	Mode     uint32        `json:"mode"`
	UID      uint32        `json:"uid"`
	GID      uint32        `json:"gid"`
	Size     int64         `json:"size"`
	Modified unix.Timespec `json:"modified"`
	Changed  unix.Timespec `json:"changed"`
}

type scanReleaseSnapshot struct {
	Schema        int                       `json:"schema"`
	AttemptID     string                    `json:"attempt_id"`
	Object        InputReceipt              `json:"object"`
	Captured      updatecontrol.Clock       `json:"captured"`
	Finished      *updatecontrol.Clock      `json:"finished,omitempty"`
	Policy        string                    `json:"policy"`
	WorkerSHA256  string                    `json:"worker_sha256"`
	BuildSHA256   string                    `json:"build_sha256"`
	FormatsSHA256 string                    `json:"formats_sha256"`
	QEMU          string                    `json:"qemu"`
	Host          string                    `json:"host"`
	Pins          map[string]scanReleasePin `json:"pins"`
	ReportSHA256  string                    `json:"report_sha256"`
	SummarySHA256 string                    `json:"summary_sha256"`
	// The QEMU closure decoded from the pinned build receipt at capture; currentness re-verifies it and never captures a new one.
	QEMURuntime *qemuruntime.Manifest `json:"qemu_runtime,omitempty"`
}

func releaseDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func releasePinIdentity(st unix.Stat_t, digest string) scanReleasePin {
	return scanReleasePin{digest, uint64(st.Dev), st.Ino, uint64(st.Nlink), uint32(st.Mode), st.Uid, st.Gid, st.Size, st.Mtim, st.Ctim}
}

func releasePin(path, expected string, hash bool) (scanReleasePin, error) {
	var empty scanReleasePin
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path || !filepath.IsAbs(path) || !validDigest(expected) {
		return empty, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Mode&0022 != 0 {
		return empty, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	if hash {
		if before.Size > 128<<20 {
			return empty, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
		}
		h := sha256.New()
		if _, err = io.CopyN(h, f, before.Size); err != nil || hex.EncodeToString(h.Sum(nil)) != expected {
			return empty, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
		}
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || releasePinIdentity(before, expected) != releasePinIdentity(after, expected) || releasePinIdentity(before, expected) != releasePinIdentity(named, expected) {
		return empty, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	return releasePinIdentity(before, expected), nil
}

func releaseFileDigest(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > 128<<20 {
		return "", failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	h := sha256.New()
	if _, err = io.CopyN(h, f, before.Size); err != nil || unix.Fstat(fd, &after) != nil || releasePinIdentity(before, "") != releasePinIdentity(after, "") {
		return "", failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s scanReleaseSnapshot) current() bool {
	if s.Schema != 3 || s.Policy != formatPolicy || !s.Captured.Valid() || !validDigest(s.BuildSHA256) || !validDigest(s.WorkerSHA256) || !validDigest(s.FormatsSHA256) || len(s.Pins) < 16 || len(s.Pins) > 1024 {
		return false
	}
	tools := s.QEMURuntime
	if tools == nil || s.QEMU != tools.System().Path {
		return false
	}
	for path, digest := range tools.Files() {
		if pin, ok := s.Pins[path]; !ok || pin.SHA256 != digest {
			return false
		}
	}
	host, err := os.Executable()
	if err == nil {
		host, err = filepath.EvalSymlinks(host)
	}
	if err != nil || host != s.Host || !validDigest(s.Pins[host].SHA256) {
		return false
	}
	for path, expected := range s.Pins {
		canonical, err := filepath.EvalSymlinks(path)
		var actual unix.Stat_t
		if err != nil || canonical != path || !validDigest(expected.SHA256) || unix.Lstat(path, &actual) != nil || releasePinIdentity(actual, expected.SHA256) != expected {
			return false
		}
	}
	// File identities alone miss a moved /opt/homebrew/opt link or an OS change, so the original closure is re-derived in full.
	_, err = qemuruntime.Verify(*tools)
	return err == nil
}

// releaseView holds one list or detail request's metadata and results. A list keeps only its decoded snapshots for
// the next request's byte-identical rows.
type releaseView struct {
	paths          map[string]releasePath
	directories    map[string]bool            // directory -> reached from / without a symlink in this request
	snapshots      map[string]displaySnapshot // attempt -> this request's stored row digest and strict decode
	current        map[string]bool            // attempt -> this request's currentForDisplay result
	qemu           map[string]bool            // manifest digest -> this request's displayQEMUCurrent result
	host           string
	hostErr        error
	hostRead       bool
	executable     string
	executableErr  error
	executableRead bool
	definition     *requestDefinition
}

type releasePath struct {
	stat unix.Stat_t
	ok   bool
}

// displaySnapshot is a strict decode of one stored snapshot row and the SHA-256 of exactly those bytes.
type displaySnapshot struct {
	digest   string
	snapshot scanReleaseSnapshot
}

type requestDefinition struct {
	state updatecontrol.ScanDefinitionState
	err   error
}

// Requests retain at most one page of attempts and a bounded set of paths; excess entries are checked without retention.
const (
	displayRequestAttempts = 100
	displayRequestPaths    = 4096
)

func newReleaseView() *releaseView {
	return &releaseView{paths: map[string]releasePath{}, directories: map[string]bool{}, snapshots: map[string]displaySnapshot{}, current: map[string]bool{}, qemu: map[string]bool{}}
}

// snapshot reads the stored row on every request. The latest list request's strict decode is reused only for the same attempt
// and a byte-identical row; any other row is decoded again, and a failed decode never falls back to an earlier value.
func (v *releaseView) snapshot(b *Broker, attempt string) (scanReleaseSnapshot, error) {
	if d, ok := v.snapshots[attempt]; ok {
		return d.snapshot, nil
	}
	rows, err := b.db.Query("SELECT data FROM scan_release_snapshots WHERE attempt_id=?", attempt)
	if err != nil {
		return scanReleaseSnapshot{}, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	// The row's bytes are borrowed until Close, so they are hashed and strictly decoded before it.
	var body sql.RawBytes
	var d displaySnapshot
	ok := rows.Next() && rows.Scan(&body) == nil
	if ok {
		d.digest = releaseDigest(body)
		if previous, found := b.displaySnapshots[attempt]; found && previous.digest == d.digest {
			d.snapshot = previous.snapshot
		} else {
			d.snapshot, ok = decodeScanRelease(body, attempt)
		}
	}
	if rows.Close() != nil || !ok {
		return d.snapshot, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	if len(v.snapshots) < displayRequestAttempts {
		v.snapshots[attempt] = d
	}
	return d.snapshot, nil
}

// readDefinition shares one admitted control commit and definition validation within a display request.
func (v *releaseView) readDefinition(b *Broker, now updatecontrol.Clock, admit func(*sql.Tx) error) (updatecontrol.ScanDefinitionState, error) {
	if v.definition == nil {
		state, err := b.updates.store.ReadScanDefinitionAdmitted(now, admit)
		v.definition = &requestDefinition{state: state, err: err}
	}
	return v.definition.state, v.definition.err
}

// path accepts an absolute clean path that is not a symlink and whose ancestors are directories reached without symlinks.
// Ancestor observations are shared within this display request; the next request and strict actions check again.
func (v *releaseView) path(path string) releasePath {
	if p, ok := v.paths[path]; ok {
		return p
	}
	var p releasePath
	p.ok = filepath.IsAbs(path) && filepath.Clean(path) == path && unix.Lstat(path, &p.stat) == nil &&
		p.stat.Mode&unix.S_IFMT != unix.S_IFLNK && v.directory(filepath.Dir(path))
	if len(v.paths) < displayRequestPaths {
		v.paths[path] = p
	}
	return p
}

func (v *releaseView) directory(path string) bool {
	if path == "/" {
		return true
	}
	if ok, seen := v.directories[path]; seen {
		return ok
	}
	var stat unix.Stat_t
	ok := v.directory(filepath.Dir(path)) && unix.Lstat(path, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR
	if len(v.directories) < displayRequestPaths {
		v.directories[path] = ok
	}
	return ok
}

// executableHost resolves this broker's executable once per request for every stored row's host comparison.
func (v *releaseView) executableHost() (string, error) {
	if !v.executableRead {
		v.executable, v.executableErr = os.Executable()
		if v.executableErr == nil {
			v.executable, v.executableErr = filepath.EvalSymlinks(v.executable)
		}
		v.executableRead = true
	}
	return v.executable, v.executableErr
}

func (v *releaseView) hostOS() (string, error) {
	if !v.hostRead {
		v.host, v.hostErr = qemuruntime.SystemVersion()
		v.hostRead = true
	}
	return v.host, v.hostErr
}

// currentForDisplay is current() for list and detail only: pins use the request's metadata, and the QEMU closure is re-derived
// unless its observation equals the last successful full Verify. Release, recovery, publication and acceptance keep current().
func (s scanReleaseSnapshot) currentForDisplay(b *Broker, v *releaseView) bool {
	if s.Schema != 3 || s.Policy != formatPolicy || !s.Captured.Valid() || !validDigest(s.BuildSHA256) || !validDigest(s.WorkerSHA256) || !validDigest(s.FormatsSHA256) || len(s.Pins) < 16 || len(s.Pins) > 1024 {
		return false
	}
	tools := s.QEMURuntime
	if tools == nil || s.QEMU != tools.System().Path {
		return false
	}
	host, err := v.executableHost()
	if err != nil || host != s.Host || !validDigest(s.Pins[host].SHA256) {
		return false
	}
	for path, digest := range tools.Files() {
		if pin, ok := s.Pins[path]; !ok || pin.SHA256 != digest {
			return false
		}
	}
	for path, expected := range s.Pins {
		p := v.path(path)
		if !p.ok || !validDigest(expected.SHA256) || releasePinIdentity(p.stat, expected.SHA256) != expected {
			return false
		}
	}
	return b.displayQEMUCurrent(*tools, v)
}

// qemuDisplayVerified is the one manifest last fully verified for display and the observation taken around that Verify.
type qemuDisplayVerified struct {
	manifest    string
	observation string
}

// displayQEMUCurrent decides a manifest once per request. The caller holds b.mu.
func (b *Broker) displayQEMUCurrent(m qemuruntime.Manifest, v *releaseView) bool {
	key := qemuruntime.Digest(m)
	if current, ok := v.qemu[key]; ok {
		return current
	}
	current := b.observeQEMU(m, key, v)
	v.qemu[key] = current
	return current
}

// observeQEMU remembers only the last success, and only when the observation did not change across the full Verify; a change
// seen there makes this request not current.
func (b *Broker) observeQEMU(m qemuruntime.Manifest, key string, v *releaseView) bool {
	host, err := v.hostOS()
	if err != nil {
		return false
	}
	before, err := qemuruntime.Observe(m, host)
	if err != nil {
		return false
	}
	if b.qemuDisplay.manifest == key && b.qemuDisplay.observation == before {
		return true
	}
	if _, err = qemuruntime.Verify(m); err != nil {
		return false
	}
	if after, err := qemuruntime.Observe(m, host); err != nil || after != before {
		return false
	}
	b.qemuDisplay = qemuDisplayVerified{manifest: key, observation: before}
	return true
}

func (b *Broker) captureScanRelease(j Job, definition *updatecontrol.ScanDefinition) (*scanReleaseSnapshot, error) {
	invalid := failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	vm := b.config.VM
	if vm == nil || vm.RunnerPath != filepath.Join(vm.Workspace, ".build/filegate-vm") || j.InputReceipt == nil {
		return nil, invalid
	}
	buildPath := filepath.Join(vm.Workspace, "experiments/vm/evidence/build.json")
	body, err := readPrivate(buildPath, 4<<20)
	var build struct {
		Schema      int               `json:"schema"`
		Kind        string            `json:"evidence_kind"`
		Artifacts   map[string]string `json:"artifacts"`
		Sources     map[string]string `json:"product_sources_sha256"`
		NativeProof string            `json:"native_proof_sha256"`
		QEMURuntime json.RawMessage   `json:"qemu_runtime"`
		Installed   map[string]struct {
			SHA256 string `json:"sha256"`
			Mode   string `json:"mode"`
			UID    int    `json:"uid"`
			GID    int    `json:"gid"`
		} `json:"installed_files"`
	}
	if err != nil || json.Unmarshal(body, &build) != nil || build.Schema != 4 || build.Kind != "derived_format_VM_construction_only" || build.NativeProof != b.proofSHA || len(build.Sources) < 16 || len(build.Sources) > 512 || len(build.Artifacts) > 32 {
		return nil, invalid
	}
	clock, err := updatecontrol.ReadClock()
	if err != nil {
		return nil, failure("UPDATE_CLOCK_UNCERTAIN", 503)
	}
	s := &scanReleaseSnapshot{Schema: 3, AttemptID: j.AttemptID, Object: *j.InputReceipt, Captured: clock, Policy: formatPolicy, BuildSHA256: releaseDigest(body), Pins: map[string]scanReleasePin{}}
	add := func(path, expected string, hash bool) error {
		pin, err := releasePin(path, expected, hash)
		if err == nil {
			s.Pins[path] = pin
		}
		return err
	}
	if add(buildPath, s.BuildSHA256, true) != nil {
		return nil, invalid
	}
	host, err := os.Executable()
	if err == nil {
		host, err = filepath.EvalSymlinks(host)
	}
	if err != nil {
		return nil, invalid
	}
	hostSHA, err := releaseFileDigest(host)
	if err != nil || add(host, hostSHA, true) != nil {
		return nil, invalid
	}
	s.Host = host
	s.BuildSHA256 = releaseDigest(encode([]string{s.BuildSHA256, hostSHA}))
	formats := map[string]string{}
	for relative, digest := range build.Sources {
		if !filepath.IsLocal(relative) || filepath.ToSlash(filepath.Clean(relative)) != relative || !validDigest(digest) {
			return nil, invalid
		}
		if add(filepath.Join(vm.Workspace, relative), digest, true) != nil {
			return nil, invalid
		}
		if strings.HasPrefix(relative, "internal/inspect/") && strings.HasSuffix(relative, ".go") {
			formats[relative] = digest
		}
	}
	for _, name := range []string{"zip32-v1.json", "txt-v1.json", "image-v1.json", "ooxml-v1.json"} {
		path := "experiments/contracts/" + name
		digest := build.Sources[path]
		installed := build.Installed["/contracts/"+name]
		if !validDigest(digest) || installed.SHA256 != digest || installed.Mode != "0444" || installed.UID != 0 || installed.GID != 0 {
			return nil, invalid
		}
		formats[path] = digest
	}
	inspectFiles, err := filepath.Glob(filepath.Join(vm.Workspace, "internal/inspect/*.go"))
	if err != nil || len(inspectFiles) == 0 || len(formats) != len(inspectFiles)+4 {
		return nil, invalid
	}
	for _, path := range inspectFiles {
		relative, err := filepath.Rel(vm.Workspace, path)
		if err != nil || !validDigest(formats[filepath.ToSlash(relative)]) {
			return nil, invalid
		}
	}
	if definition == nil || add(definition.ImagePath, definition.Image.SHA256, false) != nil {
		return nil, invalid
	}
	for relative, digest := range build.Artifacts {
		if !filepath.IsLocal(relative) || filepath.ToSlash(filepath.Clean(relative)) != relative || add(filepath.Join(vm.Workspace, "experiments/vm", relative), digest, false) != nil {
			return nil, invalid
		}
	}
	worker := build.Installed["/filegate-worker"]
	if !validDigest(worker.SHA256) || worker.SHA256 != build.Artifacts[".build/filegate-worker"] || worker.Mode != "0755" || worker.UID != 0 || worker.GID != 0 {
		return nil, invalid
	}
	formats["/filegate-worker"] = worker.SHA256
	s.FormatsSHA256 = releaseDigest(encode(formats))
	proofBody, err := readPrivate(vm.Proof, 4<<20)
	var proof struct {
		Passed bool   `json:"passed"`
		Kind   string `json:"kind"`
		Binary string `json:"binary_sha256"`
		Source string `json:"native_source_sha256"`
	}
	if err != nil || releaseDigest(proofBody) != b.proofSHA || json.Unmarshal(proofBody, &proof) != nil || !proof.Passed || proof.Kind != "launchagent_death" {
		return nil, invalid
	}
	for path, digest := range map[string]string{vm.RunnerPath: b.runnerSHA, vm.Proof: b.proofSHA, filepath.Join(vm.Workspace, "experiments/host/.build/integrated-watchdog"): proof.Binary, filepath.Join(vm.Workspace, "experiments/host/integrated_watchdog.m"): proof.Source} {
		if add(path, digest, true) != nil {
			return nil, invalid
		}
	}
	tools, err := qemuruntime.Decode(build.QEMURuntime)
	if err != nil {
		return nil, invalid
	}
	if _, err = qemuruntime.Verify(tools); err != nil {
		return nil, invalid
	}
	for path, digest := range tools.Files() {
		if add(path, digest, true) != nil {
			return nil, invalid
		}
	}
	qemu := tools.System().Path
	s.QEMU = qemu
	s.QEMURuntime = &tools
	digest, err := releaseFileDigest(vm.RunnerPath)
	if err != nil || add(vm.RunnerPath, digest, true) != nil {
		return nil, invalid
	}
	workerPins := map[string]string{}
	for _, path := range []string{"experiments/vm/.build/base.ext4", "experiments/vm/.build/initramfs.cpio.gz", "experiments/vm/.cache/boot/vmlinuz-virt", "experiments/vm/.build/filegate-worker", "experiments/vm/.build/filegate-bridge", "experiments/host/.build/integrated-watchdog"} {
		pin, ok := s.Pins[filepath.Join(vm.Workspace, path)]
		if !ok {
			return nil, invalid
		}
		workerPins[path] = pin.SHA256
	}
	workerPins["qemu"], workerPins["runner"], workerPins["native-proof"], workerPins["build-receipt"] = s.Pins[qemu].SHA256, b.runnerSHA, b.proofSHA, s.Pins[buildPath].SHA256
	s.WorkerSHA256 = releaseDigest(encode(workerPins))
	if !completedScanReleaseFits(*s) || !s.current() {
		return nil, invalid
	}
	return s, nil
}

// completedScanReleaseFits checks the largest stored form: validateScanRelease adds both result digests and
// finishScanLocked adds a valid finish clock of the captured boot, and decodeScanRelease must still accept it.
func completedScanReleaseFits(s scanReleaseSnapshot) bool {
	s.ReportSHA256, s.SummarySHA256 = strings.Repeat("0", 64), strings.Repeat("0", 64)
	s.Finished = &updatecontrol.Clock{Boot: s.Captured.Boot, UTC: updatecontrol.MaxUTC, ContinuousNS: math.MaxUint64}
	return len(encode(s)) <= 1<<20
}
