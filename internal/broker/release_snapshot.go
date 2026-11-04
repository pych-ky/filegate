package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	if s.Schema != 2 || s.Policy != formatPolicy || !s.Captured.Valid() || !validDigest(s.BuildSHA256) || !validDigest(s.WorkerSHA256) || !validDigest(s.FormatsSHA256) || len(s.Pins) < 16 || len(s.Pins) > 1024 {
		return false
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
	s := &scanReleaseSnapshot{Schema: 2, AttemptID: j.AttemptID, Object: *j.InputReceipt, Captured: clock, Policy: formatPolicy, BuildSHA256: releaseDigest(body), Pins: map[string]scanReleasePin{}}
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
	qemu, err := exec.LookPath("qemu-system-aarch64")
	if err == nil {
		qemu, err = filepath.EvalSymlinks(qemu)
	}
	if err != nil {
		return nil, invalid
	}
	s.QEMU = qemu
	for _, path := range []string{qemu, vm.RunnerPath} {
		digest, err := releaseFileDigest(path)
		if err != nil || add(path, digest, true) != nil {
			return nil, invalid
		}
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
	if len(encode(s)) > 1<<20 || !s.current() {
		return nil, invalid
	}
	return s, nil
}
