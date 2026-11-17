package updaterunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"filegate.local/filegate/internal/av"
	"filegate.local/filegate/internal/hostvm"
	"filegate.local/filegate/internal/qemuruntime"
	updatecontrol "filegate.local/filegate/internal/update"
	"golang.org/x/sys/unix"
)

type buildRecord struct {
	Schema           int                      `json:"schema"`
	RequestSchema    int                      `json:"request_schema"`
	Profile          string                   `json:"profile"`
	FixtureOnly      bool                     `json:"fixture_only"`
	LibrarySHA256    string                   `json:"library_sha256"`
	AdapterManifest  string                   `json:"adapter_manifest_sha256"`
	ImageProfile     av.Revision              `json:"image_profile"`
	ImageTools       updatecontrol.ImageTools `json:"image_tools"`
	SourcesSHA256    map[string]string        `json:"sources_sha256"`
	ArtifactsSHA256  map[string]string        `json:"artifacts_sha256"`
	Implementation   string                   `json:"implementation"`
	PythonDependency bool                     `json:"python_dependency"`
	PythonRuntime    struct {
		Method          string   `json:"method"`
		RemovedPaths    []string `json:"removed_paths"`
		RemainingPaths  []string `json:"remaining_python_paths"`
		InspectedInodes int64    `json:"inspected_inodes"`
		InventorySHA256 string   `json:"inventory_sha256"`
	} `json:"python_runtime"`
	InitramfsInspection struct {
		Entries      int64 `json:"entries"`
		Owners       bool  `json:"all_uid_gid_zero"`
		Links        bool  `json:"all_links_one"`
		BootFiles    bool  `json:"required_boot_files_present"`
		GzipCRC      bool  `json:"gzip_CRC_read_to_end"`
		PythonAbsent bool  `json:"python_runtime_absent"`
	} `json:"initramfs_inspection"`
}

func readBuild(m Manifest) (buildRecord, error) {
	var b buildRecord
	value, body, err := hostvm.Read(m.Build, 1<<20)
	if err != nil || !fields(value, "schema request_schema profile fixture_only library_sha256 adapter_manifest_sha256 image_profile image_tools sources_sha256 artifacts_sha256 implementation python_dependency python_runtime initramfs_inspection") || hash(body) != m.SHA256[m.Build] || strict(body, &b) != nil || b.Schema != 2 || b.RequestSchema != m.RequestSchema || b.Profile != m.Profile || value["fixture_only"] != false || b.FixtureOnly ||
		b.LibrarySHA256 != m.LibrarySHA256 || b.AdapterManifest != adoptedAdapter || b.ImageProfile != m.ImageProfile || b.ImageTools != m.ImageTools || len(b.SourcesSHA256) < 10 || len(b.ArtifactsSHA256) < 4 {
		return b, invalid("UPDATE_IMAGE_BINDING_CHANGED")
	}
	if b.Implementation != "go" || value["python_dependency"] != false || b.PythonDependency || b.PythonRuntime.Method != "bounded_recursive_debugfs_inode_inventory" || b.PythonRuntime.RemovedPaths == nil || b.PythonRuntime.RemainingPaths == nil || len(b.PythonRuntime.RemainingPaths) != 0 || b.PythonRuntime.InspectedInodes <= 0 || !digestPattern.MatchString(b.PythonRuntime.InventorySHA256) || !fields(hostvm.Map(value, "python_runtime"), "method removed_paths remaining_python_paths inspected_inodes inventory_sha256") || !fields(hostvm.Map(value, "initramfs_inspection"), "entries all_uid_gid_zero all_links_one required_boot_files_present gzip_CRC_read_to_end python_runtime_absent") || b.InitramfsInspection.Entries <= 0 || b.InitramfsInspection.Entries > 10000 || !b.InitramfsInspection.Owners || !b.InitramfsInspection.Links || !b.InitramfsInspection.BootFiles || !b.InitramfsInspection.GzipCRC || !b.InitramfsInspection.PythonAbsent {
		return b, invalid("UPDATE_PYTHON_FREE_IMAGE_PROOF_INVALID")
	}
	for _, pins := range []map[string]string{b.SourcesSHA256, b.ArtifactsSHA256} {
		for name, expected := range pins {
			if !digestPattern.MatchString(expected) || m.SHA256[name] != expected {
				return b, invalid("UPDATE_IMAGE_CHANGED")
			}
		}
	}
	return b, nil
}

func checkedCache(requestPath string, r Request, value object, m Manifest, verifyContents bool) (object, error) {
	if r.Definition == nil {
		return nil, nil
	}
	cache, ok := value["definition_cache"].(map[string]any)
	if !ok || hostvm.ValidateDefinition(cache, filepath.Dir(filepath.Dir(filepath.Dir(requestPath))), true) != nil {
		return nil, invalid("UPDATE_CACHE_INVALID")
	}
	d := r.Definition
	if d.Binding.ScannerManifestSHA256 != m.ImageProfile.ScannerManifestSHA256 || d.Binding.BinarySHA256 != m.ImageProfile.BinarySHA256 || d.Binding.ConfigurationSHA256 != m.ImageProfile.ConfigurationSHA256 {
		return nil, invalid("UPDATE_CACHE_PROFILE_CHANGED")
	}
	if !canonical(d.ImagePath) || strings.Contains(d.ImagePath, ",") {
		return nil, invalid("UPDATE_CACHE_PATH_INVALID")
	}
	fd, err := unix.Open(d.ImagePath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), d.ImagePath)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(before.Mode)&07777 != 0400 || before.Uid != uint32(os.Getuid()) || before.Nlink != 1 ||
		uint64(before.Dev) != d.Image.Device || before.Ino != d.Image.Inode || before.Size != d.Image.Bytes || before.Mtim.Sec*1e9+before.Mtim.Nsec != d.Image.ModifiedNS || before.Ctim.Sec*1e9+before.Ctim.Nsec != d.Image.ChangedNS {
		return nil, invalid("UPDATE_CACHE_IDENTITY_CHANGED")
	}
	if verifyContents {
		h := sha256.New()
		if n, err := io.CopyN(h, f, before.Size); err != nil || n != before.Size || hex.EncodeToString(h.Sum(nil)) != d.Image.SHA256 {
			return nil, invalid("UPDATE_CACHE_HASH_CHANGED")
		}
		var extra [1]byte
		if n, err := f.Read(extra[:]); n != 0 || err != io.EOF {
			return nil, invalid("UPDATE_CACHE_CHANGED")
		}
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(d.ImagePath, &named) != nil || identity(before) != identity(after) || identity(before) != identity(named) {
		return nil, invalid("UPDATE_CACHE_CHANGED")
	}
	return cache, nil
}

var shellSafe = regexp.MustCompile(`^[a-zA-Z0-9_@%+=:,./-]+$`)

func shellQuote(value string) string {
	if value != "" && shellSafe.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func qemuArguments(qemu, run, requestPath, requestSHA string, m Manifest, cache object) []string {
	build := filepath.Dir(m.Build)
	forward := []string{m.Helper, "--forward", "--request", requestPath, "--request-sha256", requestSHA}
	for i, part := range forward {
		forward[i] = shellQuote(part)
	}
	network := "user,id=official,restrict=on,ipv6=off,guestfwd=tcp:10.0.2.100:443-cmd:" + strings.ReplaceAll(strings.Join(forward, " "), ",", ",,")
	args := []string{qemu, "-machine", "virt-11.1,gic-version=3", "-accel", "hvf", "-cpu", "host", "-smp", "2", "-m", "4096", "-nodefaults", "-no-user-config", "-display", "none", "-serial", "null", "-monitor", "none", "-no-reboot", "-kernel", filepath.Join(build, "kernel"), "-initrd", filepath.Join(build, "initramfs.cpio.gz"), "-append", "console=ttyAMA0 panic=-1 quiet", "-chardev", "socket,id=channel,path=" + filepath.Join(run, "channel.sock") + ",server=on,wait=off", "-device", "virtio-serial-pci,id=serial", "-device", "virtserialport,chardev=channel,name=org.filegate.probe", "-netdev", network, "-device", "virtio-net-pci,netdev=official"}
	definitions := filepath.Join(build, "definitions.ext4")
	if cache != nil {
		definitions = hostvm.Str(cache, "image_path")
	}
	for _, drive := range []struct{ name, path, ro string }{{"base", filepath.Join(build, "base.ext4"), "on"}, {"definitions", definitions, "on"}, {"work", filepath.Join(run, "work.raw"), "off"}} {
		raw := "driver=raw,node-name=" + drive.name + ",file=" + drive.name + "-file,read-only=" + drive.ro + ",discard=ignore"
		if drive.ro == "off" {
			raw += ",size=4294967296"
		}
		args = append(args, "-blockdev", "driver=file,node-name="+drive.name+"-file,filename="+drive.path+",read-only="+drive.ro+",discard=ignore", "-blockdev", raw, "-device", "virtio-blk-pci,drive="+drive.name+",rerror=stop,werror=stop")
	}
	return args
}

// pinnedTools selects QEMU from the workspace build receipt and requires the registration to pin every file of that closure with the same digest.
func pinnedTools(m Manifest) (qemuruntime.Manifest, error) {
	runtime, err := hostvm.New(m.Workspace)
	if err != nil {
		return qemuruntime.Manifest{}, err
	}
	tools, err := runtime.QEMURuntime()
	if err != nil {
		return tools, err
	}
	for path, digest := range tools.Files() {
		if m.SHA256[path] != digest {
			return tools, invalid("UPDATE_TOOL_PIN_MISSING")
		}
	}
	return tools, nil
}

func checkedRun(path string) error {
	if !canonical(path) || filepath.Dir(path) != "/private/tmp" || !regexp.MustCompile(`^filegate-vm-[0-9a-f]{32}$`).MatchString(filepath.Base(path)) {
		return invalid("UPDATE_RUN_DIRECTORY_INVALID")
	}
	if _, err := owned(path, unix.S_IFDIR, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		return invalid("UPDATE_RUN_DIRECTORY_NOT_EMPTY")
	}
	return nil
}

func Prepare(ctx context.Context, manifestPath, requestPath, run string) error {
	m, _, pins, err := registration(manifestPath, true)
	if err != nil {
		return err
	}
	_, r, value, requestSHA, err := load(manifestPath, requestPath)
	if err != nil {
		return err
	}
	if err = checkedRun(run); err != nil {
		return err
	}
	if m.FixtureOnly {
		runtime, err := hostvm.New(m.Workspace)
		if err != nil {
			return err
		}
		if _, err = runtime.PrepareFixture(ctx, run, "freshclam-adapter"); err != nil {
			return err
		}
		for path, expected := range pins {
			var current unix.Stat_t
			if unix.Lstat(path, &current) != nil || identity(current) != expected {
				return invalid("UPDATE_SOURCE_CHANGED")
			}
		}
		return nil
	}
	cache, err := checkedCache(requestPath, r, value, m, true)
	if err != nil {
		return err
	}
	b, err := readBuild(m)
	if err != nil {
		return err
	}
	tools, err := pinnedTools(m)
	if err != nil {
		return err
	}
	qemu, image := tools.System().Path, tools.Image().Path
	versionCommand := exec.CommandContext(ctx, qemu, "--version")
	versionCommand.Env = qemuruntime.Environment()
	version, err := versionCommand.Output()
	parts := strings.Fields(strings.SplitN(string(version), "\n", 2)[0])
	var fs unix.Statfs_t
	if err != nil || len(parts) < 4 || parts[3] != "11.1.2" || unix.Statfs(run, &fs) != nil || uint64(fs.Bavail)*uint64(fs.Bsize) < 6<<30 {
		return invalid("UPDATE_PREPARATION_REJECTED")
	}
	create := exec.CommandContext(ctx, image, "create", "-f", "raw", "-o", "preallocation=full", filepath.Join(run, "work.raw"), "4294967296")
	create.Env = qemuruntime.Environment()
	if err = create.Run(); err != nil {
		return err
	}
	if err = os.Chmod(filepath.Join(run, "work.raw"), 0600); err != nil {
		return err
	}
	raw, err := owned(filepath.Join(run, "work.raw"), unix.S_IFREG, 0600)
	if err != nil || raw.Size != rawBytes || raw.Blocks*512 < rawBytes {
		return invalid("UPDATE_RAW_INVALID")
	}
	for path, expected := range pins {
		var current unix.Stat_t
		if unix.Lstat(path, &current) != nil || identity(current) != expected {
			return invalid("UPDATE_SOURCE_CHANGED")
		}
	}
	currentCache, err := checkedCache(requestPath, r, value, m, false)
	if err != nil || !hostvm.Equal(currentCache, cache) {
		return invalid("UPDATE_CACHE_CHANGED")
	}
	record := object{"schema": 4, "profile": m.Profile, "run_directory": run, "definition_cache": cache, "argv": qemuArguments(qemu, run, requestPath, requestSHA, m, cache), "qemu_sha256": m.SHA256[qemu], "qemu_version": strings.SplitN(string(version), "\n", 2)[0], "raw": object{"size": raw.Size, "allocated_bytes": raw.Blocks * 512}, "artifacts_sha256": b.ArtifactsSHA256, "pin_identities": pins, "manifest_sha256": r.ManifestSHA256, "request_path": requestPath, "request_sha256": requestSHA}
	body, err := json.Marshal(record)
	if err != nil || len(body) > 1<<20 {
		return invalid("UPDATE_PREPARED_LIMIT")
	}
	fd, err := unix.Open(filepath.Join(run, "prepared.json"), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "prepared")
	n, err := file.Write(body)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return hostvm.SyncDirectory(run)
}

func PreparedConfig(runtime *hostvm.Runtime, path, manifestPath, requestPath string, m Manifest, r Request, requestSHA string) (object, error) {
	p, _, err := hostvm.Read(path, 1<<20)
	if err != nil || !fields(p, "schema profile run_directory argv qemu_sha256 qemu_version raw artifacts_sha256 pin_identities manifest_sha256 request_path request_sha256 definition_cache") || hostvm.Int(p, "schema") != 4 || hostvm.Str(p, "profile") != Profile || hostvm.Str(p, "manifest_sha256") != r.ManifestSHA256 || hostvm.Str(p, "request_sha256") != requestSHA {
		return nil, invalid("UPDATE_PREPARED_INVALID")
	}
	var pins map[string]fileIdentity
	body, err := json.Marshal(p["pin_identities"])
	if err != nil || strict(body, &pins) != nil || len(pins) != len(m.SHA256) {
		return nil, invalid("UPDATE_SOURCE_PINS_INVALID")
	}
	for name, expected := range pins {
		var current unix.Stat_t
		if !canonical(name) || unix.Lstat(name, &current) != nil || identity(current) != expected || !digestPattern.MatchString(m.SHA256[name]) {
			return nil, invalid("UPDATE_SOURCE_CHANGED")
		}
	}
	run := hostvm.Str(p, "run_directory")
	if _, err = owned(run, unix.S_IFDIR, 0700); err != nil || path != filepath.Join(run, "prepared.json") {
		return nil, invalid("UPDATE_RUN_DIRECTORY_INVALID")
	}
	_, _, requested, currentRequestSHA, err := load(manifestPath, requestPath)
	if err != nil || currentRequestSHA != requestSHA {
		return nil, invalid("UPDATE_REQUEST_BINDING_CHANGED")
	}
	cache, err := checkedCache(requestPath, r, requested, m, false)
	if err != nil || !hostvm.Equal(cache, p["definition_cache"]) {
		return nil, invalid("UPDATE_CACHE_CHANGED")
	}
	var argv []string
	body, err = json.Marshal(p["argv"])
	if err != nil || json.Unmarshal(body, &argv) != nil || len(argv) == 0 || !reflect.DeepEqual(argv, qemuArguments(argv[0], run, requestPath, requestSHA, m, cache)) || hostvm.Str(p, "request_path") != requestPath {
		return nil, invalid("UPDATE_ARGUMENTS_CHANGED")
	}
	qemu := argv[0]
	version := strings.Fields(hostvm.Str(p, "qemu_version"))
	if filepath.Base(qemu) != "qemu-system-aarch64" || !canonical(qemu) || hostvm.Str(p, "qemu_sha256") != m.SHA256[qemu] || len(version) < 4 || version[3] != "11.1.2" {
		return nil, invalid("UPDATE_QEMU_CHANGED")
	}
	if tools, err := pinnedTools(m); err != nil || qemu != tools.System().Path || hostvm.Str(p, "qemu_sha256") != tools.System().SHA256 {
		return nil, invalid("UPDATE_QEMU_CHANGED")
	}
	raw, err := owned(filepath.Join(run, "work.raw"), unix.S_IFREG, 0600)
	if err != nil || raw.Size != rawBytes || raw.Blocks*512 < rawBytes || hostvm.Int(hostvm.Map(p, "raw"), "size") != rawBytes {
		return nil, invalid("UPDATE_RAW_INVALID")
	}
	b, err := readBuild(m)
	actual, _ := json.Marshal(p["artifacts_sha256"])
	expected, _ := json.Marshal(b.ArtifactsSHA256)
	if err != nil || !bytes.Equal(actual, expected) {
		return nil, invalid("UPDATE_IMAGE_BINDING_CHANGED")
	}
	proof, _, err := hostvm.Read(m.Proof, 4<<20)
	hostVersion, hostErr := runtime.HostVersion()
	platform, platformErr := runtime.NativePlatform()
	if err != nil || hostErr != nil || platformErr != nil || hostvm.Str(proof, "kind") != "launchagent_death" ||
		proof["passed"] != true || proof["guardian_result_verified"] != true || proof["cleanup_all_exited"] != true || proof["guardian_fixture_vm_sigkill_confirmed"] != true || proof["all_exited_without_child_signal"] != true || proof["normal_completion_disabled"] != true || proof["stop_events_observed"] != false || proof["temporary_service_absent"] != true || proof["emergency_owned_cleanup"] == true || !hostvm.Equal(proof["host"], hostVersion) || !hostvm.Equal(proof["native_platform"], platform) {
		return nil, invalid("UPDATE_NATIVE_PROOF_INVALID")
	}
	nativeSHA, err := hostvm.HashFile(runtime.NativeBinary)
	sourceSHA, sourceErr := hostvm.HashFile(filepath.Join(runtime.Root, "experiments/host/integrated_watchdog.m"))
	if err != nil || sourceErr != nil || hostvm.Str(proof, "binary_sha256") != nativeSHA || hostvm.Str(proof, "native_source_sha256") != sourceSHA {
		return nil, invalid("UPDATE_NATIVE_PROOF_INVALID")
	}
	build := filepath.Dir(m.Build)
	helperPins := map[string]string{}
	for _, name := range []string{m.Runner, m.Helper, filepath.Join(build, "kernel"), filepath.Join(build, "initramfs.cpio.gz"), filepath.Join(build, "base.ext4"), filepath.Join(build, "definitions.ext4"), m.Build} {
		if !digestPattern.MatchString(m.SHA256[name]) {
			return nil, invalid("UPDATE_IMAGE_CHANGED")
		}
		helperPins[name] = m.SHA256[name]
	}
	if r.Definition != nil {
		helperPins[r.Definition.ImagePath] = r.Definition.Image.SHA256
	}
	return object{"mode": "qemu", "run_directory": run, "vm_argv": argv, "helper_argv": []string{m.Helper, run, "--request", requestPath, "--request-sha256", requestSHA, "--watchdog-relay"}, "helper_pins": helperPins, "qemu_sha256": hostvm.Str(p, "qemu_sha256"), "launch_proof_path": m.Proof, "require_launchagent": true, "expected_stop_reason": "EXCHANGE_COMPLETE", "fixture": "product-update"}, nil
}
