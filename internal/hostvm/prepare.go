package hostvm

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"filegate.local/filegate/internal/qemuruntime"
	"golang.org/x/sys/unix"
)

func (r *Runtime) scopedFile(base, name string) (string, error) {
	if filepath.IsAbs(name) || strings.ContainsRune(name, 0) {
		return "", Error("BUILD_SOURCE_SCOPE_INVALID")
	}
	path := filepath.Clean(filepath.Join(base, name))
	rel, e := filepath.Rel(r.Root, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", Error("BUILD_SOURCE_SCOPE_INVALID")
	}
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if strings.HasPrefix(part, ".env") || part == "secrets" || part == "credentials" || part == "client.json" || part == ".git" {
			return "", Error("BUILD_SOURCE_SCOPE_INVALID")
		}
	}
	actual, e := filepath.EvalSymlinks(path)
	if e != nil || actual != path {
		return "", Error("BUILD_SOURCE_PATH_INVALID")
	}
	var s unix.Stat_t
	if e = unix.Lstat(path, &s); e != nil || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Uid != uint32(os.Getuid()) {
		return "", Error("BUILD_SOURCE_OWNER_INVALID")
	}
	return path, nil
}
func (r *Runtime) VerifyBuild() (Object, error) {
	receipt, _, e := Read(filepath.Join(r.VM, "evidence/build.json"), 4<<20)
	if e != nil {
		return nil, e
	}
	if Int(receipt, "schema") != 4 || Str(receipt, "evidence_kind") != "derived_format_VM_construction_only" || len(Map(receipt, "product_sources_sha256")) < 16 || len(Map(receipt, "product_sources_sha256")) > 512 || len(Map(receipt, "artifacts")) > 32 {
		return nil, Error("BUILD_RECEIPT_SCHEMA_INVALID")
	}
	for _, base := range []string{"cmd", "internal"} {
		e = filepath.WalkDir(filepath.Join(r.Root, base), func(path string, entry fs.DirEntry, walkError error) error {
			if walkError != nil {
				return walkError
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return Error("BUILD_SOURCE_PATH_INVALID")
			}
			if entry.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".go", ".c", ".h", ".m", ".s", ".S", ".html", ".css", ".js", ".json":
				relative, e := filepath.Rel(r.Root, path)
				if e != nil || !digestPattern.MatchString(Str(Map(receipt, "product_sources_sha256"), filepath.ToSlash(relative))) {
					return Error("BUILD_SOURCE_PIN_MISSING")
				}
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	for _, name := range []string{"go.mod", "go.sum", "experiments/host/integrated_watchdog.m", "experiments/vm/init", "experiments/vm/fixtures.json"} {
		if !digestPattern.MatchString(Str(Map(receipt, "product_sources_sha256"), name)) {
			return nil, Error("BUILD_SOURCE_PIN_MISSING")
		}
	}
	maps := []struct {
		name, base string
		required   bool
	}{{"artifacts", r.VM, true}, {"sources_sha256", r.VM, true}, {"external_sources_sha256", filepath.Join(r.Root, "experiments"), false}, {"product_sources_sha256", r.Root, true}}
	for _, group := range maps {
		pins := Map(receipt, group.name)
		if group.required && len(pins) == 0 {
			return nil, Error("BUILD_SOURCE_PINS_MISSING")
		}
		for name, want := range pins {
			expected, ok := want.(string)
			if !ok || !digestPattern.MatchString(expected) || strings.HasSuffix(name, ".py") {
				return nil, Error("BUILD_SOURCE_PIN_INVALID")
			}
			path, e := r.scopedFile(group.base, name)
			if e != nil {
				return nil, e
			}
			actual, e := HashFile(path)
			if e != nil || actual != expected {
				return nil, Error("BUILD_SOURCE_CHANGED")
			}
		}
	}
	for _, field := range []string{"host_runner", "host_update_runner"} {
		pin := Map(receipt, field)
		name := "filegate-vm"
		if field == "host_update_runner" {
			name = "filegate-update"
		}
		if !Fields(pin, "path", "sha256") || Str(pin, "path") != filepath.Join(r.Root, ".build", name) || !digestPattern.MatchString(Str(pin, "sha256")) {
			return nil, Error("BUILD_HOST_RUNNER_PIN_INVALID")
		}
		if _, e = Owned(Str(pin, "path"), unix.S_IFREG, 0500); e != nil {
			return nil, e
		}
		actual, e := HashFile(Str(pin, "path"))
		if e != nil || actual != Str(pin, "sha256") {
			return nil, Error("BUILD_HOST_RUNNER_CHANGED")
		}
	}
	for _, file := range []string{"base.ext4", "definitions.ext4", "initramfs.cpio.gz", "filegate-bridge"} {
		if !digestPattern.MatchString(Str(Map(receipt, "artifacts"), ".build/"+file)) {
			return nil, Error("BUILD_ARTIFACT_PIN_MISSING")
		}
	}
	return receipt, nil
}

// QEMURuntime returns the fixed QEMU configuration frozen in the verified build receipt after re-verifying it against the current files.
func (r *Runtime) QEMURuntime() (qemuruntime.Manifest, error) {
	receipt, e := r.VerifyBuild()
	if e != nil {
		return qemuruntime.Manifest{}, e
	}
	return qemuRuntime(receipt)
}
func qemuRuntime(receipt Object) (qemuruntime.Manifest, error) {
	m, e := qemuruntime.Decode(receipt["qemu_runtime"])
	if e != nil {
		return m, e
	}
	_, e = qemuruntime.Verify(m)
	return m, e
}
func QEMUArgs(qemu, vm, run, definition string) []string {
	args := []string{qemu, "-machine", "virt-11.1,gic-version=3", "-accel", "hvf", "-cpu", "host", "-smp", "2", "-m", "4096", "-nodefaults", "-no-user-config", "-nic", "none", "-display", "none", "-serial", "null", "-monitor", "none", "-no-reboot", "-kernel", filepath.Join(vm, ".cache/boot/vmlinuz-virt"), "-initrd", filepath.Join(vm, ".build/initramfs.cpio.gz"), "-append", "console=ttyAMA0 panic=-1 quiet", "-chardev", "socket,id=channel,path=" + filepath.Join(run, "channel.sock") + ",server=on,wait=off", "-device", "virtio-serial-pci,id=serial", "-device", "virtserialport,chardev=channel,name=org.filegate.probe"}
	for _, d := range []struct {
		name, path string
		ro         bool
	}{{"base", filepath.Join(vm, ".build/base.ext4"), true}, {"definitions", definition, true}, {"work", filepath.Join(run, "work.raw"), false}} {
		ro := "off"
		size := ",size=4294967296"
		if d.ro {
			ro = "on"
			size = ""
		}
		args = append(args, "-blockdev", "driver=file,node-name="+d.name+"-file,filename="+d.path+",read-only="+ro+",discard=ignore", "-blockdev", "driver=raw,node-name="+d.name+",file="+d.name+"-file,read-only="+ro+",discard=ignore"+size, "-device", "virtio-blk-pci,drive="+d.name+",rerror=stop,werror=stop")
	}
	return args
}
func checkedRun(run string) error {
	actual, e := filepath.EvalSymlinks(run)
	if e != nil || actual != run || !runPattern.MatchString(run) {
		return Error("PREPARATION_DIRECTORY_SCOPE_INVALID")
	}
	if _, e = Owned(run, unix.S_IFDIR, 0700); e != nil {
		return e
	}
	entries, e := os.ReadDir(run)
	if e != nil || len(entries) != 0 {
		return Error("PREPARATION_DIRECTORY_NOT_EMPTY")
	}
	return nil
}
func (r *Runtime) PrepareScan(ctx context.Context, run, request string) (Object, error) {
	if request == "" {
		return nil, Error("PRODUCT_DEFINITION_REQUEST_REQUIRED")
	}
	req, e := ReadScanRequest(request, false)
	if e != nil {
		return nil, e
	}
	if Int(req, "schema_version") == 2 {
		return r.prepare(ctx, run, "", "")
	}
	return r.prepare(ctx, run, request, "")
}
func (r *Runtime) PrepareFixture(ctx context.Context, run, fixture string) (Object, error) {
	if !fixtureAllowed(fixture) {
		return nil, Error("UNKNOWN_NATIVE_FIXTURE")
	}
	return r.prepare(ctx, run, "", fixture)
}

// blockIOFixture alone gets a private QMP socket for its fixed internal arming; product and other fixture argv stay exactly QEMUArgs.
const blockIOFixture = "workspace-block-io"

func fixtureQEMUArgs(fixture string, args []string, run string) []string {
	if fixture != blockIOFixture {
		return args
	}
	return append(append([]string{}, args...), "-qmp", "unix:"+filepath.Join(run, "qmp.sock")+",server=on,wait=off")
}
func (r *Runtime) prepare(ctx context.Context, run, request, fixture string) (Object, error) {
	if e := checkedRun(run); e != nil {
		return nil, e
	}
	var definition Object
	var e error
	definitionPath := filepath.Join(r.VM, ".build/definitions.ext4")
	if request != "" {
		definition, e = SelectedDefinition(request, true)
		if e != nil {
			return nil, e
		}
		definitionPath = Str(definition, "image_path")
	}
	receipt, e := r.VerifyBuild()
	if e != nil {
		return nil, e
	}
	var base, fixed unix.Stat_t
	if unix.Lstat(filepath.Join(r.VM, ".build/base.ext4"), &base) != nil || base.Size != 1<<30 || unix.Lstat(filepath.Join(r.VM, ".build/definitions.ext4"), &fixed) != nil || fixed.Size != 16<<20 {
		return nil, Error("READONLY_IMAGE_CAPACITY_INVALID")
	}
	tools, e := qemuRuntime(receipt)
	if e != nil {
		return nil, e
	}
	qemu, image := tools.System().Path, tools.Image().Path
	version, e := boundedCommand(ctx, []string{qemu, "--version"}, 15*time.Second, 65536)
	if e != nil {
		return nil, e
	}
	qline := strings.Split(string(version), "\n")[0]
	parts := strings.Fields(qline)
	if len(parts) < 4 || parts[3] != "11.1.2" {
		return nil, Error("QEMU_VERSION_PIN_INVALID")
	}
	ib, e := boundedCommand(ctx, []string{image, "--version"}, 15*time.Second, 65536)
	if e != nil {
		return nil, e
	}
	parts = strings.Fields(strings.Split(string(ib), "\n")[0])
	if len(parts) < 3 || parts[2] != "11.1.2" {
		return nil, Error("QEMU_IMAGE_VERSION_PIN_INVALID")
	}
	var fs unix.Statfs_t
	if e = unix.Statfs(run, &fs); e != nil || uint64(fs.Bavail)*uint64(fs.Bsize) < 6<<30 {
		return nil, Error("DISK_PRESSURE")
	}
	started := time.Now()
	if _, e = boundedCommand(ctx, []string{image, "create", "-f", "raw", "-o", "preallocation=full", filepath.Join(run, "work.raw"), "4294967296"}, 120*time.Second, 65536); e != nil {
		return nil, e
	}
	if e = os.Chmod(filepath.Join(run, "work.raw"), 0600); e != nil {
		return nil, e
	}
	raw, e := Owned(filepath.Join(run, "work.raw"), unix.S_IFREG, 0600)
	if e != nil || raw.Size != RawBytes || raw.Blocks*512 < RawBytes {
		return nil, Error("RAW_CAPACITY_INVALID")
	}
	qsha := tools.System().SHA256
	baseSHA, e := HashFile(filepath.Join(r.VM, ".build/base.ext4"))
	if e != nil {
		return nil, e
	}
	kernel, e := HashFile(filepath.Join(r.VM, ".cache/boot/vmlinuz-virt"))
	if e != nil {
		return nil, e
	}
	initramfs, e := HashFile(filepath.Join(r.VM, ".build/initramfs.cpio.gz"))
	if e != nil {
		return nil, e
	}
	definitionSHA := ""
	if request != "" {
		if current, e := SelectedDefinition(request, false); e != nil || !Equal(current, definition) {
			return nil, Error("PRODUCT_DEFINITION_IMAGE_CHANGED")
		}
		definitionSHA = Str(Map(definition, "image"), "sha256")
	} else {
		definitionSHA, e = HashFile(definitionPath)
		if e != nil {
			return nil, e
		}
	}
	prepared := Object{"schema": 2, "block_io_fault": fixture == blockIOFixture, "run_directory": run, "argv": fixtureQEMUArgs(fixture, QEMUArgs(qemu, r.VM, run, definitionPath), run), "qemu_version": qline, "qemu_sha256": qsha, "raw": Object{"size": raw.Size, "allocated_bytes": raw.Blocks * 512, "full_preallocation_seconds": time.Since(started).Seconds()}, "images_before": Object{"base": baseSHA, "definitions": definitionSHA}, "boot_artifacts": Object{"kernel": kernel, "initramfs": initramfs}, "status": "prepared_not_started"}
	if request != "" {
		prepared["schema"] = 3
		prepared["definition"] = definition
	}
	body, e := Encoded(prepared)
	if e != nil || int64(len(body)) > ControlLimit {
		return nil, Error("PREPARATION_RECORD_INVALID")
	}
	if e = create(filepath.Join(run, "prepared.json"), body, 0600); e != nil {
		return nil, e
	}
	if e = SyncDirectory(run); e != nil {
		return nil, e
	}
	return prepared, nil
}
func (r *Runtime) PreparedConfig(path, proofPath, fixture, requestPath string) (Object, Object, error) {
	if fixture != "product-inspect" || requestPath == "" {
		return nil, nil, Error("PREPARED_PROFILE_INVALID")
	}
	return r.preparedConfig(path, proofPath, fixture, requestPath)
}
func (r *Runtime) PreparedFixtureConfig(path, proofPath, fixture string) (Object, Object, error) {
	if !fixtureAllowed(fixture) {
		return nil, nil, Error("UNKNOWN_NATIVE_FIXTURE")
	}
	return r.preparedConfig(path, proofPath, fixture, "")
}
func (r *Runtime) preparedConfig(path, proofPath, fixture, requestPath string) (Object, Object, error) {
	prepared, _, e := Read(path, ControlLimit)
	if e != nil {
		return nil, nil, e
	}
	fields := []string{"schema", "run_directory", "argv", "qemu_version", "qemu_sha256", "raw", "images_before", "boot_artifacts", "status", "block_io_fault"}
	wantedSchema := int64(2)
	if requestPath != "" {
		req, e := ReadScanRequest(requestPath, false)
		if e != nil {
			return nil, nil, e
		}
		if Int(req, "schema_version") == 3 {
			fields = append(fields, "definition")
			wantedSchema = 3
		}
	}
	if !Fields(prepared, fields...) || Int(prepared, "schema") != wantedSchema || Str(prepared, "status") != "prepared_not_started" || prepared["block_io_fault"] != (fixture == blockIOFixture) {
		return nil, nil, Error("PREPARED_SCHEMA_INVALID")
	}
	run := Str(prepared, "run_directory")
	if !runPattern.MatchString(run) || path != filepath.Join(run, "prepared.json") || requestPath != "" && requestPath != filepath.Join(run, "product-request.json") {
		return nil, nil, Error("PREPARED_SCOPE_INVALID")
	}
	if _, e = Owned(run, unix.S_IFDIR, 0700); e != nil {
		return nil, nil, e
	}
	var definition Object
	definitionPath := filepath.Join(r.VM, ".build/definitions.ext4")
	if wantedSchema == 3 {
		definition, e = SelectedDefinition(requestPath, false)
		if e != nil || !Equal(prepared["definition"], definition) {
			return nil, nil, Error("PRODUCT_DEFINITION_IMAGE_CHANGED")
		}
		definitionPath = Str(definition, "image_path")
	}
	args, ok := Strings(prepared["argv"])
	if !ok || len(args) == 0 || !Equal(args, fixtureQEMUArgs(fixture, QEMUArgs(args[0], r.VM, run, definitionPath), run)) {
		return nil, nil, Error("QEMU_ARGUMENTS_INVALID")
	}
	qemu := args[0]
	actual, e := filepath.EvalSymlinks(qemu)
	if e != nil || actual != qemu || filepath.Base(qemu) != "qemu-system-aarch64" || !filepath.IsAbs(qemu) {
		return nil, nil, Error("QEMU_EXECUTABLE_INVALID")
	}
	qsha, e := HashFile(qemu)
	if e != nil || qsha != Str(prepared, "qemu_sha256") {
		return nil, nil, Error("QEMU_EXECUTABLE_CHANGED")
	}
	version := strings.Fields(Str(prepared, "qemu_version"))
	if len(version) < 4 || version[3] != "11.1.2" {
		return nil, nil, Error("QEMU_VERSION_PIN_INVALID")
	}
	raw, e := Owned(filepath.Join(run, "work.raw"), unix.S_IFREG, 0600)
	if e != nil || raw.Size != RawBytes || raw.Blocks*512 < RawBytes || Int(Map(prepared, "raw"), "size") != RawBytes {
		return nil, nil, Error("RAW_CAPACITY_INVALID")
	}
	receipt, e := r.VerifyBuild()
	if e != nil {
		return nil, nil, e
	}
	tools, e := qemuRuntime(receipt)
	if e != nil {
		return nil, nil, e
	}
	if qemu != tools.System().Path || qsha != tools.System().SHA256 {
		return nil, nil, Error("QEMU_RUNTIME_PIN_MISMATCH")
	}
	for name, path := range map[string]string{"base": filepath.Join(r.VM, ".build/base.ext4"), "definitions": definitionPath} {
		want := Str(Map(prepared, "images_before"), name)
		actual := ""
		if name == "definitions" && definition != nil {
			actual = Str(Map(definition, "image"), "sha256")
		} else {
			actual, e = HashFile(path)
		}
		if e != nil || actual != want {
			return nil, nil, Error("READONLY_IMAGE_CHANGED")
		}
	}
	for name, path := range map[string]string{"kernel": filepath.Join(r.VM, ".cache/boot/vmlinuz-virt"), "initramfs": filepath.Join(r.VM, ".build/initramfs.cpio.gz")} {
		actual, e := HashFile(path)
		if e != nil || actual != Str(Map(prepared, "boot_artifacts"), name) {
			return nil, nil, Error("BOOT_ARTIFACT_CHANGED")
		}
	}
	if e = r.ValidateLaunchProof(proofPath); e != nil {
		return nil, nil, e
	}
	catalog, _, e := ReadAsset(filepath.Join(r.VM, "fixtures.json"), 4<<20)
	if e != nil {
		return nil, nil, e
	}
	contract := Map(Map(catalog, "fixtures"), fixture)
	if Int(catalog, "schema") != 1 || contract == nil {
		return nil, nil, Error("UNKNOWN_NATIVE_FIXTURE")
	}
	helper := filepath.Join(r.VM, ".build/filegate-bridge")
	if _, e = Owned(helper, unix.S_IFREG, 0500); e != nil {
		return nil, nil, e
	}
	helperSHA, e := HashFile(helper)
	if e != nil || helperSHA != Str(Map(receipt, "artifacts"), ".build/filegate-bridge") {
		return nil, nil, Error("PRODUCT_HELPER_CHANGED")
	}
	pinPaths := []string{r.Executable, helper, filepath.Join(r.VM, "fixtures.json"), filepath.Join(r.VM, ".cache/boot/vmlinuz-virt"), filepath.Join(r.VM, ".build/initramfs.cpio.gz"), filepath.Join(r.VM, ".build/base.ext4"), definitionPath, filepath.Join(r.VM, "evidence/build.json")}
	pins := Object{}
	for _, p := range pinPaths {
		sha, e := HashFile(p)
		if e != nil {
			return nil, nil, e
		}
		pins[p] = sha
	}
	helperArgs := []string{helper, run, "--fixture", fixture, "--watchdog-relay"}
	if requestPath != "" {
		requestSHA, e := HashFile(requestPath)
		if e != nil {
			return nil, nil, e
		}
		helperArgs = append(helperArgs, "--product-request", requestPath, "--product-request-sha256", requestSHA)
	}
	return Object{"mode": "qemu", "run_directory": run, "vm_argv": args, "helper_argv": helperArgs, "helper_pins": pins, "qemu_sha256": prepared["qemu_sha256"], "launch_proof_path": proofPath, "require_launchagent": true, "expected_stop_reason": contract["expected_stop_reason"], "fixture": fixture, "fixture_contract": contract, "fixture_catalog_sha256": pins[filepath.Join(r.VM, "fixtures.json")]}, prepared, nil
}
func (r *Runtime) ValidateLaunchProof(path string) error {
	proof, _, e := Read(path, 4<<20)
	if e != nil {
		return e
	}
	host, e := r.HostVersion()
	if e != nil {
		return e
	}
	platform, e := r.NativePlatform()
	if e != nil {
		return e
	}
	binary, e := HashFile(r.NativeBinary)
	if e != nil {
		return e
	}
	source, e := HashFile(r.NativeSource)
	if e != nil {
		return e
	}
	if Str(proof, "kind") != "launchagent_death" || proof["passed"] != true || proof["guardian_result_verified"] != true || proof["cleanup_all_exited"] != true || proof["guardian_fixture_vm_sigkill_confirmed"] != true || proof["all_exited_without_child_signal"] != true || proof["normal_completion_disabled"] != true || proof["stop_events_observed"] != false || proof["temporary_service_absent"] != true || proof["emergency_owned_cleanup"] == true || !Equal(proof["host"], host) || !Equal(proof["native_platform"], platform) || Str(proof, "binary_sha256") != binary || Str(proof, "native_source_sha256") != source {
		return Error("NATIVE_LAUNCH_PROOF_MISMATCH")
	}
	return nil
}

type boundedWriter struct {
	body     []byte
	limit    int
	overflow bool
}

func (w *boundedWriter) Write(b []byte) (int, error) {
	n := len(b)
	remaining := w.limit - len(w.body)
	if len(b) > remaining {
		w.body = append(w.body, b[:remaining]...)
		w.overflow = true
		return n, Error("CONTROL_OUTPUT_LIMIT")
	}
	w.body = append(w.body, b...)
	return n, nil
}
func boundedCommand(parent context.Context, args []string, timeout time.Duration, limit int) ([]byte, error) {
	ctx, c := context.WithTimeout(parent, timeout)
	defer c()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = qemuruntime.Environment()
	writer := &boundedWriter{limit: limit}
	cmd.Stdout = writer
	cmd.Stderr = writer
	e := cmd.Run()
	if writer.overflow {
		return nil, Error("CONTROL_OUTPUT_LIMIT")
	}
	return writer.body, e
}
