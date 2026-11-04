package buildtools

import (
	"compress/gzip"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"filegate.local/filegate/internal/av"
)

func freshclamSources(repository string) (map[string]string, error) {
	result := map[string]string{}
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(repository, name)
		value, err := SHA(path)
		if err != nil {
			return nil, err
		}
		result[name] = value
	}
	for _, base := range []string{"cmd/filegate-freshclam", "internal/freshclamadapter"} {
		entries, err := os.ReadDir(filepath.Join(repository, base))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			switch filepath.Ext(entry.Name()) {
			case ".go", ".c", ".h":
				name := filepath.ToSlash(filepath.Join(base, entry.Name()))
				value, err := SHA(filepath.Join(repository, name))
				if err != nil {
					return nil, err
				}
				result[name] = value
			}
		}
	}
	return result, nil
}

func verifyFreshclam(repository, binary, receipt string) error {
	value, err := object(receipt)
	if err != nil {
		return err
	}
	expected, err := freshclamSources(repository)
	if err != nil {
		return err
	}
	sources, err := nested(value, "sources_sha256")
	if err != nil {
		return err
	}
	actual := map[string]string{}
	for name, hash := range sources {
		value, ok := hash.(string)
		if !ok {
			return errors.New("freshclam source digest required")
		}
		actual[name] = value
	}
	if number(value, "schema") != 1 || str(value, "target") != "linux/arm64" || str(value, "libc") != "musl" || !isTrue(value, "passed") || str(value, "binary_sha256") != mustSHA(binary) || !reflect.DeepEqual(actual, expected) {
		return errors.New("UPDATE_ADAPTER_BUILD_BINDING")
	}
	info, err := os.Stat(binary)
	if err != nil || info.Size() <= 0 || info.Size() > 64<<20 {
		return errors.New("UPDATE_ADAPTER_BUILD_LIMIT")
	}
	file, err := elf.Open(binary)
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_AARCH64 {
		return errors.New("AArch64 ELF64 freshclam required")
	}
	return nil
}

func buildImageTools(ctx context.Context) (map[string]string, error) {
	result := map[string]string{}
	for name, path := range map[string]string{"mke2fs": "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs", "debugfs": "/opt/homebrew/opt/e2fsprogs/sbin/debugfs", "mke2fs_config": "/opt/homebrew/etc/mke2fs.conf"} {
		actual, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		result[name] = actual
	}
	for _, name := range []string{"mke2fs", "debugfs"} {
		if err := toolVersion(ctx, result[name], name); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func extractInitramfs(ctx context.Context, path, directory string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	archive, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer archive.Close()
	cmd := exec.CommandContext(ctx, "bsdtar", "-xf", "-", "-C", directory)
	cmd.Stdin = archive
	cmd.Stdout = io.Discard
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("initramfs extraction failed: %w: %s", err, stderr.String())
	}
	return nil
}

func reuseUpdate(previousPath, out string, sources map[string]string, profile av.Revision, tools map[string]string, library string) (string, error) {
	if err := privateFile(previousPath); err != nil {
		return "", err
	}
	previous, err := object(previousPath)
	if err != nil {
		return "", err
	}
	build, err := object(str(previous, "build"))
	if err != nil {
		return "", err
	}
	wantProfile, _ := json.Marshal(profile)
	haveProfile, _ := json.Marshal(previous["image_profile"])
	wantTools, _ := json.Marshal(tools)
	haveTools, _ := json.Marshal(previous["image_tools"])
	if number(previous, "schema") != 2 || number(build, "schema") != 2 || str(previous, "profile") != "filegate-official-update-v1" || previous["fixture_only"] != false || str(previous, "engine") != "1.4.6" || str(previous, "adapter") != "filegate-freshclam-1.4.6-v1" || str(previous, "origin") != "https://database.clamav.net" || str(previous, "library_sha256") != library || string(wantProfile) != string(haveProfile) || string(wantTools) != string(haveTools) || number(previous, "request_schema") != 2 || number(build, "request_schema") != 2 {
		return "", errors.New("UPDATE_REUSE_PROFILE_INVALID")
	}
	pinsRaw, err := nested(previous, "sha256")
	if err != nil {
		return "", err
	}
	pins := map[string]string{}
	for path, value := range pinsRaw {
		hash, ok := value.(string)
		if !ok {
			return "", errors.New("UPDATE_REUSE_PIN_CHANGED")
		}
		canonicalPath, err := canonical(path)
		if err != nil || canonicalPath != path {
			return "", errors.New("UPDATE_REUSE_PIN_CHANGED")
		}
		pins[path] = hash
	}
	if err = verifyPins(pins); err != nil {
		return "", err
	}
	priorSources, err := nested(build, "sources_sha256")
	if err != nil {
		return "", err
	}
	priorRoot := str(previous, "workspace")
	for path, expected := range sources {
		name := path
		if within(path, priorRoot) {
			name = path
		}
		currentRoot := findWorkspace(sources, path)
		if currentRoot != "" && within(path, currentRoot) {
			relative, _ := filepath.Rel(currentRoot, path)
			name = filepath.Join(priorRoot, relative)
		}
		if priorSources[name] != expected || pins[name] != expected {
			return "", errors.New("UPDATE_REUSE_IMAGE_INPUT_CHANGED")
		}
	}
	artifacts, err := nested(build, "artifacts_sha256")
	if err != nil {
		return "", err
	}
	copied := []map[string]string{}
	for _, name := range []string{"base.ext4", "definitions.ext4", "kernel", "initramfs.cpio.gz", "filegate-update-bridge"} {
		source := filepath.Join(filepath.Dir(str(previous, "build")), name)
		expected, ok := artifacts[source].(string)
		if !ok || pins[source] != expected || mustSHA(source) != expected {
			return "", errors.New("UPDATE_REUSE_ARTIFACT_CHANGED")
		}
		target := filepath.Join(out, name)
		if err = copyNew(source, target, 0); err != nil {
			return "", err
		}
		copied = append(copied, map[string]string{"source": source, "target": target, "sha256": expected})
	}
	if err = verifyPins(pins); err != nil {
		return "", err
	}
	receipt := filepath.Join(out, "reuse-receipt.json")
	if err = saveNewJSON(receipt, map[string]any{"schema": 2, "request_schema": 2, "previous_registration": previousPath, "previous_registration_sha256": mustSHA(previousPath), "previous_build": str(previous, "build"), "previous_build_sha256": mustSHA(str(previous, "build")), "permitted_host_changes": []any{}, "unchanged_image_inputs": true, "copied_artifacts": copied, "vm_executed": false}); err != nil {
		return "", err
	}
	return receipt, nil
}

func findWorkspace(sources map[string]string, path string) string {
	for name := range sources {
		if filepath.Base(name) == "go.mod" && filepath.Base(filepath.Dir(name)) != "vm" && filepath.Base(filepath.Dir(name)) != "contracts" && within(path, filepath.Dir(name)) {
			return filepath.Dir(name)
		}
	}
	return ""
}

func BuildUpdate(ctx context.Context, options BuildOptions) (map[string]any, error) {
	repository, err := Repository(options.Repository)
	if err != nil {
		return nil, err
	}
	verification := options.Verification
	if verification == "" {
		verification, err = DefaultVerification()
		if err != nil {
			return nil, err
		}
	}
	unlock, err := buildLock(repository, verification)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = requireToolchain(ctx); err != nil {
		return nil, err
	}
	out, err := canonical(options.Out)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("new update artifact output required")
	}
	if _, err = os.Stat(filepath.Join(repository, ".git")); err == nil && within(out, repository) {
		return nil, errors.New("update artifacts must be outside repository")
	}
	baselinePath, err := canonical(options.BaselineBuild)
	if err != nil {
		return nil, err
	}
	baseline, err := object(baselinePath)
	if err != nil {
		return nil, err
	}
	if str(baseline, "evidence_kind") != "derived_format_VM_construction_only" || number(baseline, "schema") != 4 {
		return nil, errors.New("Go scan baseline binding required")
	}
	baselineVM := filepath.Dir(filepath.Dir(baselinePath))
	original := map[string]string{}
	artifacts, err := nested(baseline, "artifacts")
	if err != nil {
		return nil, err
	}
	for name, value := range artifacts {
		expected, ok := value.(string)
		if !ok {
			return nil, errors.New("baseline artifact digest required")
		}
		path, err := checked(baselineVM, name)
		if err != nil {
			return nil, err
		}
		original[path] = expected
	}
	if err = verifyPins(original); err != nil {
		return nil, err
	}
	adapterPath, err := canonical(options.AdapterBuild)
	if err != nil {
		return nil, err
	}
	binding, err := VerifyAdapter(adapterPath, filepath.Join(repository, "experiments/av"))
	if err != nil {
		return nil, err
	}
	adapterManifest := filepath.Join(adapterPath, "output/artifact-manifest.json")
	entries, err := adapterEntries(binding.Manifest)
	if err != nil {
		return nil, err
	}
	library := ""
	for _, row := range entries {
		if strings.HasPrefix(row.Path, "lib/libfreshclam.so") && row.SHA256 != "" {
			if library != "" {
				return nil, errors.New("UPDATE_LIBRARY_BINDING_INVALID")
			}
			library = row.SHA256
		}
	}
	if library == "" {
		return nil, errors.New("UPDATE_LIBRARY_BINDING_INVALID")
	}
	proof, err := canonical(options.NativeProof)
	if err != nil {
		return nil, err
	}
	native, err := object(proof)
	if err != nil {
		return nil, err
	}
	nativeBinary := filepath.Join(repository, "experiments/host/.build/integrated-watchdog")
	if !isTrue(native, "passed") || str(native, "kind") != "launchagent_death" || str(native, "binary_sha256") != mustSHA(nativeBinary) || str(native, "native_source_sha256") != mustSHA(filepath.Join(repository, "experiments/host/integrated_watchdog.m")) {
		return nil, errors.New("UPDATE_NATIVE_BINDING_REQUIRED")
	}
	freshclam, err := canonical(options.FreshclamBinary)
	if err != nil {
		return nil, err
	}
	freshclamBuild, err := canonical(options.FreshclamBuild)
	if err != nil {
		return nil, err
	}
	if err = verifyFreshclam(repository, freshclam, freshclamBuild); err != nil {
		return nil, err
	}
	observation := filepath.Join(repository, "experiments/av/observation-specification.json")
	if mustSHA(observation) != observationSHA {
		return nil, errors.New("UPDATE_OBSERVATION_CHANGED")
	}
	fixture, err := nested(baseline, "av_fixture")
	if err != nil {
		return nil, err
	}
	baselineObservation := str(fixture, "observation_path")
	if mustSHA(baselineObservation) != str(fixture, "observation_sha256") || (str(fixture, "observation_sha256") != observationSHA && str(fixture, "observation_sha256") != oldObservationSHA) {
		return nil, errors.New("UPDATE_BASELINE_OBSERVATION_CHANGED")
	}
	profile := av.CurrentRevision()
	tools, err := buildImageTools(ctx)
	if err != nil {
		return nil, err
	}
	sources, err := sourcePins(repository)
	if err != nil {
		return nil, err
	}
	for path, hash := range original {
		sources[path] = hash
	}
	productSources, err := nested(baseline, "product_sources_sha256")
	if err != nil {
		return nil, err
	}
	for name, value := range productSources {
		hash, ok := value.(string)
		if !ok {
			return nil, errors.New("baseline Go source digest required")
		}
		path, err := checked(repository, name)
		if err != nil {
			return nil, err
		}
		actual, err := SHA(path)
		if err != nil || actual != hash {
			return nil, errors.New("baseline Go source binding changed")
		}
		sources[path] = hash
	}
	hostRunner, err := nested(baseline, "host_update_runner")
	if err != nil {
		return nil, err
	}
	if str(hostRunner, "path") != filepath.Join(repository, ".build/filegate-update") || str(hostRunner, "sha256") != mustSHA(str(hostRunner, "path")) {
		return nil, errors.New("baseline Go update runner changed")
	}
	sources[str(hostRunner, "path")] = str(hostRunner, "sha256")
	for _, path := range []string{freshclam, freshclamBuild, baselinePath, baselineObservation, tools["mke2fs"], tools["debugfs"], tools["mke2fs_config"], filepath.Join(repository, ".build/filegate-update")} {
		hash, err := SHA(path)
		if err != nil {
			return nil, err
		}
		sources[path] = hash
	}
	if err = os.Mkdir(out, 0700); err != nil {
		return nil, err
	}
	if options.ReuseRegistration != "" {
		receipt, err := reuseUpdate(options.ReuseRegistration, out, sources, profile, tools, library)
		if err != nil {
			return nil, err
		}
		sources[receipt] = mustSHA(receipt)
	} else {
		image := filepath.Join(out, "base.ext4")
		if err = copyNew(filepath.Join(baselineVM, ".build/base.ext4"), image, 0600); err != nil {
			return nil, err
		}
		if err = copyNew(filepath.Join(baselineVM, ".build/definitions.ext4"), filepath.Join(out, "definitions.ext4"), 0600); err != nil {
			return nil, err
		}
		if err = copyNew(filepath.Join(baselineVM, ".cache/boot/vmlinuz-virt"), filepath.Join(out, "kernel"), 0600); err != nil {
			return nil, err
		}
		staging, err := os.MkdirTemp(out, "construct-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(staging)
		vm := filepath.Join(repository, "experiments/vm")
		for _, item := range []struct{ name, directory, pkg string }{{"vm-guest", vm, "."}, {"filegate-update-worker", repository, "./cmd/filegate-update-worker"}} {
			if _, _, err = command(ctx, item.directory, goEnvironment("linux"), "go", "build", "-trimpath", "-o", filepath.Join(staging, item.name), item.pkg); err != nil {
				return nil, err
			}
		}
		marker := filepath.Join(staging, "profile")
		if err = os.WriteFile(marker, []byte("filegate-official-update-v1\n"), 0444); err != nil {
			return nil, err
		}
		if _, err = installImage(ctx, tools["debugfs"], image, staging, map[string]string{"/vm-guest": filepath.Join(staging, "vm-guest"), "/etc/filegate-update-profile": marker, "/filegate-update-worker": filepath.Join(staging, "filegate-update-worker"), "/filegate-freshclam": freshclam}, map[string]bool{"/vm-guest": true, "/filegate-update-worker": true, "/filegate-freshclam": true}, []string{"/vm-guest", "/av/signed-bytecode.cvd"}, nil); err != nil {
			return nil, err
		}
		init := filepath.Join(staging, "initramfs")
		if err = os.Mkdir(init, 0700); err != nil {
			return nil, err
		}
		if err = extractInitramfs(ctx, filepath.Join(baselineVM, ".build/initramfs.cpio.gz"), init); err != nil {
			return nil, err
		}
		body, err := os.ReadFile(filepath.Join(init, "init"))
		if err != nil {
			return nil, err
		}
		needle := "modprobe virtio_blk || fail"
		if strings.Count(string(body), needle) != 1 {
			return nil, errors.New("UPDATE_INIT_BINDING_CHANGED")
		}
		body = []byte(strings.Replace(string(body), needle, needle+"\nmodprobe virtio_net || fail", 1))
		if err = os.WriteFile(filepath.Join(init, "init"), body, 0755); err != nil {
			return nil, err
		}
		if err = RootCPIO(init, filepath.Join(out, "initramfs.cpio.gz")); err != nil {
			return nil, err
		}
		if _, _, err = command(ctx, repository, goEnvironment("darwin"), "go", "build", "-trimpath", "-o", filepath.Join(out, "filegate-update-bridge"), "./cmd/filegate-update-bridge"); err != nil {
			return nil, err
		}
		if err = os.Chmod(filepath.Join(out, "filegate-update-bridge"), 0500); err != nil {
			return nil, err
		}
	}
	if err = verifyPins(sources); err != nil {
		return nil, err
	}
	if err = verifyPins(original); err != nil {
		return nil, err
	}
	outputArtifacts := map[string]string{}
	pythonRuntime, err := removeImagePython(ctx, tools["debugfs"], filepath.Join(out, "base.ext4"))
	if err != nil {
		return nil, err
	}
	initramfsInspection, err := InspectCPIO(filepath.Join(out, "initramfs.cpio.gz"))
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"base.ext4", "definitions.ext4", "kernel", "initramfs.cpio.gz", "filegate-update-bridge"} {
		path := filepath.Join(out, name)
		hash, err := SHA(path)
		if err != nil {
			return nil, err
		}
		outputArtifacts[path] = hash
	}
	build := filepath.Join(out, "build.json")
	if err = saveNewJSON(build, map[string]any{"schema": 2, "request_schema": 2, "profile": "filegate-official-update-v1", "fixture_only": false, "library_sha256": library, "adapter_manifest_sha256": mustSHA(adapterManifest), "image_profile": profile, "image_tools": tools, "sources_sha256": sources, "artifacts_sha256": outputArtifacts, "implementation": "go", "python_dependency": false, "python_runtime": pythonRuntime, "initramfs_inspection": initramfsInspection}); err != nil {
		return nil, err
	}
	pins := map[string]string{}
	for path, value := range sources {
		pins[path] = value
	}
	for path, value := range outputArtifacts {
		pins[path] = value
	}
	qemu, err := exec.LookPath("qemu-system-aarch64")
	if err != nil {
		return nil, err
	}
	imageTool, err := exec.LookPath("qemu-img")
	if err != nil {
		return nil, err
	}
	for _, path := range []string{build, proof, adapterManifest, nativeBinary, qemu, imageTool} {
		actual, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		hash, err := SHA(actual)
		if err != nil {
			return nil, err
		}
		pins[actual] = hash
	}
	if len(pins) > 512 {
		return nil, errors.New("bounded Go update source inventory exceeded")
	}
	registration := filepath.Join(out, "registration-candidate.json")
	if err = saveNewJSON(registration, map[string]any{"schema": 2, "request_schema": 2, "profile": "filegate-official-update-v1", "fixture_only": false, "library_sha256": library, "workspace": repository, "runner": filepath.Join(repository, ".build/filegate-update"), "helper": filepath.Join(out, "filegate-update-bridge"), "proof": proof, "sha256": pins, "engine": "1.4.6", "adapter": "filegate-freshclam-1.4.6-v1", "origin": "https://database.clamav.net", "build": build, "adapter_manifest": adapterManifest, "image_profile": profile, "image_tools": tools}); err != nil {
		return nil, err
	}
	if err = syncDirectory(out); err != nil {
		return nil, err
	}
	return map[string]any{"registration_candidate": registration, "registered": false, "runtime_executed": false, "python_dependency": false, "source_count": len(sources), "pin_count": len(pins)}, nil
}
