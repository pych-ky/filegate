package buildtools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filegate.local/filegate/internal/av"
	"golang.org/x/sys/unix"
)

var updateArtifactNames = []string{"base.ext4", "definitions.ext4", "kernel", "initramfs.cpio.gz", "filegate-update-bridge"}

// BuildUpdateHost derives a normal update registration from a registered one when only host-side inputs changed: the update image,
// adapter and libraries are reused byte for byte, the host update runner comes from build-host, and the update bridge helper is
// rebuilt from the current workspace.
func BuildUpdateHost(ctx context.Context, options BuildOptions) (map[string]any, error) {
	if (options.NativeBinary == "") != (options.ReplacementNativeProof == "") {
		return nil, errors.New("native binary and replacement proof must be specified together")
	}
	repository, err := Repository(options.Repository)
	if err != nil {
		return nil, err
	}
	verification := options.Verification
	if verification == "" {
		if verification, err = DefaultVerification(); err != nil {
			return nil, err
		}
	}
	parentPath, err := canonical(options.ParentRegistration)
	if err != nil {
		return nil, err
	}
	out, err := canonical(options.Out)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("new update artifact output required")
	}
	if within(out, repository) || within(repository, out) {
		return nil, errors.New("update artifacts must be outside the workspace")
	}
	unlock, err := buildLock(repository, verification)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = requireToolchain(ctx); err != nil {
		return nil, err
	}

	if err = privateFile(parentPath); err != nil {
		return nil, err
	}
	parentSHA := mustSHA(parentPath)
	var parent map[string]any
	if err = readJSON(parentPath, &parent); err != nil {
		return nil, err
	}
	if !exactKeys(parent, "schema profile fixture_only library_sha256 workspace runner helper proof sha256 engine adapter origin build adapter_manifest image_profile image_tools request_schema") || number(parent, "schema") != 2 || str(parent, "profile") != "filegate-official-update-v1" || parent["fixture_only"] != false || number(parent, "request_schema") != 2 || str(parent, "engine") != "1.4.6" || str(parent, "adapter") != "filegate-freshclam-1.4.6-v1" || str(parent, "origin") != "https://database.clamav.net" || !validSHA(str(parent, "library_sha256")) || str(parent, "runner") != filepath.Join(str(parent, "workspace"), ".build/filegate-update") || !sameJSON(parent["image_profile"], av.CurrentRevision()) {
		return nil, errors.New("UPDATE_PARENT_REGISTRATION_INVALID")
	}
	parentPins := map[string]string{}
	rows, err := nested(parent, "sha256")
	if err != nil {
		return nil, err
	}
	for path, value := range rows {
		hash, ok := value.(string)
		if actual, e := canonical(path); !ok || !validSHA(hash) || e != nil || actual != path {
			return nil, errors.New("UPDATE_PARENT_PIN_INVALID")
		}
		parentPins[path] = hash
	}
	tools, err := buildImageTools(ctx)
	if err != nil {
		return nil, err
	}
	adopted, err := object(filepath.Join(repository, "experiments/av/adopted-bindings.json"))
	if err != nil {
		return nil, err
	}
	evidence, err := nested(adopted, "evidence")
	if err != nil {
		return nil, err
	}
	adapterReference, err := nested(evidence, "adapter_manifest")
	if err != nil {
		return nil, err
	}
	adapterManifest, parentWorkspace, parentBuildPath := str(parent, "adapter_manifest"), str(parent, "workspace"), str(parent, "build")
	if !sameJSON(parent["image_tools"], tools) || len(parentPins) < 16 || len(parentPins) > 512 || !validSHA(str(adapterReference, "sha256")) || parentPins[adapterManifest] != str(adapterReference, "sha256") {
		return nil, errors.New("UPDATE_PARENT_REGISTRATION_INVALID")
	}
	for _, path := range []string{str(parent, "runner"), str(parent, "helper"), str(parent, "proof"), parentBuildPath, adapterManifest, tools["mke2fs"], tools["debugfs"], tools["mke2fs_config"]} {
		if !validSHA(parentPins[path]) {
			return nil, fmt.Errorf("UPDATE_PARENT_PIN_MISSING: %s", path)
		}
	}
	if err = verifyPins(parentPins); err != nil {
		return nil, err
	}
	if err = verifyAdapterLibrary(adapterManifest, str(parent, "library_sha256")); err != nil {
		return nil, err
	}

	var parentBuild map[string]any
	if err = readJSON(parentBuildPath, &parentBuild); err != nil {
		return nil, err
	}
	parentArtifacts, err := nested(parentBuild, "artifacts_sha256")
	if err != nil {
		return nil, err
	}
	parentSources, err := nested(parentBuild, "sources_sha256")
	if err != nil {
		return nil, err
	}
	if !exactKeys(parentBuild, "schema request_schema profile fixture_only library_sha256 adapter_manifest_sha256 image_profile image_tools sources_sha256 artifacts_sha256 implementation python_dependency python_runtime initramfs_inspection") || number(parentBuild, "schema") != 2 || number(parentBuild, "request_schema") != 2 || str(parentBuild, "profile") != str(parent, "profile") || parentBuild["fixture_only"] != false || str(parentBuild, "library_sha256") != str(parent, "library_sha256") || str(parentBuild, "adapter_manifest_sha256") != parentPins[adapterManifest] || !sameJSON(parentBuild["image_profile"], parent["image_profile"]) || !sameJSON(parentBuild["image_tools"], parent["image_tools"]) || str(parentBuild, "implementation") != "go" || parentBuild["python_dependency"] != false || len(parentArtifacts) != len(updateArtifactNames) {
		return nil, errors.New("UPDATE_PARENT_BUILD_INVALID")
	}
	for _, group := range []map[string]any{parentSources, parentArtifacts} {
		for path, value := range group {
			if hash, ok := value.(string); !ok || parentPins[path] != hash {
				return nil, fmt.Errorf("UPDATE_PARENT_BUILD_PIN_CHANGED: %s", path)
			}
		}
	}
	parentDirectory := filepath.Dir(parentBuildPath)
	for _, name := range updateArtifactNames {
		if _, ok := parentArtifacts[filepath.Join(parentDirectory, name)]; !ok {
			return nil, fmt.Errorf("UPDATE_PARENT_ARTIFACT_MISSING: %s", name)
		}
	}
	proof := str(parent, "proof")
	proofSHA := parentPins[proof]
	var replacementNative map[string]any
	replacementPins := map[string]string{}
	if options.NativeBinary != "" {
		original, err := object(proof)
		if err != nil {
			return nil, err
		}
		parentBinarySHA := parentPins[filepath.Join(parentWorkspace, "experiments/host/.build/integrated-watchdog")]
		parentSourceSHA := parentPins[filepath.Join(parentWorkspace, "experiments/host/integrated_watchdog.m")]
		if !validSHA(parentBinarySHA) || !validSHA(parentSourceSHA) || !isTrue(original, "passed") || str(original, "kind") != "launchagent_death" || str(original, "binary_sha256") != parentBinarySHA || str(original, "native_source_sha256") != parentSourceSHA {
			return nil, errors.New("native monitor proof mismatch")
		}
		binary, err := canonical(options.NativeBinary)
		if err != nil {
			return nil, err
		}
		var info unix.Stat_t
		if unix.Lstat(binary, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&07777 != 0500 {
			return nil, errors.New("qualified native binary must be owner-only mode0500")
		}
		selectedProof, err := canonical(options.ReplacementNativeProof)
		if err != nil {
			return nil, err
		}
		replacement, err := object(selectedProof)
		if err != nil {
			return nil, err
		}
		binarySHA, err := SHA(binary)
		if err != nil {
			return nil, err
		}
		source := filepath.Join(repository, "experiments/host/integrated_watchdog.m")
		sourceSHA, err := SHA(source)
		if err != nil {
			return nil, err
		}
		selectedProofSHA, err := SHA(selectedProof)
		if err != nil {
			return nil, err
		}
		workspaceBinary := filepath.Join(repository, "experiments/host/.build/integrated-watchdog")
		if !isTrue(replacement, "passed") || str(replacement, "kind") != "launchagent_death" || str(replacement, "binary_sha256") != binarySHA || str(replacement, "native_source_sha256") != sourceSHA || mustSHA(workspaceBinary) != binarySHA {
			return nil, errors.New("replacement native monitor proof mismatch")
		}
		replacementNative = map[string]any{"parent_proof": proof, "parent_proof_sha256": proofSHA, "proof": selectedProof, "proof_sha256": selectedProofSHA, "binary": binary, "binary_sha256": binarySHA, "workspace_binary": workspaceBinary, "source": source, "source_sha256": sourceSHA}
		replacementPins[binary], replacementPins[selectedProof] = binarySHA, selectedProofSHA
		replacementPins[source], replacementPins[workspaceBinary] = sourceSHA, binarySHA
		proof, proofSHA = selectedProof, selectedProofSHA
	}

	receiptPath := filepath.Join(repository, "experiments/vm/evidence/build.json")
	receiptSHA, err := SHA(receiptPath)
	if err != nil {
		return nil, err
	}
	var receipt map[string]any
	if err = readJSON(receiptPath, &receipt); err != nil {
		return nil, err
	}
	runner := filepath.Join(repository, ".build/filegate-update")
	hostRunner, err := nested(receipt, "host_update_runner")
	if err != nil {
		return nil, err
	}
	if number(receipt, "schema") != 4 || str(receipt, "evidence_kind") != "derived_format_VM_construction_only" || str(hostRunner, "path") != runner || str(hostRunner, "sha256") != mustSHA(runner) || str(receipt, "native_proof_sha256") != proofSHA {
		return nil, errors.New("UPDATE_SCAN_RECEIPT_BINDING_INVALID")
	}
	productSources, err := nested(receipt, "product_sources_sha256")
	if err != nil {
		return nil, err
	}
	current := map[string]string{}
	for name, value := range productSources {
		hash, _ := value.(string)
		if _, err := checked(repository, name); err != nil || !validSHA(hash) {
			return nil, errors.New("UPDATE_SCAN_RECEIPT_BINDING_INVALID")
		}
		current[filepath.ToSlash(name)] = hash
	}
	if err = verifyPins(relativeToAbsolute(repository, current)); err != nil {
		return nil, err
	}

	guestClosure, helperClosure := map[string]bool{}, map[string]bool{}
	for _, target := range []struct {
		goos, module, pkg string
		closure           map[string]bool
	}{{"linux", ".", "./cmd/filegate-update-worker", guestClosure}, {"linux", "experiments/vm", ".", guestClosure}, {"darwin", ".", "./cmd/filegate-update-bridge", helperClosure}} {
		listed, _, err := command(ctx, filepath.Join(repository, target.module), goEnvironment(target.goos), "go", "list", "-deps", "-f", "{{.Dir}}{{range .GoFiles}}|{{.}}{{end}}{{range .CgoFiles}}|{{.}}{{end}}{{range .SFiles}}|{{.}}{{end}}{{range .HFiles}}|{{.}}{{end}}{{range .CFiles}}|{{.}}{{end}}{{range .EmbedFiles}}|{{.}}{{end}}{{with .Module}}{{if .GoMod}}|{{.GoMod}}{{end}}{{end}}", target.pkg)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(listed)), "\n") {
			fields := strings.Split(line, "|")
			for _, file := range fields[1:] {
				path := file
				if !filepath.IsAbs(path) {
					path = filepath.Join(fields[0], file)
				}
				if name, err := filepath.Rel(repository, path); err == nil && within(path, repository) {
					target.closure[filepath.ToSlash(name)] = true
				}
			}
		}
	}
	// go.sum binds the module-cache packages the helper compiles.
	helperClosure["go.sum"] = true
	changed := []map[string]any{}
	seen := map[string]bool{}
	for path, expected := range parentPins {
		if !within(path, parentWorkspace) {
			continue
		}
		name, _ := filepath.Rel(parentWorkspace, path)
		name = filepath.ToSlash(name)
		seen[name] = true
		now, err := SHA(filepath.Join(repository, filepath.FromSlash(name)))
		if err != nil {
			return nil, fmt.Errorf("UPDATE_WORKSPACE_PIN_MISSING: %s", name)
		}
		if now != expected {
			changed = append(changed, map[string]any{"path": name, "parent_sha256": expected, "sha256": now})
		}
	}
	for name, hash := range current {
		if !seen[name] {
			changed = append(changed, map[string]any{"path": name, "parent_sha256": nil, "sha256": hash})
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i]["path"].(string) < changed[j]["path"].(string) })
	helperChanged := []string{}
	var acceptedContract map[string]any
	for _, row := range changed {
		name := row["path"].(string)
		if guestClosure[name] {
			return nil, fmt.Errorf("UPDATE_GUEST_OR_IMAGE_INPUT_CHANGED: %s", name)
		}
		if replacementNative != nil && name == "experiments/host/integrated_watchdog.m" && !helperClosure[name] {
			continue
		}
		if name == hostBudgetContract && !helperClosure[name] {
			oldSHA, _ := row["parent_sha256"].(string)
			newSHA, _ := row["sha256"].(string)
			if acceptedContract, err = hostBudgetAccountingDelta(filepath.Join(parentWorkspace, filepath.FromSlash(name)), oldSHA, filepath.Join(repository, filepath.FromSlash(name)), newSHA); err != nil {
				return nil, err
			}
			continue
		}
		permitted := name == ".build/filegate-update" || name == "experiments/vm/evidence/build.json" || strings.HasPrefix(name, "experiments/vm/.build/") || strings.HasPrefix(name, "experiments/host/.build/") || strings.HasPrefix(name, "cmd/") || strings.HasPrefix(name, "internal/")
		if !permitted {
			return nil, fmt.Errorf("UPDATE_GUEST_OR_IMAGE_INPUT_CHANGED: %s", name)
		}
		if helperClosure[name] {
			helperChanged = append(helperChanged, name)
		}
	}

	staging, err := os.MkdirTemp(verification, ".update-host-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	debugfs := tools["debugfs"]
	parentImage := filepath.Join(parentDirectory, "base.ext4")
	readback := map[string]string{}
	for _, path := range []string{"/filegate-update-worker", "/vm-guest", "/filegate-freshclam", "/etc/filegate-update-profile"} {
		quoted, _ := quoteDebugfs(path)
		target := filepath.Join(staging, "readback"+strings.ReplaceAll(path, "/", "_"))
		output, _ := quoteDebugfs(target)
		if _, _, err = command(ctx, "", nil, debugfs, "-R", "dump "+quoted+" "+output, parentImage); err != nil {
			return nil, err
		}
		if readback[path], err = SHA(target); err != nil {
			return nil, fmt.Errorf("UPDATE_IMAGE_READBACK_FAILED: %s", path)
		}
	}
	if profile, err := os.ReadFile(filepath.Join(staging, "readback_etc_filegate-update-profile")); err != nil || string(profile) != "filegate-official-update-v1\n" {
		return nil, errors.New("UPDATE_IMAGE_PROFILE_CHANGED")
	}
	freshclam := ""
	for path := range parentPins {
		if filepath.Base(path) == "filegate-freshclam" && !within(path, parentWorkspace) {
			freshclam = path
		}
	}
	if freshclam == "" || readback["/filegate-freshclam"] != parentPins[freshclam] {
		return nil, errors.New("UPDATE_IMAGE_FRESHCLAM_CHANGED")
	}
	if err = debugfsAbsent(ctx, debugfs, parentImage, "/av/signed-bytecode.cvd"); err != nil {
		return nil, err
	}
	guest := []map[string]any{}
	for _, item := range []struct{ name, module, pkg string }{{"filegate-update-worker", ".", "./cmd/filegate-update-worker"}, {"vm-guest", "experiments/vm", "."}} {
		argv := []string{"go", "build", "-trimpath", "-o", filepath.Join(staging, "rebuilt-"+item.name), item.pkg}
		if _, _, err = command(ctx, filepath.Join(repository, item.module), goEnvironment("linux"), argv...); err != nil {
			return nil, err
		}
		rebuilt := mustSHA(filepath.Join(staging, "rebuilt-"+item.name))
		equal := rebuilt == readback["/"+item.name]
		guest = append(guest, map[string]any{"name": item.name, "directory": item.module, "argv": argv[:3], "package": item.pkg, "goos": "linux", "sha256": rebuilt, "image_sha256": readback["/"+item.name], "equal": equal})
		if !equal {
			return nil, fmt.Errorf("UPDATE_GUEST_NOT_REPRODUCED: %s", item.name)
		}
	}
	inventory, err := imageInventory(ctx, debugfs, parentImage)
	if err != nil {
		return nil, err
	}
	for _, entry := range inventory {
		if pythonPath(entry.Path) {
			return nil, errors.New("UPDATE_IMAGE_PYTHON_PRESENT")
		}
	}
	encoded, err := jsonBytes(inventory)
	if err != nil {
		return nil, err
	}
	parentPython, _ := nested(parentBuild, "python_runtime")
	if number(parentPython, "inspected_inodes") != int64(len(inventory)) || str(parentPython, "inventory_sha256") != digest(encoded) {
		return nil, errors.New("UPDATE_IMAGE_INVENTORY_CHANGED")
	}
	initramfs, err := InspectCPIO(filepath.Join(parentDirectory, "initramfs.cpio.gz"))
	if err != nil || !sameJSON(initramfs, parentBuild["initramfs_inspection"]) {
		return nil, errors.New("UPDATE_INITRAMFS_CHANGED")
	}
	extracted := filepath.Join(staging, "initramfs")
	if err = os.Mkdir(extracted, 0700); err != nil {
		return nil, err
	}
	if err = extractInitramfs(ctx, filepath.Join(parentDirectory, "initramfs.cpio.gz"), extracted); err != nil {
		return nil, err
	}
	if init, err := os.ReadFile(filepath.Join(extracted, "init")); err != nil || strings.Count(string(init), "modprobe virtio_blk || fail\nmodprobe virtio_net || fail") != 1 {
		return nil, errors.New("UPDATE_INIT_BINDING_CHANGED")
	}

	if err = os.Mkdir(out, 0700); err != nil {
		return nil, err
	}
	artifacts := map[string]string{}
	copied := []map[string]string{}
	for _, name := range updateArtifactNames {
		if name == "filegate-update-bridge" {
			continue
		}
		source, target := filepath.Join(parentDirectory, name), filepath.Join(out, name)
		if err = copyNew(source, target, 0); err != nil {
			return nil, err
		}
		hash := mustSHA(target)
		if hash != parentArtifacts[source] {
			return nil, fmt.Errorf("UPDATE_ARTIFACT_COPY_CHANGED: %s", name)
		}
		artifacts[target] = hash
		copied = append(copied, map[string]string{"source": source, "target": target, "sha256": hash})
	}
	// The helper is built with build-update's command line; its input closure must be the same before and after the build.
	helperInputs := map[string]string{}
	helperInputNames := map[string]string{}
	for name := range helperClosure {
		path := filepath.Join(repository, filepath.FromSlash(name))
		if helperInputs[path], err = SHA(path); err != nil {
			return nil, err
		}
		helperInputNames[name] = helperInputs[path]
	}
	goVersion, _, err := command(ctx, "", nil, "go", "version")
	if err != nil {
		return nil, err
	}
	helper := filepath.Join(out, "filegate-update-bridge")
	helperArgv := []string{"go", "build", "-trimpath", "-o", helper, "./cmd/filegate-update-bridge"}
	if _, _, err = command(ctx, repository, goEnvironment("darwin"), helperArgv...); err != nil {
		return nil, err
	}
	if err = os.Chmod(helper, 0500); err != nil {
		return nil, err
	}
	if err = verifyPins(helperInputs); err != nil {
		return nil, err
	}
	artifacts[helper] = mustSHA(helper)
	sources := map[string]string{}
	for path, expected := range parentSources {
		hash := expected.(string)
		if within(path, parentWorkspace) {
			name, _ := filepath.Rel(parentWorkspace, path)
			path = filepath.Join(repository, name)
			hash = mustSHA(path)
		}
		sources[path] = hash
	}
	for name, hash := range current {
		sources[filepath.Join(repository, filepath.FromSlash(name))] = hash
	}
	for path, hash := range helperInputs {
		sources[path] = hash
	}
	derivedPath := filepath.Join(out, "derived-from.json")
	derived := map[string]any{
		"schema": 1, "kind": "host_runner_and_helper_normal_update_registration", "created_utc": time.Now().UTC().Format(time.RFC3339),
		"parent_registration": parentPath, "parent_registration_sha256": parentSHA, "parent_build": parentBuildPath, "parent_build_sha256": parentPins[parentBuildPath], "parent_pins_verified": len(parentPins),
		"scan_receipt": receiptPath, "scan_receipt_sha256": receiptSHA, "runner": runner, "runner_sha256": mustSHA(runner),
		"changed_workspace_sources": changed, "update_guest_inputs_unchanged": len(guestClosure), "helper_changed_inputs": helperChanged,
		"image_readback_sha256": readback, "guest_comparison": guest, "copied_artifacts": copied,
		"helper_construction":   map[string]any{"path": helper, "sha256": artifacts[helper], "directory": ".", "package": "./cmd/filegate-update-bridge", "argv": helperArgv, "environment": fixedGoEnvironment("darwin"), "go": strings.TrimSpace(string(goVersion)), "inputs_sha256": helperInputNames, "parent_helper": str(parent, "helper"), "parent_helper_sha256": parentPins[str(parent, "helper")]},
		"retained":              map[string]any{"update_image": "base.ext4, definitions.ext4, kernel and initramfs.cpio.gz copied byte for byte from the parent build; constructed by the parent's builder, not rebuilt here", "adapter": "adopted manifest pin and libfreshclam binding verified; adapter builder results.json and inputs/inputs.json are not available and no adapter build was performed"},
		"new_host_construction": map[string]any{"filegate-update": "built by build-host for the new workspace; bound by the scan receipt host_update_runner", "filegate-update-bridge": "rebuilt here from the current workspace; the parent helper binary was not copied"},
		"runtime_executed":      false, "registered": false,
	}
	if acceptedContract != nil {
		derived["accepted_contract_metadata"] = acceptedContract
	}
	if replacementNative != nil {
		derived["replacement_native"] = replacementNative
	}
	if err = saveNewJSON(derivedPath, derived); err != nil {
		return nil, err
	}
	build := filepath.Join(out, "build.json")
	if err = saveNewJSON(build, map[string]any{"schema": 2, "request_schema": 2, "profile": "filegate-official-update-v1", "fixture_only": false, "library_sha256": str(parent, "library_sha256"), "adapter_manifest_sha256": parentPins[adapterManifest], "image_profile": parent["image_profile"], "image_tools": tools, "sources_sha256": sources, "artifacts_sha256": artifacts, "implementation": "go", "python_dependency": false, "python_runtime": parentBuild["python_runtime"], "initramfs_inspection": parentBuild["initramfs_inspection"]}); err != nil {
		return nil, err
	}
	pins := map[string]string{}
	for path, hash := range sources {
		pins[path] = hash
	}
	for path, hash := range artifacts {
		pins[path] = hash
	}
	nativeBinary := filepath.Join(repository, "experiments/host/.build/integrated-watchdog")
	pins[build], pins[derivedPath], pins[proof], pins[adapterManifest], pins[nativeBinary] = mustSHA(build), mustSHA(derivedPath), proofSHA, parentPins[adapterManifest], mustSHA(nativeBinary)
	for path, hash := range replacementPins {
		pins[path] = hash
	}
	for path, hash := range parentPins {
		if !within(path, parentWorkspace) && !within(path, parentDirectory) && path != parentBuildPath {
			pins[path] = hash
		}
	}
	runtimePins, err := qemuRuntimePins(receipt)
	if err != nil {
		return nil, err
	}
	for path, hash := range runtimePins {
		if inherited, ok := pins[path]; ok && inherited != hash {
			return nil, fmt.Errorf("parent registration pin differs from the scan receipt QEMU closure: %s", path)
		}
		pins[path] = hash
	}
	if len(pins) > 512 {
		return nil, errors.New("bounded Go update source inventory exceeded")
	}
	if err = verifyPins(pins); err != nil {
		return nil, err
	}
	if err = verifyPins(parentPins); err != nil {
		return nil, err
	}
	registration := filepath.Join(out, "registration-candidate.json")
	if err = saveNewJSON(registration, map[string]any{"schema": 2, "request_schema": 2, "profile": "filegate-official-update-v1", "fixture_only": false, "library_sha256": str(parent, "library_sha256"), "workspace": repository, "runner": runner, "helper": filepath.Join(out, "filegate-update-bridge"), "proof": proof, "sha256": pins, "engine": "1.4.6", "adapter": "filegate-freshclam-1.4.6-v1", "origin": "https://database.clamav.net", "build": build, "adapter_manifest": adapterManifest, "image_profile": parent["image_profile"], "image_tools": tools}); err != nil {
		return nil, err
	}
	if err = syncDirectory(out); err != nil {
		return nil, err
	}
	return map[string]any{"registration_candidate": registration, "registered": false, "runtime_executed": false, "parent_registration_sha256": parentSHA, "changed_workspace_sources": len(changed), "guest_binaries_reproduced": len(guest), "helper_sha256": artifacts[helper], "pin_count": len(pins)}, nil
}

// debugfsAbsent accepts only debugfs's exact not-found diagnostic as absence; debugfs exits 0 even when it cannot open the image.
func debugfsAbsent(ctx context.Context, debugfs, image, path string) error {
	quoted, err := quoteDebugfs(path)
	if err != nil {
		return err
	}
	stdout, stderr, err := command(ctx, "", nil, debugfs, "-R", "stat "+quoted, image)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(stderr), "\n"), "\n")
	if len(stdout) == 0 && len(lines) == 2 && strings.HasPrefix(lines[0], "debugfs ") && strings.TrimRight(lines[1], " ") == path+": File not found by ext2_lookup" {
		return nil
	}
	if bytes.Contains(stdout, []byte("Inode:")) {
		return errors.New("UPDATE_IMAGE_REMOVED_INPUT_PRESENT")
	}
	return errors.New("UPDATE_IMAGE_ABSENCE_UNVERIFIED")
}

func verifyAdapterLibrary(manifest, library string) error {
	body, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	var adapter struct {
		Entries []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"entries"`
	}
	if json.Unmarshal(body, &adapter) != nil {
		return errors.New("UPDATE_ADOPTED_ADAPTER_INVALID")
	}
	matches := 0
	for _, entry := range adapter.Entries {
		if strings.HasPrefix(entry.Path, "lib/libfreshclam.so") && entry.SHA256 != "" {
			if entry.SHA256 != library {
				return errors.New("UPDATE_LIBRARY_BINDING_INVALID")
			}
			matches++
		}
	}
	if matches != 1 {
		return errors.New("UPDATE_LIBRARY_BINDING_INVALID")
	}
	return nil
}

func exactKeys(value map[string]any, names string) bool {
	keys := strings.Fields(names)
	if len(value) != len(keys) {
		return false
	}
	for _, name := range keys {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	return true
}

func sameJSON(a, b any) bool {
	normalize := func(value any) ([]byte, error) {
		body, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		var generic any
		if err = json.Unmarshal(body, &generic); err != nil {
			return nil, err
		}
		return json.Marshal(generic)
	}
	x, e := normalize(a)
	y, f := normalize(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

func relativeToAbsolute(base string, rows map[string]string) map[string]string {
	result := map[string]string{}
	for name, hash := range rows {
		result[filepath.Join(base, filepath.FromSlash(name))] = hash
	}
	return result
}
