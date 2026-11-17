package buildtools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"filegate.local/filegate/internal/qemuruntime"
	"golang.org/x/sys/unix"
)

func quoteDebugfs(path string) (string, error) {
	if strings.ContainsAny(path, "\"\\\n\r") {
		return "", errors.New("unsupported debugfs path")
	}
	return "\"" + path + "\"", nil
}
func statMode(metadata, mode string) bool {
	return regexp.MustCompile(`User:\s+0\s+Group:\s+0`).MatchString(metadata) && regexp.MustCompile(`Type:\s+regular\s+Mode:\s+0*`+strings.TrimLeft(mode, "0")+`\b`).MatchString(metadata)
}

func toolVersion(ctx context.Context, path, name string) error {
	out, stderr, err := command(ctx, "", nil, path, "-V")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(out)+string(stderr), name+" 1.47.4 ") {
		return fmt.Errorf("fixed %s1.47.4 required", name)
	}
	return nil
}

func installImage(ctx context.Context, debugfs, image, staging string, installs map[string]string, executables map[string]bool, remove, dirs []string) (map[string]any, error) {
	commands := []string{}
	for _, name := range remove {
		q, err := quoteDebugfs(name)
		if err != nil {
			return nil, err
		}
		commands = append(commands, "rm "+q)
	}
	for _, name := range dirs {
		q, err := quoteDebugfs(name)
		if err != nil {
			return nil, err
		}
		commands = append(commands, "mkdir "+q, "set_inode_field "+q+" uid 0", "set_inode_field "+q+" gid 0", "set_inode_field "+q+" mode 040755")
	}
	names := make([]string, 0, len(installs))
	for name := range installs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		q, err := quoteDebugfs(name)
		if err != nil {
			return nil, err
		}
		source, err := quoteDebugfs(installs[name])
		if err != nil {
			return nil, err
		}
		mode := "0100444"
		if executables[name] {
			mode = "0100755"
		}
		commands = append(commands, "rm "+q, "write "+source+" "+q, "set_inode_field "+q+" uid 0", "set_inode_field "+q+" gid 0", "set_inode_field "+q+" mode "+mode)
	}
	batch := filepath.Join(staging, "install-"+filepath.Base(image)+".txt")
	if err := os.WriteFile(batch, []byte(strings.Join(commands, "\n")+"\n"), 0600); err != nil {
		return nil, err
	}
	if _, _, err := command(ctx, "", nil, debugfs, "-w", "-f", batch, image); err != nil {
		return nil, err
	}
	for _, name := range remove {
		if !strings.HasSuffix(name, ".py") {
			continue
		}
		quoted, _ := quoteDebugfs(name)
		metadata, diagnostic, err := command(ctx, "", nil, debugfs, "-R", "stat "+quoted, image)
		if err != nil || strings.Contains(string(metadata), "Inode:") || !strings.Contains(string(diagnostic), "File not found") {
			return nil, errors.New("removed project script absence not proven")
		}
	}
	installed := map[string]any{}
	for i, name := range names {
		q, _ := quoteDebugfs(name)
		recovered := filepath.Join(staging, fmt.Sprintf("readback-%s-%d", filepath.Base(image), i))
		dump, _ := quoteDebugfs(recovered)
		if _, _, err := command(ctx, "", nil, debugfs, "-R", "dump "+q+" "+dump, image); err != nil {
			return nil, err
		}
		before, err := SHA(installs[name])
		if err != nil {
			return nil, err
		}
		after, err := SHA(recovered)
		if err != nil || before != after {
			return nil, errors.New("image content readback mismatch")
		}
		metadata, _, err := command(ctx, "", nil, debugfs, "-R", "stat "+q, image)
		if err != nil {
			return nil, err
		}
		mode := "0444"
		if executables[name] {
			mode = "0755"
		}
		if !statMode(string(metadata), mode) {
			return nil, errors.New("image inode owner or mode mismatch")
		}
		installed[name] = map[string]any{"sha256": before, "mode": mode, "uid": 0, "gid": 0}
	}
	return installed, nil
}

func relativePins(pins map[string]string, base string) (map[string]string, error) {
	result := map[string]string{}
	for path, value := range pins {
		name, err := filepath.Rel(base, path)
		if err != nil {
			return nil, err
		}
		result[filepath.ToSlash(name)] = value
	}
	return result, nil
}

func BuildScan(ctx context.Context, options BuildOptions) (map[string]any, error) {
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
	baseline, err := canonical(options.Baseline)
	if err != nil {
		return nil, err
	}
	proof, err := canonical(options.BaselineProof)
	if err != nil {
		return nil, err
	}
	nativeProof, err := canonical(options.NativeProof)
	if err != nil {
		return nil, err
	}
	if within(repository, baseline) || within(baseline, repository) {
		return nil, errors.New("product workspace must be separate from baseline")
	}
	unlock, err := buildLock(repository, verification)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = requireToolchain(ctx); err != nil {
		return nil, err
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
	baselineProof, err := object(proof)
	if err != nil {
		return nil, err
	}
	baselineBuild, err := nested(baselineProof, "build")
	if err != nil {
		return nil, err
	}
	frozen := filepath.Join(filepath.Dir(proof), "sources")
	original := map[string]string{}
	sourceRows, err := nested(baselineProof, "source_sha256")
	if err != nil {
		return nil, err
	}
	for name, value := range sourceRows {
		expected, ok := value.(string)
		if !ok || !validSHA(expected) {
			return nil, errors.New("invalid baseline source digest")
		}
		path, err := checked(frozen, name)
		if err != nil {
			return nil, err
		}
		if _, err = os.Stat(path); err != nil {
			return nil, fmt.Errorf("baseline frozen source unavailable: %s", name)
		}
		original[path] = expected
	}
	artifactRows, err := nested(baselineBuild, "artifacts")
	if err != nil {
		return nil, err
	}
	for name, value := range artifactRows {
		expected, ok := value.(string)
		if !ok || !validSHA(expected) {
			return nil, errors.New("invalid baseline artifact digest")
		}
		path, err := checked(filepath.Join(baseline, "experiments/vm"), name)
		if err != nil {
			return nil, err
		}
		original[path] = expected
	}
	baselineObservation := filepath.Join(baseline, "experiments/av/observation-matrix.json")
	value, err := SHA(baselineObservation)
	if err != nil || value != oldObservationSHA {
		return nil, errors.New("fixed baseline observation required")
	}
	original[baselineObservation] = value
	observation := filepath.Join(repository, "experiments/av/observation-specification.json")
	value, err = SHA(observation)
	if err != nil || value != observationSHA {
		return nil, errors.New("fixed current observation required")
	}
	if err = verifyPins(original); err != nil {
		return nil, err
	}
	baselineInputs, err := nested(baselineBuild, "external_sources_sha256")
	if err != nil {
		return nil, err
	}
	for name, value := range baselineInputs {
		if !strings.HasPrefix(name, "av/") || !strings.HasSuffix(name, ".json") {
			continue
		}
		expected, ok := value.(string)
		if !ok || !validSHA(expected) {
			return nil, errors.New("invalid baseline metadata pin")
		}
		source, err := checked(filepath.Join(frozen, "experiments"), name)
		if err != nil {
			return nil, err
		}
		actual, err := SHA(source)
		if err != nil || actual != expected {
			return nil, errors.New("frozen baseline metadata changed")
		}
		target, err := checked(filepath.Join(repository, "experiments"), name)
		if err != nil {
			return nil, err
		}
		if err = copyFixed(source, target); err != nil {
			return nil, err
		}
	}
	native, err := object(nativeProof)
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(baseline, "experiments/host/.build/integrated-watchdog")
	if options.NativeBinary != "" {
		binary, err = canonical(options.NativeBinary)
		if err != nil {
			return nil, err
		}
		var info unix.Stat_t
		if unix.Lstat(binary, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&07777 != 0500 {
			return nil, errors.New("qualified native binary must be owner-only mode0500")
		}
	}
	nativeSource := filepath.Join(repository, "experiments/host/integrated_watchdog.m")
	binaryHash, err := SHA(binary)
	if err != nil {
		return nil, err
	}
	nativeSourceHash, err := SHA(nativeSource)
	if err != nil {
		return nil, err
	}
	if !isTrue(native, "passed") || str(native, "kind") != "launchagent_death" || str(native, "binary_sha256") != binaryHash || str(native, "native_source_sha256") != nativeSourceHash {
		return nil, errors.New("native monitor proof mismatch")
	}
	debugfs := "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"
	if err = toolVersion(ctx, debugfs, "debugfs"); err != nil {
		return nil, err
	}
	sources, err := sourcePins(repository)
	if err != nil {
		return nil, err
	}
	relative, err := relativePins(sources, repository)
	if err != nil {
		return nil, err
	}
	corpusManifest := filepath.Join(repository, "experiments/contracts/corpus-v1.json")
	corpus, err := object(corpusManifest)
	if err != nil {
		return nil, err
	}
	corpusArchive := filepath.Join(verification, "fixtures/contracts-v1.tar.gz")
	corpusHash, err := SHA(corpusArchive)
	if err != nil || corpusHash != str(corpus, "archive_sha256") {
		return nil, errors.New("fixed contract corpus archive digest mismatch")
	}
	corpusInfo, err := os.Stat(corpusArchive)
	if err != nil || !corpusInfo.Mode().IsRegular() || corpusInfo.Size() != number(corpus, "archive_bytes") || number(corpus, "schema") != 1 {
		return nil, errors.New("fixed contract corpus bounds mismatch")
	}
	corpusInputs := map[string]string{corpusArchive: corpusHash, freshclam: mustSHA(freshclam), freshclamBuild: mustSHA(freshclamBuild), binary: binaryHash, nativeProof: mustSHA(nativeProof)}
	vm := filepath.Join(repository, "experiments/vm")
	build := filepath.Join(vm, ".build")
	if err = os.MkdirAll(build, 0700); err != nil {
		return nil, err
	}
	known := []string{"base.ext4", "definitions.ext4", "initramfs.cpio.gz", "vm-guest", "filegate-worker", "filegate-av-fixture", "image-fixture", "filegate-fixtures", "filegate-freshclam", "freshclam-build.json", "filegate-bridge", "filegate-fixture-bridge", "contracts-fixtures.tar.gz"}
	for _, name := range known {
		if _, err = os.Lstat(filepath.Join(build, name)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("new output workspace required; existing images are immutable")
		}
	}
	staging, err := os.MkdirTemp(build, "format-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	for _, item := range []struct{ name, target, directory, pkg string }{{"filegate-bridge", "darwin", repository, "./cmd/filegate-bridge"}, {"filegate-fixture-bridge", "darwin", repository, "./cmd/filegate-fixture-bridge"}, {"vm-guest", "linux", vm, "."}, {"filegate-worker", "linux", repository, "./cmd/filegate-worker"}, {"filegate-av-fixture", "linux", repository, "./experiments/productav/driver"}, {"image-fixture", "linux", filepath.Join(repository, "experiments/contracts"), "./image_fixture"}, {"filegate-fixtures", "linux", repository, "./cmd/filegate-fixtures"}} {
		if _, _, err = command(ctx, item.directory, goEnvironment(item.target), "go", "build", "-trimpath", "-o", filepath.Join(staging, item.name), item.pkg); err != nil {
			return nil, err
		}
	}
	if err = os.Chmod(filepath.Join(staging, "filegate-bridge"), 0500); err != nil {
		return nil, err
	}
	if err = os.Chmod(filepath.Join(staging, "filegate-fixture-bridge"), 0500); err != nil {
		return nil, err
	}
	fixtureRoot := filepath.Join(staging, "av-fixtures")
	if err = os.Mkdir(fixtureRoot, 0700); err != nil {
		return nil, err
	}
	fixture, err := GenerateAVFixtures(repository, fixtureRoot, observation)
	if err != nil {
		return nil, err
	}
	if err = copyNew(corpusArchive, filepath.Join(staging, "contracts-fixtures.tar.gz"), 0444); err != nil {
		return nil, err
	}
	if err = copyNew(freshclam, filepath.Join(staging, "filegate-freshclam"), 0500); err != nil {
		return nil, err
	}
	if err = copyNew(freshclamBuild, filepath.Join(staging, "freshclam-build.json"), 0600); err != nil {
		return nil, err
	}
	image := filepath.Join(staging, "base.ext4")
	if err = copyNew(filepath.Join(baseline, "experiments/vm/.build/base.ext4"), image, 0600); err != nil {
		return nil, err
	}
	compilerPackages, err := trimCompilerImage(ctx, debugfs, image, staging, freshclamBuild, verification)
	if err != nil {
		return nil, err
	}
	pythonRuntime, err := removeImagePython(ctx, debugfs, image)
	if err != nil {
		return nil, err
	}
	installs := map[string]string{"/vm-guest": filepath.Join(staging, "vm-guest"), "/filegate-worker": filepath.Join(staging, "filegate-worker"), "/filegate-av-fixture": filepath.Join(staging, "filegate-av-fixture"), "/image-fixture": filepath.Join(staging, "image-fixture"), "/filegate-fixtures": filepath.Join(staging, "filegate-fixtures"), "/av/product-profile-fixture.json": filepath.Join(fixtureRoot, "product-profile-fixture.json"), "/contracts/fixtures.tar.gz": filepath.Join(staging, "contracts-fixtures.tar.gz"), "/contracts/corpus-v1.json": corpusManifest}
	installs["/filegate-freshclam"] = filepath.Join(staging, "filegate-freshclam")
	fixtureFiles, err := os.ReadDir(filepath.Join(fixtureRoot, "product-fixtures"))
	if err != nil {
		return nil, err
	}
	for _, entry := range fixtureFiles {
		installs["/av/product-fixtures/"+entry.Name()] = filepath.Join(fixtureRoot, "product-fixtures", entry.Name())
	}
	for _, name := range []string{"zip32-v1.json", "txt-v1.json", "image-v1.json", "ooxml-v1.json"} {
		installs["/contracts/"+name] = filepath.Join(repository, "experiments/contracts", name)
	}
	for _, name := range []string{"remaining_candidate/boundary_observer.c", "xml_error_observer.c", "xml_dict_probe.c"} {
		installs["/av/"+name] = filepath.Join(repository, "experiments/av", name)
	}
	executables := map[string]bool{"/vm-guest": true, "/filegate-worker": true, "/filegate-av-fixture": true, "/image-fixture": true, "/filegate-fixtures": true}
	executables["/filegate-freshclam"] = true
	remove := []string{"/vm-guest"}
	external, err := nested(baselineBuild, "external_sources_sha256")
	if err != nil {
		return nil, err
	}
	for name := range external {
		if strings.HasPrefix(name, "av/") && strings.HasSuffix(name, ".py") {
			remove = append(remove, "/"+name)
		}
	}
	installed, err := installImage(ctx, debugfs, image, staging, installs, executables, remove, []string{"/contracts", "/av/product-fixtures"})
	if err != nil {
		return nil, err
	}
	definitions := filepath.Join(staging, "definitions.ext4")
	if err = copyNew(filepath.Join(baseline, "experiments/vm/.build/definitions.ext4"), definitions, 0600); err != nil {
		return nil, err
	}
	if _, err = installImage(ctx, debugfs, definitions, staging, map[string]string{"/marker.ndb": filepath.Join(fixtureRoot, "marker.ndb")}, map[string]bool{}, nil, nil); err != nil {
		return nil, err
	}
	info, err := os.Stat(definitions)
	if err != nil || info.Size() != 16<<20 {
		return nil, errors.New("fixture definition image size mismatch")
	}
	if err = verifyPins(sources); err != nil {
		return nil, err
	}
	if err = verifyPins(original); err != nil {
		return nil, err
	}
	if err = verifyPins(corpusInputs); err != nil {
		return nil, err
	}
	for _, name := range known {
		if name == "initramfs.cpio.gz" {
			continue
		}
		if err = os.Rename(filepath.Join(staging, name), filepath.Join(build, name)); err != nil {
			return nil, err
		}
	}
	if err = copyFixed(filepath.Join(baseline, "experiments/vm/.build/initramfs.cpio.gz"), filepath.Join(build, "initramfs.cpio.gz")); err != nil {
		return nil, err
	}
	initramfsInspection, err := InspectCPIO(filepath.Join(build, "initramfs.cpio.gz"))
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"vmlinuz-virt", "config-6.18.58-0-virt"} {
		if err = copyFixed(filepath.Join(baseline, "experiments/vm/.cache/boot", name), filepath.Join(vm, ".cache/boot", name)); err != nil {
			return nil, err
		}
	}
	if err = copyFixed(binary, filepath.Join(repository, "experiments/host/.build/integrated-watchdog")); err != nil {
		return nil, err
	}
	if err = atomicFile(filepath.Join(repository, "experiments/host/.build/integrated-build.json"), []byte(fmt.Sprintf("{\"source_sha256\":%q,\"binary_sha256\":%q}\n", nativeSourceHash, binaryHash)), 0600); err != nil {
		return nil, err
	}
	hostBuild := filepath.Join(repository, ".build")
	if err = os.MkdirAll(hostBuild, 0700); err != nil {
		return nil, err
	}
	hostRunners := map[string]any{}
	for _, name := range []string{"filegate-vm", "filegate-update"} {
		target := filepath.Join(hostBuild, name)
		if _, err = os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("host runner output must be new")
		}
		if _, _, err = command(ctx, repository, goEnvironment("darwin"), "go", "build", "-trimpath", "-o", target, "./cmd/"+name); err != nil {
			return nil, err
		}
		if err = os.Chmod(target, 0500); err != nil {
			return nil, err
		}
		hash, err := SHA(target)
		if err != nil {
			return nil, err
		}
		hostRunners[name] = map[string]any{"path": target, "sha256": hash}
	}
	if err = copyNew(filepath.Join(build, "filegate-fixture-bridge"), filepath.Join(hostBuild, "filegate-fixture-bridge"), 0500); err != nil {
		return nil, err
	}
	if err = verifyPins(sources); err != nil {
		return nil, err
	}
	if err = verifyPins(original); err != nil {
		return nil, err
	}
	if err = verifyPins(corpusInputs); err != nil {
		return nil, err
	}
	output := map[string]any{}
	for key, value := range baselineBuild {
		output[key] = value
	}
	artifacts := map[string]string{}
	for _, name := range known {
		hash, err := SHA(filepath.Join(build, name))
		if err != nil {
			return nil, err
		}
		artifacts[".build/"+name] = hash
	}
	for _, name := range []string{"vmlinuz-virt", "config-6.18.58-0-virt"} {
		hash, err := SHA(filepath.Join(vm, ".cache/boot", name))
		if err != nil {
			return nil, err
		}
		artifacts[".cache/boot/"+name] = hash
	}
	vmSources := map[string]string{}
	externalSources := map[string]string{}
	for path, hash := range sources {
		if within(path, vm) {
			name, _ := filepath.Rel(vm, path)
			vmSources[filepath.ToSlash(name)] = hash
		} else {
			name, _ := filepath.Rel(filepath.Join(repository, "experiments"), path)
			externalSources[filepath.ToSlash(name)] = hash
		}
	}
	output["schema"] = 4
	output["evidence_kind"] = "derived_format_VM_construction_only"
	output["runtime_executed"] = false
	output["baseline"] = map[string]any{"proof_path": proof, "proof_sha256": mustSHA(proof), "source_and_image_sha256": original}
	output["product_sources_sha256"] = relative
	output["sources_sha256"] = vmSources
	output["external_sources_sha256"] = externalSources
	output["artifacts"] = artifacts
	output["installed_files"] = installed
	output["product_helper"] = map[string]any{"sha256": mustSHA(filepath.Join(build, "filegate-bridge")), "implementation": "go", "sources_sha256": relative}
	output["host_runner"] = hostRunners["filegate-vm"]
	output["host_update_runner"] = hostRunners["filegate-update"]
	output["native_proof_sha256"] = mustSHA(nativeProof)
	tools, err := qemuruntime.Capture(ctx)
	if err != nil {
		return nil, err
	}
	output["qemu_runtime"] = tools
	output["av_fixture"] = fixture
	output["normal_product_profile_installed"] = false
	output["official_definitions_adopted"] = false
	output["copied_baseline_inputs"] = []string{}
	output["shared_runtime_state"] = filepath.Join(verification, "experiments/host/.build")
	output["production_enabled"] = false
	output["implementation"] = "go"
	output["project_python_scripts_absent"] = remove[1:]
	output["python_runtime"] = pythonRuntime
	output["compiler_package_subset"] = compilerPackages
	output["initramfs_inspection"] = initramfsInspection
	output["contract_fixture_corpus"] = map[string]any{"manifest_path": corpusManifest, "manifest_sha256": mustSHA(corpusManifest), "archive_input": corpusArchive, "archive_sha256": corpusHash, "file_count": corpus["file_count"], "case_counts": corpus["case_counts"]}
	output["external_input_sha256"] = corpusInputs
	if err = os.MkdirAll(filepath.Join(vm, "evidence"), 0700); err != nil {
		return nil, err
	}
	receipt := filepath.Join(vm, "evidence/build.json")
	if err = saveNewJSON(receipt, output); err != nil {
		return nil, err
	}
	if err = syncDirectory(build); err != nil {
		return nil, err
	}
	return map[string]any{"built": true, "runtime_executed": false, "installed_files": len(installed), "baseline_unchanged": true, "evidence": receipt, "host_runners": hostRunners, "python_dependency": false}, nil
}

func mustSHA(path string) string {
	hash, err := SHA(path)
	if err != nil {
		panic(err)
	}
	return hash
}

func cloneJSON(value map[string]any) map[string]any {
	body, _ := json.Marshal(value)
	result := map[string]any{}
	json.Unmarshal(body, &result)
	return result
}
