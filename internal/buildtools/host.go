package buildtools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filegate.local/filegate/internal/qemuruntime"
	"golang.org/x/sys/unix"
)

// Guest binaries whose bytes must be reproduced from the new sources before the baseline images are reused.
var hostGuestTargets = []struct{ name, module, pkg string }{
	{"filegate-worker", ".", "./cmd/filegate-worker"},
	{"filegate-av-fixture", ".", "./experiments/productav/driver"},
	{"filegate-fixtures", ".", "./cmd/filegate-fixtures"},
	{"vm-guest", "experiments/vm", "."},
	{"image-fixture", "experiments/contracts", "./image_fixture"},
}

var hostCopiedArtifacts = []string{".build/base.ext4", ".build/definitions.ext4", ".build/initramfs.cpio.gz", ".build/contracts-fixtures.tar.gz", ".build/filegate-freshclam", ".build/freshclam-build.json", ".build/filegate-worker", ".build/filegate-av-fixture", ".build/filegate-fixtures", ".build/vm-guest", ".build/image-fixture", ".cache/boot/vmlinuz-virt", ".cache/boot/config-6.18.58-0-virt"}

var hostRebuiltArtifacts = []string{".build/filegate-bridge", ".build/filegate-fixture-bridge"}

// BuildHost derives a scan build from an existing one when only host-side sources changed: guest images are reused byte for byte,
// except that build-guest may replace the allowlisted fixture binaries and build-inspector also the ZIP inspector binaries and
// contract, and host binaries are rebuilt.
func BuildHost(ctx context.Context, options BuildOptions) (map[string]any, error) {
	if (options.NativeBinary == "") != (options.ReplacementNativeProof == "") {
		return nil, errors.New("native binary and replacement proof must be specified together")
	}
	// build-inspector extends build-guest; its replacements go through the same image installation and comparison.
	options.GuestFixtures = options.GuestFixtures || options.Inspector
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
	baseline, err := canonical(options.Baseline)
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
	goVersion, _, err := command(ctx, "", nil, "go", "version")
	if err != nil {
		return nil, err
	}
	receiptPath := filepath.Join(baseline, "experiments/vm/evidence/build.json")
	receiptSHA, err := SHA(receiptPath)
	if err != nil {
		return nil, err
	}
	var old map[string]any
	if err = readJSON(receiptPath, &old); err != nil {
		return nil, err
	}
	if number(old, "schema") != 4 || str(old, "evidence_kind") != "derived_format_VM_construction_only" {
		return nil, errors.New("baseline must be a schema-4 scan build receipt")
	}

	pinned := map[string]string{}
	pinGroup := func(group, base string, rows map[string]any) (int, error) {
		for name, value := range rows {
			expected, ok := value.(string)
			path := filepath.Join(base, filepath.FromSlash(name))
			if !ok || !validSHA(expected) || !within(path, baseline) {
				return 0, fmt.Errorf("invalid baseline %s pin: %s", group, name)
			}
			pinned[path] = expected
		}
		return len(rows), nil
	}
	verified := map[string]any{}
	for _, group := range []struct{ name, base string }{{"product_sources_sha256", baseline}, {"sources_sha256", filepath.Join(baseline, "experiments/vm")}, {"external_sources_sha256", filepath.Join(baseline, "experiments")}, {"artifacts", filepath.Join(baseline, "experiments/vm")}} {
		rows, err := nested(old, group.name)
		if err != nil {
			return nil, err
		}
		if verified[group.name], err = pinGroup(group.name, group.base, rows); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"host_runner", "host_update_runner"} {
		runner, err := nested(old, name)
		if err != nil {
			return nil, err
		}
		path := str(runner, "path")
		if !validSHA(str(runner, "sha256")) || !within(path, baseline) {
			return nil, fmt.Errorf("invalid baseline %s", name)
		}
		pinned[path] = str(runner, "sha256")
		verified[name] = 1
	}
	native, err := object(nativeProof)
	if err != nil {
		return nil, err
	}
	nativeBinary := filepath.Join(baseline, "experiments/host/.build/integrated-watchdog")
	nativeSource := filepath.Join(baseline, "experiments/host/integrated_watchdog.m")
	if str(old, "native_proof_sha256") != mustSHA(nativeProof) || !isTrue(native, "passed") || str(native, "kind") != "launchagent_death" || str(native, "binary_sha256") != mustSHA(nativeBinary) || str(native, "native_source_sha256") != mustSHA(nativeSource) {
		return nil, errors.New("native monitor proof mismatch")
	}
	if err = verifyPins(pinned); err != nil {
		return nil, err
	}
	artifacts, _ := nested(old, "artifacts")
	expectedArtifacts := append(append([]string{}, hostCopiedArtifacts...), hostRebuiltArtifacts...)
	if len(artifacts) != len(expectedArtifacts) {
		return nil, errors.New("baseline artifact set differs from the derivable set")
	}
	for _, name := range expectedArtifacts {
		if _, ok := artifacts[name]; !ok {
			return nil, fmt.Errorf("baseline artifact missing: %s", name)
		}
	}
	oldSources, _ := nested(old, "product_sources_sha256")
	avFixture, _ := nested(old, "av_fixture")
	fixtureFiles, _ := nested(avFixture, "files_sha256")
	installed, err := nested(old, "installed_files")
	if err != nil {
		return nil, err
	}
	installedSources := map[string]string{"/contracts/fixtures.tar.gz": artifactPin(artifacts, ".build/contracts-fixtures.tar.gz")}
	for _, name := range []string{"filegate-worker", "filegate-av-fixture", "filegate-fixtures", "filegate-freshclam", "image-fixture", "vm-guest"} {
		installedSources["/"+name] = artifactPin(artifacts, ".build/"+name)
	}
	for _, name := range []string{"corpus-v1.json", "image-v1.json", "ooxml-v1.json", "txt-v1.json", "zip32-v1.json"} {
		installedSources["/contracts/"+name] = artifactPin(oldSources, "experiments/contracts/"+name)
	}
	for _, name := range []string{"remaining_candidate/boundary_observer.c", "xml_dict_probe.c", "xml_error_observer.c"} {
		installedSources["/av/"+name] = artifactPin(oldSources, "experiments/av/"+name)
	}
	fixtureHashes := map[string]bool{}
	for _, value := range fixtureFiles {
		if hash, ok := value.(string); ok {
			fixtureHashes[hash] = true
		}
	}
	for path, value := range installed {
		row, _ := value.(map[string]any)
		hash := str(row, "sha256")
		expected, mapped := installedSources[path]
		if mapped && hash != expected || !mapped && (!strings.HasPrefix(path, "/av/product-") || !fixtureHashes[hash]) {
			return nil, fmt.Errorf("installed file does not correspond to a baseline artifact or source: %s", path)
		}
	}
	verified["installed_files"] = len(installed)
	verified["native"] = map[string]any{"proof": nativeProof, "proof_sha256": mustSHA(nativeProof), "binary_sha256": mustSHA(nativeBinary), "source_sha256": mustSHA(nativeSource)}
	if options.NativeBinary != "" {
		binary, err := canonical(options.NativeBinary)
		if err != nil {
			return nil, err
		}
		var info unix.Stat_t
		if unix.Lstat(binary, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&07777 != 0500 {
			return nil, errors.New("qualified native binary must be owner-only mode0500")
		}
		proof, err := canonical(options.ReplacementNativeProof)
		if err != nil {
			return nil, err
		}
		replacement, err := object(proof)
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
		proofSHA, err := SHA(proof)
		if err != nil {
			return nil, err
		}
		if !isTrue(replacement, "passed") || str(replacement, "kind") != "launchagent_death" || str(replacement, "binary_sha256") != binarySHA || str(replacement, "native_source_sha256") != sourceSHA {
			return nil, errors.New("replacement native monitor proof mismatch")
		}
		verified["replacement_native"] = map[string]any{"proof": proof, "proof_sha256": proofSHA, "binary": binary, "binary_sha256": binarySHA, "source": source, "source_sha256": sourceSHA}
		pinned[binary], pinned[proof] = binarySHA, proofSHA
		nativeBinary, nativeProof, native = binary, proof, replacement
	}

	vm := filepath.Join(repository, "experiments/vm")
	build := filepath.Join(vm, ".build")
	hostBuild := filepath.Join(repository, ".build")
	for _, name := range append(append(append([]string{}, hostCopiedArtifacts...), hostRebuiltArtifacts...), "evidence/build.json") {
		if _, err = os.Lstat(filepath.Join(vm, name)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("new output workspace required; existing images are immutable")
		}
	}
	for _, path := range []string{filepath.Join(hostBuild, "filegate-vm"), filepath.Join(hostBuild, "filegate-update"), filepath.Join(hostBuild, "filegate-fixture-bridge"), filepath.Join(repository, "experiments/host/.build/integrated-watchdog")} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("host output must be new")
		}
	}
	copiedInputs := []string{}
	for name := range oldSources {
		path := filepath.Join(repository, filepath.FromSlash(name))
		if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if !strings.HasPrefix(name, "experiments/av/evidence/") {
				return nil, fmt.Errorf("baseline source missing from the new workspace: %s", name)
			}
			if err = copyNew(filepath.Join(baseline, filepath.FromSlash(name)), path, 0600); err != nil {
				return nil, err
			}
			copiedInputs = append(copiedInputs, name)
		}
	}
	sort.Strings(copiedInputs)
	if mustSHA(filepath.Join(repository, "experiments/host/integrated_watchdog.m")) != str(native, "native_source_sha256") {
		return nil, errors.New("native monitor source changed")
	}
	sources, err := sourcePins(repository)
	if err != nil {
		return nil, err
	}
	relative, err := relativePins(sources, repository)
	if err != nil {
		return nil, err
	}
	changed := []map[string]any{}
	for name, value := range relative {
		if oldSources[name] != value {
			changed = append(changed, map[string]any{"path": name, "baseline_sha256": oldSources[name], "sha256": value})
		}
	}
	for name, value := range oldSources {
		if _, ok := relative[name]; !ok {
			changed = append(changed, map[string]any{"path": name, "baseline_sha256": value, "sha256": nil})
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i]["path"].(string) < changed[j]["path"].(string) })

	guestInputs := map[string]bool{}
	imageInputs := map[string]bool{}
	for name := range relative {
		if !strings.HasPrefix(name, "cmd/") && !strings.HasPrefix(name, "internal/") {
			guestInputs[name] = true
			imageInputs[name] = true
		}
	}
	targetInputs := map[string]map[string]bool{}
	for _, target := range hostGuestTargets {
		targetInputs[target.name] = map[string]bool{}
		listed, _, err := command(ctx, filepath.Join(repository, target.module), goEnvironment("linux"), "go", "list", "-deps", "-f", "{{.Dir}}{{range .GoFiles}}|{{.}}{{end}}{{range .CgoFiles}}|{{.}}{{end}}{{range .SFiles}}|{{.}}{{end}}{{range .HFiles}}|{{.}}{{end}}{{range .CFiles}}|{{.}}{{end}}{{range .EmbedFiles}}|{{.}}{{end}}{{with .Module}}{{if .GoMod}}|{{.GoMod}}{{end}}{{end}}", target.pkg)
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
					guestInputs[filepath.ToSlash(name)] = true
					targetInputs[target.name][filepath.ToSlash(name)] = true
				}
			}
		}
	}
	// build-guest accepts only changed sources that no guest binary other than a replaceable one reads.
	guestChanged, inspectorChanged := []string{}, []string{}
	var acceptedContract, inspectorContractChange map[string]any
	for _, row := range changed {
		name := row["path"].(string)
		if !guestInputs[name] {
			continue
		}
		read := false
		for _, target := range hostGuestTargets {
			read = read || targetInputs[target.name][name]
		}
		if options.NativeBinary != "" && name == "experiments/host/integrated_watchdog.m" && !read {
			delete(guestInputs, name)
			continue
		}
		// The host-budget contract is neither read by a guest target nor installed in the image.
		if name == hostBudgetContract && !read {
			oldSHA, _ := row["baseline_sha256"].(string)
			newSHA, _ := row["sha256"].(string)
			if acceptedContract, err = hostBudgetAccountingDelta(filepath.Join(baseline, filepath.FromSlash(name)), oldSHA, filepath.Join(repository, filepath.FromSlash(name)), newSHA); err != nil {
				return nil, err
			}
			delete(guestInputs, name)
			continue
		}
		kind, err := guestChange(name, imageInputs[name], targetInputs, options)
		if err != nil {
			return nil, err
		}
		if kind == "inspector" {
			if name == zipContract {
				oldSHA, _ := row["baseline_sha256"].(string)
				newSHA, _ := row["sha256"].(string)
				if inspectorContractChange, err = inspectorContract(filepath.Join(baseline, filepath.FromSlash(name)), oldSHA, filepath.Join(repository, filepath.FromSlash(name)), newSHA); err != nil {
					return nil, err
				}
			}
			inspectorChanged = append(inspectorChanged, name)
			continue
		}
		guestChanged = append(guestChanged, name)
	}
	if options.Inspector && (inspectorContractChange == nil || len(inspectorChanged) < 2) {
		return nil, errors.New("build-inspector requires a changed ZIP inspector source and the approved ZIP contract")
	}

	staging, err := os.MkdirTemp(repository, "host-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	buildRecord := func(name, target, directory, pkg, output string) (map[string]any, error) {
		argv := []string{"go", "build", "-trimpath", "-buildvcs=false", "-o", output, pkg}
		if _, _, err := command(ctx, directory, goEnvironment(target), argv...); err != nil {
			return nil, err
		}
		hash, err := SHA(output)
		if err != nil {
			return nil, err
		}
		relativeDirectory, _ := filepath.Rel(repository, directory)
		return map[string]any{"name": name, "directory": filepath.ToSlash(relativeDirectory), "argv": argv[:len(argv)-3], "package": pkg, "environment": fixedGoEnvironment(target), "sha256": hash}, nil
	}
	guestComparison := []map[string]any{}
	replacements := map[string]string{}
	for _, target := range hostGuestTargets {
		record, err := buildRecord(target.name, "linux", filepath.Join(repository, target.module), target.pkg, filepath.Join(staging, target.name))
		if err != nil {
			return nil, err
		}
		record["baseline_sha256"] = artifacts[".build/"+target.name]
		record["equal"] = record["sha256"] == record["baseline_sha256"]
		if options.GuestFixtures && guestReplaceable["/"+target.name] != "" || options.Inspector && inspectorReplaceable["/"+target.name] != "" {
			repeat, err := buildRecord(target.name, "linux", filepath.Join(repository, target.module), target.pkg, filepath.Join(staging, target.name+"-repeat"))
			if err != nil {
				return nil, err
			}
			if repeat["sha256"] != record["sha256"] {
				return nil, fmt.Errorf("replaceable guest binary is not reproducible: %s", target.name)
			}
			record["repeat_build_equal"] = true
			if record["equal"] != true {
				replacements["/"+target.name] = filepath.Join(staging, target.name)
			}
		}
		guestComparison = append(guestComparison, record)
		if record["equal"] != true && replacements["/"+target.name] == "" {
			return nil, fmt.Errorf("guest binary not reproduced from the new sources: %s", target.name)
		}
	}
	if len(guestChanged) != 0 && len(replacements) == 0 {
		return nil, errors.New("changed guest sources did not change a replaceable binary")
	}
	if options.Inspector {
		if replacements["/filegate-worker"] == "" {
			return nil, errors.New("changed inspector sources did not change the worker")
		}
		contract := filepath.Join(staging, "zip32-v1.json")
		if err = copyNew(filepath.Join(repository, zipContract), contract, 0400); err != nil {
			return nil, err
		}
		if mustSHA(contract) != zipContractV2 {
			return nil, fmt.Errorf("pinned source/artifact changed: %s", zipContract)
		}
		replacements[zipContractImagePath] = contract
	}

	debugfs := "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"
	if err = toolVersion(ctx, debugfs, "debugfs"); err != nil {
		return nil, err
	}
	copiedUnchanged := []string{}
	for _, name := range hostCopiedArtifacts {
		target := filepath.Join(vm, filepath.FromSlash(name))
		if binary := replacements["/"+strings.TrimPrefix(name, ".build/")]; binary != "" {
			if err = copyNew(binary, target, 0); err != nil {
				return nil, err
			}
			continue
		}
		if err = copyNew(filepath.Join(baseline, "experiments/vm", filepath.FromSlash(name)), target, 0); err != nil {
			return nil, err
		}
		if mustSHA(target) != artifacts[name] {
			return nil, fmt.Errorf("copied artifact changed: %s", name)
		}
		if name != ".build/base.ext4" || len(replacements) == 0 {
			copiedUnchanged = append(copiedUnchanged, name)
		}
	}
	installedExpected := map[string]string{}
	for path, value := range installed {
		row, _ := value.(map[string]any)
		installedExpected[path] = str(row, "sha256")
	}
	var guestReplacement map[string]any
	if options.GuestFixtures {
		image := filepath.Join(build, "base.ext4")
		executables := map[string]bool{}
		for path, binary := range replacements {
			executables[path] = path != zipContractImagePath
			if installedExpected[path], err = SHA(binary); err != nil {
				return nil, err
			}
		}
		if len(replacements) != 0 {
			if _, err = installImage(ctx, debugfs, image, staging, replacements, executables, nil, nil); err != nil {
				return nil, err
			}
		}
		replacedPaths := map[string]bool{}
		for path := range replacements {
			replacedPaths[path] = true
		}
		comparison, err := compareImages(ctx, debugfs, filepath.Join(baseline, "experiments/vm/.build/base.ext4"), image, staging, replacedPaths)
		if err != nil {
			return nil, err
		}
		allowed := []string{}
		for path := range guestReplaceable {
			allowed = append(allowed, path)
		}
		if options.Inspector {
			allowed = append(allowed, zipContractImagePath)
			for path := range inspectorReplaceable {
				if guestReplaceable[path] == "" {
					allowed = append(allowed, path)
				}
			}
		}
		sort.Strings(allowed)
		guestReplacement = map[string]any{"allowlist": allowed, "changed_guest_sources": guestChanged, "parent_image_sha256": artifacts[".build/base.ext4"], "image_sha256": mustSHA(image), "comparison": comparison, "contract_change": false}
		if options.Inspector {
			guestReplacement["mode"] = "build-inspector"
			guestReplacement["changed_inspector_sources"] = inspectorChanged
			guestReplacement["contract_change"] = true
			guestReplacement["contract"] = inspectorContractChange
			guestReplacement["contract_fixture_corpus"] = "copied unchanged as regression inputs; its fixture manifest still records the Profile 1 contract digest, which the runner does not check, so it is not Profile 2 evidence"
		}
	}
	readback := filepath.Join(staging, "installed")
	if err = os.Mkdir(readback, 0700); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(installed))
	for path := range installed {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for i, path := range paths {
		quoted, err := quoteDebugfs(path)
		if err != nil {
			return nil, err
		}
		output := filepath.Join(readback, fmt.Sprint(i))
		target, err := quoteDebugfs(output)
		if err != nil {
			return nil, err
		}
		if _, _, err = command(ctx, "", nil, debugfs, "-R", "dump "+quoted+" "+target, filepath.Join(build, "base.ext4")); err != nil {
			return nil, err
		}
		if actual, err := SHA(output); err != nil || actual != installedExpected[path] {
			return nil, fmt.Errorf("installed file differs in the reused image: %s", path)
		}
	}
	verified["installed_files_image_readback"] = len(paths)

	hostBuilds := []map[string]any{}
	for _, item := range []struct{ name, pkg, output string }{{"filegate-bridge", "./cmd/filegate-bridge", filepath.Join(build, "filegate-bridge")}, {"filegate-fixture-bridge", "./cmd/filegate-fixture-bridge", filepath.Join(build, "filegate-fixture-bridge")}, {"filegate-vm", "./cmd/filegate-vm", filepath.Join(hostBuild, "filegate-vm")}, {"filegate-update", "./cmd/filegate-update", filepath.Join(hostBuild, "filegate-update")}} {
		if err = os.MkdirAll(filepath.Dir(item.output), 0700); err != nil {
			return nil, err
		}
		record, err := buildRecord(item.name, "darwin", repository, item.pkg, item.output)
		if err != nil {
			return nil, err
		}
		if err = os.Chmod(item.output, 0500); err != nil {
			return nil, err
		}
		record["path"] = item.output
		hostBuilds = append(hostBuilds, record)
	}
	if err = copyNew(filepath.Join(build, "filegate-fixture-bridge"), filepath.Join(hostBuild, "filegate-fixture-bridge"), 0500); err != nil {
		return nil, err
	}
	if err = copyNew(nativeBinary, filepath.Join(repository, "experiments/host/.build/integrated-watchdog"), 0); err != nil {
		return nil, err
	}
	if err = atomicFile(filepath.Join(repository, "experiments/host/.build/integrated-build.json"), []byte(fmt.Sprintf("{\"source_sha256\":%q,\"binary_sha256\":%q}\n", str(native, "native_source_sha256"), str(native, "binary_sha256"))), 0600); err != nil {
		return nil, err
	}
	if err = verifyPins(sources); err != nil {
		return nil, err
	}
	if err = verifyPins(pinned); err != nil {
		return nil, err
	}
	// The QEMU closure is never inherited from the baseline: it is captured from the current fixed-keg bytes and frozen in this receipt.
	tools, err := qemuruntime.Capture(ctx)
	if err != nil {
		return nil, err
	}

	output := cloneJSON(old)
	newArtifacts := map[string]string{}
	for _, name := range expectedArtifacts {
		newArtifacts[name] = mustSHA(filepath.Join(vm, filepath.FromSlash(name)))
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
	corpus, _ := nested(old, "contract_fixture_corpus")
	corpus = cloneJSON(corpus)
	corpus["manifest_path"] = filepath.Join(repository, "experiments/contracts/corpus-v1.json")
	corpus["archive_input"] = filepath.Join(baseline, "experiments/vm/.build/contracts-fixtures.tar.gz")
	inherited := []string{}
	for key := range old {
		switch key {
		case "created_utc", "go", "runtime_executed", "baseline", "product_sources_sha256", "sources_sha256", "external_sources_sha256", "artifacts", "product_helper", "host_runner", "host_update_runner", "native_proof_sha256", "shared_runtime_state", "production_enabled", "copied_baseline_inputs", "contract_fixture_corpus", "external_input_sha256", "qemu_runtime":
		default:
			inherited = append(inherited, key)
		}
	}
	sort.Strings(inherited)
	historical, _ := nested(old, "baseline")
	historicalPins, _ := nested(historical, "source_and_image_sha256")
	present := 0
	for path := range historicalPins {
		if _, err := os.Stat(path); err == nil {
			present++
		}
	}
	output["created_utc"] = time.Now().UTC().Format(time.RFC3339)
	output["go"] = strings.TrimSpace(string(goVersion))
	output["runtime_executed"] = false
	output["production_enabled"] = false
	output["baseline"] = map[string]any{"kind": "derived_from_scan_build", "receipt_path": receiptPath, "receipt_sha256": receiptSHA}
	output["product_sources_sha256"] = relative
	output["sources_sha256"] = vmSources
	output["external_sources_sha256"] = externalSources
	output["artifacts"] = newArtifacts
	output["product_helper"] = map[string]any{"sha256": newArtifacts[".build/filegate-bridge"], "implementation": "go", "sources_sha256": relative}
	output["host_runner"] = map[string]any{"path": filepath.Join(hostBuild, "filegate-vm"), "sha256": mustSHA(filepath.Join(hostBuild, "filegate-vm"))}
	output["host_update_runner"] = map[string]any{"path": filepath.Join(hostBuild, "filegate-update"), "sha256": mustSHA(filepath.Join(hostBuild, "filegate-update"))}
	output["native_proof_sha256"] = mustSHA(nativeProof)
	output["qemu_runtime"] = tools
	output["shared_runtime_state"] = filepath.Join(verification, "experiments/host/.build")
	output["copied_baseline_inputs"] = copiedInputs
	output["contract_fixture_corpus"] = corpus
	output["external_input_sha256"] = map[string]string{receiptPath: receiptSHA, nativeProof: mustSHA(nativeProof), nativeBinary: mustSHA(nativeBinary)}
	output["derived_from"] = map[string]any{
		"receipt_path":                   receiptPath,
		"receipt_sha256":                 receiptSHA,
		"verified_pin_groups":            verified,
		"historical_baseline":            map[string]any{"proof_path": historical["proof_path"], "proof_sha256": historical["proof_sha256"], "pins": len(historicalPins), "pins_present": present, "status": "historical_unavailable_not_reverified"},
		"changed_sources":                changed,
		"guest_inputs_unchanged":         len(guestInputs),
		"guest_comparison":               guestComparison,
		"host_builds":                    hostBuilds,
		"copied_artifacts_unchanged":     copiedUnchanged,
		"inherited_image_fields":         inherited,
		"baseline_external_input_sha256": old["external_input_sha256"],
		"baseline_qemu_runtime_present":  old["qemu_runtime"] != nil,
		"qemu_runtime_sha256":            qemuruntime.Digest(tools),
		"qemu_runtime_evidence":          "current fixed-keg bytes at construction; not evidence of a previously accepted environment",
		"stage0_gate_evidence":           "not restored or reverified by this construction",
	}
	if acceptedContract != nil {
		derived, _ := nested(output, "derived_from")
		derived["accepted_contract_metadata"] = acceptedContract
	}
	if guestReplacement != nil {
		derived, _ := nested(output, "derived_from")
		derived["guest_replacement"] = guestReplacement
		rows, _ := nested(output, "installed_files")
		for path := range replacements {
			row, _ := rows[path].(map[string]any)
			row["sha256"] = installedExpected[path]
		}
	}
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
	return map[string]any{"built": true, "runtime_executed": false, "evidence": receipt, "baseline_receipt_sha256": receiptSHA, "changed_sources": len(changed), "guest_binaries_reproduced": len(guestComparison), "host_runner": output["host_runner"], "host_update_runner": output["host_update_runner"]}, nil
}

// fixedGoEnvironment returns the build variables goEnvironment fixes for target, for build records.
func fixedGoEnvironment(target string) map[string]string {
	result := map[string]string{}
	for _, entry := range goEnvironment(target) {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case "GOOS", "GOARCH", "GOARM64", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOTOOLCHAIN", "GOPROXY":
			result[key] = value
		}
	}
	return result
}

func artifactPin(rows map[string]any, name string) string {
	value, _ := rows[name].(string)
	return value
}
