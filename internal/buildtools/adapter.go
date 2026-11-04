package buildtools

import (
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

const adapterSourceID = "1.4.6:5853e1396777bae4d909cd3dd44f58352e7cf9b3:filegate-v1"

var libraryName = regexp.MustCompile(`^lib(?:clamav|freshclam|clamunrar|clamunrar_iface)\.so(?:\.[0-9]+)*$`)

type adapterELF struct {
	Machine string   `json:"machine"`
	Needed  []string `json:"needed"`
	SONAME  []string `json:"soname"`
	RPath   []string `json:"rpath"`
}

type adapterEntry struct {
	Path    string      `json:"path"`
	Symlink string      `json:"symlink,omitempty"`
	Bytes   int64       `json:"bytes,omitempty"`
	SHA256  string      `json:"sha256,omitempty"`
	ELF     *adapterELF `json:"elf,omitempty"`
}

type AdapterBinding struct {
	Schema                 int            `json:"schema"`
	Mode                   string         `json:"mode"`
	Manifest               map[string]any `json:"manifest"`
	BuilderResultsSHA256   string         `json:"builder_results_sha256"`
	ArtifactManifestSHA256 string         `json:"artifact_manifest_sha256"`
	InputsSHA256           string         `json:"inputs_sha256"`
	BuilderSHA256          string         `json:"builder_sha256"`
}

func object(path string) (map[string]any, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("bounded regular metadata required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func nested(value map[string]any, name string) (map[string]any, error) {
	result, ok := value[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("object required: %s", name)
	}
	return result, nil
}
func str(value map[string]any, name string) string { result, _ := value[name].(string); return result }
func isTrue(value map[string]any, name string) bool {
	result, ok := value[name].(bool)
	return ok && result
}
func number(value map[string]any, name string) int64 {
	result, _ := value[name].(float64)
	return int64(result)
}
func contains(values []any, value string) bool {
	for _, entry := range values {
		if entry == value {
			return true
		}
	}
	return false
}

func verifyLibraryELF(path string) (adapterELF, error) {
	result := adapterELF{Machine: "AArch64", Needed: []string{}, SONAME: []string{}, RPath: []string{}}
	file, err := elf.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_AARCH64 {
		return result, errors.New("AArch64 ELF64 little endian library required")
	}
	result.Needed, err = file.ImportedLibraries()
	if err != nil {
		return result, err
	}
	if result.Needed == nil {
		result.Needed = []string{}
	}
	result.SONAME, err = file.DynString(elf.DT_SONAME)
	if err != nil {
		return result, err
	}
	if result.SONAME == nil {
		result.SONAME = []string{}
	}
	one, err := file.DynString(elf.DT_RPATH)
	if err != nil {
		return result, err
	}
	two, err := file.DynString(elf.DT_RUNPATH)
	if err != nil {
		return result, err
	}
	result.RPath = append(result.RPath, one...)
	result.RPath = append(result.RPath, two...)
	return result, nil
}

func adapterEntries(manifest map[string]any) ([]adapterEntry, error) {
	body, err := json.Marshal(manifest["entries"])
	if err != nil {
		return nil, err
	}
	var entries []adapterEntry
	if err = json.Unmarshal(body, &entries); err != nil || len(entries) < 4 || len(entries) > 32 {
		return nil, errors.New("fixed library count rejected")
	}
	return entries, nil
}

func verifyLibraries(root string, manifest map[string]any) error {
	entries, err := adapterEntries(manifest)
	if err != nil {
		return err
	}
	names := map[string]bool{}
	families := map[string]bool{}
	total := int64(0)
	for _, row := range entries {
		if !strings.HasPrefix(row.Path, "lib/") || !libraryName.MatchString(strings.TrimPrefix(row.Path, "lib/")) || names[row.Path] {
			return errors.New("fixed library path rejected")
		}
		names[row.Path] = true
		path := filepath.Join(root, row.Path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if row.Symlink != "" {
			if info.Mode()&os.ModeSymlink == 0 || !libraryName.MatchString(row.Symlink) {
				return errors.New("fixed library symlink rejected")
			}
			actual, err := os.Readlink(path)
			if err != nil || actual != row.Symlink {
				return errors.New("fixed library link target mismatch")
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil || filepath.Dir(resolved) != filepath.Join(root, "lib") {
				return errors.New("fixed library symlink escaped")
			}
		} else {
			if !info.Mode().IsRegular() || row.Bytes < 0 || info.Size() != row.Bytes || row.Bytes > 128<<20 || !validSHA(row.SHA256) {
				return errors.New("fixed library type/size rejected")
			}
			total += row.Bytes
			if total > 128<<20 {
				return errors.New("fixed library aggregate limit")
			}
			hash, err := SHA(path)
			if err != nil || hash != row.SHA256 {
				return errors.New("fixed library digest mismatch")
			}
			actual, err := verifyLibraryELF(path)
			if err != nil || row.ELF == nil || !reflect.DeepEqual(actual, *row.ELF) || !reflect.DeepEqual(actual.RPath, []string{"$ORIGIN"}) || len(actual.SONAME) != 1 {
				return errors.New("fixed library ELF binding mismatch")
			}
			families[strings.Split(filepath.Base(row.Path), ".so")[0]] = true
		}
	}
	actual, err := os.ReadDir(filepath.Join(root, "lib"))
	if err != nil || len(actual) != len(names) {
		return errors.New("fixed library inventory mismatch")
	}
	for _, entry := range actual {
		if !names["lib/"+entry.Name()] {
			return errors.New("unbound fixed library")
		}
	}
	for _, row := range entries {
		if row.Symlink != "" {
			if !names["lib/"+row.Symlink] {
				return errors.New("unbound library symlink")
			}
			continue
		}
		for _, name := range append(append([]string{}, row.ELF.SONAME...), row.ELF.Needed...) {
			if (strings.HasPrefix(name, "libclam") || strings.HasPrefix(name, "libfreshclam")) && !names["lib/"+name] {
				return errors.New("fixed library family incomplete")
			}
		}
	}
	if len(families) != 4 || !families["libclamav"] || !families["libfreshclam"] || !families["libclamunrar"] || !families["libclamunrar_iface"] {
		return errors.New("simultaneous library families missing")
	}
	return nil
}

func VerifyAdapter(path, avRoot string) (AdapterBinding, error) {
	var binding AdapterBinding
	path, err := canonical(path)
	if err != nil {
		return binding, err
	}
	result, err := object(filepath.Join(path, "results.json"))
	if err != nil {
		return binding, err
	}
	prepared, err := object(filepath.Join(path, "prepared.json"))
	if err != nil {
		return binding, err
	}
	inputs, err := object(filepath.Join(path, "inputs/inputs.json"))
	if err != nil {
		return binding, err
	}
	manifest, err := object(filepath.Join(path, "output/artifact-manifest.json"))
	if err != nil {
		return binding, err
	}
	if str(result, "evidence_kind") != "trusted_source_container_build_only" || !isTrue(result, "passed") || !isTrue(result, "container_stopped") || !isTrue(result, "owned_container_removed") || result["failure"] != nil {
		return binding, errors.New("builder completion and cleanup not proven")
	}
	if str(manifest, "evidence_kind") != "trusted_source_container_build_only" || str(manifest, "engine") != "1.4.6" || number(manifest, "adapter_abi") != 1 || str(manifest, "adapter_source_id") != adapterSourceID {
		return binding, errors.New("fixed adapter build identity mismatch")
	}
	tests, _ := manifest["upstream_tests_passed"].([]any)
	if !contains(tests, "libclamav") || !contains(tests, "libclamav_rust") {
		return binding, errors.New("upstream library tests missing")
	}
	inputsHash, err := SHA(filepath.Join(path, "inputs/inputs.json"))
	if err != nil {
		return binding, err
	}
	manifestHash, err := SHA(filepath.Join(path, "output/artifact-manifest.json"))
	if err != nil {
		return binding, err
	}
	resultHash, err := SHA(filepath.Join(path, "results.json"))
	if err != nil {
		return binding, err
	}
	if inputsHash != str(prepared, "inputs_sha256") || inputsHash != str(manifest, "input_manifest_sha256") || inputsHash != str(result, "inputs_sha256") || manifestHash != str(result, "artifact_manifest_sha256") {
		return binding, errors.New("builder input/artifact binding mismatch")
	}
	adopted, err := object(filepath.Join(avRoot, "adopted-bindings.json"))
	if err != nil {
		return binding, err
	}
	evidence, err := nested(adopted, "evidence")
	if err != nil {
		return binding, err
	}
	for _, name := range []string{"adapter_build", "adapter_manifest", "adapter_inputs"} {
		reference, err := nested(evidence, name)
		if err != nil {
			return binding, err
		}
		expected := str(reference, "sha256")
		actual := map[string]string{"adapter_build": resultHash, "adapter_manifest": manifestHash, "adapter_inputs": inputsHash}[name]
		if !validSHA(expected) || actual != expected {
			return binding, errors.New("adopted adapter receipt changed")
		}
	}
	current, err := object(filepath.Join(avRoot, "evidence/build-inputs.json"))
	if err != nil {
		return binding, err
	}
	for _, name := range []string{"source_archive_sha256", "patch_sha256"} {
		if inputs[name] != current[name] {
			return binding, errors.New("adapter source generation mismatch")
		}
	}
	if inputs["source_manifest_sha256"] != current["source_file_manifest_sha256"] {
		return binding, errors.New("adapter source tree mismatch")
	}
	files, err := nested(inputs, "files_sha256")
	if err != nil {
		return binding, err
	}
	// The adopted consumer checks its closed dependency set; source.tar is construction-only provenance.
	dependencies := map[string]bool{"build_adapter.sh": true, "entry.sh": true, "container_build.py": true, "rootfs.tar.gz": true}
	for _, name := range []string{"packages-build.json", "packages.json"} {
		packages, err := object(filepath.Join(avRoot, "evidence", name))
		if err != nil {
			return binding, err
		}
		rows, ok := packages["packages"].([]any)
		if !ok {
			return binding, errors.New("package rows required")
		}
		for _, value := range rows {
			row, ok := value.(map[string]any)
			if !ok {
				return binding, errors.New("package row invalid")
			}
			name := "packages/" + str(row, "name") + "-" + str(row, "version") + ".apk"
			if files[name] != row["sha256"] {
				return binding, errors.New("fixed APK settings mismatch")
			}
			dependencies[name] = true
		}
	}
	if !validSHA(str(files, "source.tar")) {
		return binding, errors.New("fixed source archive provenance missing")
	}
	for name := range dependencies {
		hash := files[name]
		expected, ok := hash.(string)
		if !ok || !validSHA(expected) {
			return binding, errors.New("invalid fixed build source digest")
		}
		checkedPath, err := checked(filepath.Join(path, "inputs"), name)
		if err != nil {
			return binding, err
		}
		actual, err := SHA(checkedPath)
		if err != nil || actual != expected {
			return binding, errors.New("fixed builder dependency changed")
		}
	}
	if files["rootfs.tar.gz"] != rootfsSHA {
		return binding, errors.New("fixed rootfs binding changed")
	}
	if err = verifyLibraries(filepath.Join(path, "output"), manifest); err != nil {
		return binding, err
	}
	binding = AdapterBinding{Schema: 1, Mode: "fixed_prebuilt_adapter", Manifest: manifest, BuilderResultsSHA256: resultHash, ArtifactManifestSHA256: manifestHash, InputsSHA256: inputsHash, BuilderSHA256: str(inputs, "builder_sha256")}
	return binding, nil
}
