package buildtools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type imageEntry struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

func pythonPath(name string) bool {
	for _, part := range strings.Split(strings.ToLower(name), "/") {
		if strings.Contains(part, "python") || strings.HasPrefix(part, "py3-") || strings.HasPrefix(part, "pydoc") || strings.HasPrefix(part, "idle3") || strings.HasPrefix(part, "2to3") {
			return true
		}
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".py", ".pyc", ".pyo", ".pyw", ".pyz", ".whl":
		return true
	}
	return false
}

func trimCompilerImage(ctx context.Context, debugfs, image, staging, receiptPath, verification string) (map[string]any, error) {
	receipt, err := object(receiptPath)
	if err != nil {
		return nil, err
	}
	closure, err := nested(receipt, "compiler_dependency_closure")
	if err != nil || number(closure, "selected_count") != 16 || closure["python_dependency"] != false {
		return nil, errors.New("Go compiler package closure required")
	}
	packages, err := nested(closure, "packages")
	if err != nil || len(packages) != 16 {
		return nil, errors.New("fixed compiler package inventory required")
	}
	inputs, err := nested(receipt, "input_pins_sha256")
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(verification, "experiments/av/evidence/packages-build.json")
	manifestSHA, err := SHA(manifestPath)
	if err != nil || inputs[manifestPath] != manifestSHA {
		return nil, errors.New("fixed diagnostic package manifest pin required")
	}
	manifest, err := object(manifestPath)
	if err != nil {
		return nil, err
	}
	rows, ok := manifest["packages"].([]any)
	if !ok || len(rows) != 109 {
		return nil, errors.New("fixed diagnostic package inventory required")
	}
	packageDirectory := filepath.Join(verification, "experiments/av/cache/packages-build")
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid diagnostic package row")
		}
		archive := str(row, "name") + "-" + str(row, "version") + ".apk"
		if filepath.Base(archive) != archive {
			return nil, errors.New("invalid diagnostic package archive")
		}
		input := filepath.Join(packageDirectory, archive)
		actual, err := SHA(input)
		if err != nil || !validSHA(actual) || inputs[input] != actual || str(row, "sha256") != actual {
			return nil, errors.New("fixed diagnostic package digest mismatch")
		}
	}
	_, diagnosticClosure, err := diagnosticCompilerSubset(ctx, packageDirectory, rows)
	if err != nil {
		return nil, err
	}
	diagnosticPackages, err := nested(diagnosticClosure, "packages")
	if err != nil || len(diagnosticPackages) <= len(packages) {
		return nil, errors.New("diagnostic compiler dependency closure incomplete")
	}
	for name, value := range packages {
		oldBody, err := jsonBytes(value)
		if err != nil {
			return nil, err
		}
		newBody, err := jsonBytes(diagnosticPackages[name])
		if err != nil || string(oldBody) != string(newBody) {
			return nil, errors.New("FreshClam and diagnostic compiler inputs differ")
		}
	}
	wanted := map[string]string{}
	for name, value := range diagnosticPackages {
		row, ok := value.(map[string]any)
		archive := str(row, "archive")
		if !ok || pythonPath(name) || pythonPath(archive) || archive != name+"-"+str(row, "version")+".apk" || filepath.Base(archive) != archive {
			return nil, errors.New("invalid fixed compiler package")
		}
		for input, digest := range inputs {
			if filepath.Base(input) != archive {
				continue
			}
			expected, ok := digest.(string)
			if !ok || !validSHA(expected) || wanted["/build-packages/"+archive] != "" {
				return nil, errors.New("ambiguous fixed compiler package pin")
			}
			wanted["/build-packages/"+archive] = expected
		}
	}
	if len(wanted) != len(diagnosticPackages) {
		return nil, errors.New("compiler package input pins incomplete")
	}
	before, err := imageInventory(ctx, debugfs, image)
	if err != nil {
		return nil, err
	}
	removed, found := []string{}, map[string]bool{}
	for _, entry := range before {
		if path.Dir(entry.Path) != "/build-packages" {
			continue
		}
		if entry.Mode&0170000 != 0100000 || path.Ext(entry.Path) != ".apk" {
			return nil, errors.New("unexpected build package inode")
		}
		if wanted[entry.Path] != "" {
			found[entry.Path] = true
			continue
		}
		quoted, err := quoteDebugfs(entry.Path)
		if err != nil {
			return nil, err
		}
		if _, _, err = command(ctx, "", nil, debugfs, "-w", "-R", "rm "+quoted, image); err != nil {
			return nil, err
		}
		removed = append(removed, entry.Path)
	}
	if len(found) != len(wanted) {
		return nil, errors.New("fixed compiler package missing from baseline image")
	}
	selected := make([]string, 0, len(wanted))
	for name := range wanted {
		selected = append(selected, name)
	}
	sort.Strings(selected)
	normalized := []string{}
	for i, name := range selected {
		quoted, _ := quoteDebugfs(name)
		metadata, _, err := command(ctx, "", nil, debugfs, "-R", "stat "+quoted, image)
		if err != nil || !statMode(string(metadata), "0444") && !statMode(string(metadata), "0644") {
			return nil, errors.New("fixed compiler package baseline ownership mismatch")
		}
		if statMode(string(metadata), "0644") {
			if _, _, err = command(ctx, "", nil, debugfs, "-w", "-R", "set_inode_field "+quoted+" mode 0100444", image); err != nil {
				return nil, err
			}
			normalized = append(normalized, name)
		}
		readback := filepath.Join(staging, fmt.Sprintf("compiler-package-%d.apk", i))
		quotedReadback, err := quoteDebugfs(readback)
		if err != nil {
			return nil, err
		}
		if _, _, err = command(ctx, "", nil, debugfs, "-R", "dump "+quoted+" "+quotedReadback, image); err != nil {
			return nil, err
		}
		actual, err := SHA(readback)
		if err != nil || actual != wanted[name] {
			return nil, errors.New("fixed compiler package image readback mismatch")
		}
		if err = os.Remove(readback); err != nil {
			return nil, err
		}
		stat, _, err := command(ctx, "", nil, debugfs, "-R", "stat "+quoted, image)
		if err != nil || !statMode(string(stat), "0444") {
			return nil, errors.New("fixed compiler package image ownership mismatch")
		}
	}
	after, err := imageInventory(ctx, debugfs, image)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, entry := range after {
		if path.Dir(entry.Path) == "/build-packages" {
			if wanted[entry.Path] == "" || entry.Mode&0170000 != 0100000 {
				return nil, errors.New("unexpected compiler package remains in image")
			}
			count++
		}
	}
	if count != len(wanted) {
		return nil, errors.New("fixed compiler package subset incomplete")
	}
	return map[string]any{"roots": diagnosticClosure["roots"], "package_count": count, "package_sha256": wanted, "removed_paths": removed,
		"dependency_closure": diagnosticClosure, "freshclam_compiler_dependency_closure": closure, "fixed_manifest_sha256": manifestSHA,
		"scope": "guest_AV_C_observers_and_dictionary_probe", "signature_verification": "required_by_guest_apk_add_no_network", "all_root_0444": true, "all_bytes_read_back": true,
		"metadata_normalization": map[string]any{"input_required_uid": 0, "input_required_gid": 0, "input_permitted_modes": []string{"0444", "0644"}, "normalized_0644_to_0444_paths": normalized, "method": "metadata_only_on_new_derived_image_before_content_and_inode_readback", "baseline_image_changed": false}}, nil
}

func imageInventory(ctx context.Context, debugfs, image string) ([]imageEntry, error) {
	records, err := imageRecords(ctx, debugfs, image)
	if err != nil {
		return nil, err
	}
	entries := []imageEntry{}
	for _, record := range records {
		if record.Path != "/" {
			entries = append(entries, imageEntry{Path: record.Path, Mode: record.Mode})
		}
	}
	return entries, nil
}

// imageRecord is one directory entry (and the root itself as "/") with the inode, owner and size that debugfs ls -p reports; directories have no size.
type imageRecord struct {
	Path  string
	Mode  uint32
	UID   string
	GID   string
	Size  string
	Inode string
}

func imageRecords(ctx context.Context, debugfs, image string) ([]imageRecord, error) {
	queue := []string{"/"}
	seen := map[string]bool{}
	entries := []imageRecord{}
	for len(queue) != 0 {
		directory := queue[0]
		queue = queue[1:]
		if seen[directory] {
			return nil, errors.New("duplicate image directory")
		}
		seen[directory] = true
		quoted, err := quoteDebugfs(directory)
		if err != nil {
			return nil, err
		}
		out, diagnostic, err := command(ctx, "", nil, debugfs, "-R", "ls -p "+quoted, image)
		if err != nil || strings.Contains(string(diagnostic), "File not found") {
			return nil, fmt.Errorf("image inventory failed: %s", directory)
		}
		self, parent := false, false
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Split(line, "/")
			if len(fields) != 8 || fields[0] != "" || fields[7] != "" {
				return nil, errors.New("unexpected debugfs inventory record")
			}
			inode, e := strconv.ParseUint(fields[1], 10, 64)
			if e != nil {
				return nil, e
			}
			if inode != 0 && fields[5] == "." {
				self = true
				if directory == "/" {
					mode, e := strconv.ParseUint(fields[2], 8, 32)
					if e != nil || mode&0170000 != 0040000 {
						return nil, errors.New("invalid image root record")
					}
					entries = append(entries, imageRecord{Path: "/", Mode: uint32(mode), UID: fields[3], GID: fields[4], Size: fields[6], Inode: fields[1]})
				}
			}
			if inode != 0 && fields[5] == ".." {
				parent = true
			}
			if inode == 0 || fields[5] == "." || fields[5] == ".." {
				continue
			}
			mode, e := strconv.ParseUint(fields[2], 8, 32)
			if e != nil || fields[5] == "" || strings.ContainsAny(fields[5], "\x00\n\r") {
				return nil, errors.New("invalid image inode record")
			}
			name := path.Join(directory, fields[5])
			if len(name) > 4096 || strings.Count(name, "/") > 128 || len(entries) >= 100000 {
				return nil, errors.New("image inventory bounds exceeded")
			}
			entries = append(entries, imageRecord{Path: name, Mode: uint32(mode), UID: fields[3], GID: fields[4], Size: fields[6], Inode: fields[1]})
			if mode&0170000 == 0040000 {
				queue = append(queue, name)
			}
		}
		if !self || !parent {
			return nil, errors.New("image directory inventory incomplete")
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func removeImagePython(ctx context.Context, debugfs, image string) (map[string]any, error) {
	before, err := imageInventory(ctx, debugfs, image)
	if err != nil {
		return nil, err
	}
	removed := []string{}
	selected := []imageEntry{}
	for _, entry := range before {
		if pythonPath(entry.Path) {
			selected = append(selected, entry)
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		a, b := strings.Count(selected[i].Path, "/"), strings.Count(selected[j].Path, "/")
		if a != b {
			return a > b
		}
		return selected[i].Path > selected[j].Path
	})
	for _, entry := range selected {
		quoted, err := quoteDebugfs(entry.Path)
		if err != nil {
			return nil, err
		}
		action := "rm "
		if entry.Mode&0170000 == 0040000 {
			action = "rmdir "
		}
		if _, _, err = command(ctx, "", nil, debugfs, "-w", "-R", action+quoted, image); err != nil {
			return nil, err
		}
		removed = append(removed, entry.Path)
	}
	after, err := imageInventory(ctx, debugfs, image)
	if err != nil {
		return nil, err
	}
	for _, entry := range after {
		if pythonPath(entry.Path) {
			return nil, fmt.Errorf("Python runtime artifact remains in image: %s", entry.Path)
		}
	}
	encoded, err := jsonBytes(after)
	if err != nil {
		return nil, err
	}
	sort.Strings(removed)
	return map[string]any{"method": "bounded_recursive_debugfs_inode_inventory", "removed_paths": removed, "remaining_python_paths": []string{}, "inspected_inodes": len(after), "inventory_sha256": digest(encoded)}, nil
}
