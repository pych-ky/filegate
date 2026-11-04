package buildtools

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

func dependencyName(value string) string {
	parts := strings.FieldsFunc(value, func(c rune) bool { return c == '=' || c == '<' || c == '>' || c == '~' })
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func compilerSubset(ctx context.Context, directory string, rows []any) ([]string, map[string]any, error) {
	return packageSubset(ctx, directory, rows, []string{"gcc", "musl-dev"})
}

func packageSubset(ctx context.Context, directory string, rows []any, roots []string) ([]string, map[string]any, error) {
	type metadata struct {
		archive, version, controlSHA string
		depends, provides            []string
	}
	all := map[string]metadata{}
	providers := map[string][]string{}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, nil, errors.New("invalid pinned package row")
		}
		name, version := str(row, "name"), str(row, "version")
		archive := name + "-" + version + ".apk"
		body, _, err := command(ctx, "", nil, "bsdtar", "-xOf", filepath.Join(directory, archive), ".PKGINFO")
		if err != nil || len(body) > 128<<10 {
			return nil, nil, errors.New("pinned compiler package metadata unavailable")
		}
		entry := metadata{archive: archive, version: version, controlSHA: digest(body)}
		gotName, gotVersion, architecture := "", "", ""
		for _, line := range strings.Split(string(body), "\n") {
			key, value, exists := strings.Cut(line, " = ")
			if !exists {
				continue
			}
			switch key {
			case "pkgname":
				gotName = value
			case "pkgver":
				gotVersion = value
			case "arch":
				architecture = value
			case "depend":
				if value == "" {
					return nil, nil, errors.New("empty compiler dependency")
				}
				entry.depends = append(entry.depends, value)
			case "provides":
				entry.provides = append(entry.provides, value)
			}
		}
		if gotName != name || gotVersion != version || (architecture != "aarch64" && architecture != "noarch") || all[name].archive != "" {
			return nil, nil, errors.New("pinned compiler package identity mismatch")
		}
		all[name] = entry
		for _, provide := range append([]string{name}, entry.provides...) {
			key := dependencyName(provide)
			if key == "" {
				return nil, nil, errors.New("empty compiler provider")
			}
			found := false
			for _, existing := range providers[key] {
				found = found || existing == name
			}
			if !found {
				providers[key] = append(providers[key], name)
			}
		}
	}
	selected := map[string]bool{}
	queue := append([]string{}, roots...)
	for len(queue) != 0 {
		dependency := queue[0]
		queue = queue[1:]
		if strings.HasPrefix(dependency, "!") {
			continue
		}
		name := dependencyName(dependency)
		if all[name].archive == "" {
			candidates := providers[name]
			if len(candidates) != 1 {
				return nil, nil, fmt.Errorf("compiler dependency has no unique pinned provider: %s", name)
			}
			name = candidates[0]
		}
		if pythonPath(name) || strings.HasPrefix(name, "py3-") {
			return nil, nil, errors.New("Python compiler dependency rejected")
		}
		if selected[name] {
			continue
		}
		selected[name] = true
		queue = append(queue, all[name].depends...)
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	archives := []string{}
	proof := map[string]any{}
	for _, name := range names {
		entry := all[name]
		archives = append(archives, entry.archive)
		proof[name] = map[string]any{"version": entry.version, "archive": entry.archive, "control_sha256": entry.controlSHA, "depends": entry.depends, "provides": entry.provides}
	}
	return archives, map[string]any{"roots": roots, "packages": proof, "selected_count": len(names), "unselected_count": len(rows) - len(names), "python_dependency": false, "signature_verification": "required_by_guest_apk_add_no_network"}, nil
}

func diagnosticCompilerSubset(ctx context.Context, directory string, rows []any) ([]string, map[string]any, error) {
	return packageSubset(ctx, directory, rows, []string{"gcc", "musl-dev", "libxml2-dev"})
}
