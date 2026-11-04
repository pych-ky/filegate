package nativeproof

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

type object = map[string]any

func failure(code string) error { return errors.New(code) }

func canonical(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", failure("NATIVE_PROOF_ABSOLUTE_PATH_REQUIRED")
	}
	actual, err := filepath.EvalSymlinks(path)
	if err != nil || actual != path {
		return "", failure("NATIVE_PROOF_CANONICAL_PATH_REQUIRED")
	}
	return path, nil
}

func freshDirectory(path, repo string) error {
	parent, err := canonical(filepath.Dir(path))
	if err != nil || filepath.Join(parent, filepath.Base(path)) != path || path == repo || strings.HasPrefix(path, repo+string(filepath.Separator)) {
		return failure("NATIVE_PROOF_NEW_EXTERNAL_DIRECTORY_REQUIRED")
	}
	return os.Mkdir(path, 0700)
}

func sourcePins(repo string) (map[string]string, error) {
	pins := map[string]string{}
	add := func(name string) error {
		path := filepath.Join(repo, name)
		if _, err := canonical(path); err != nil {
			return err
		}
		var info unix.Stat_t
		if unix.Lstat(path, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&0022 != 0 || info.Size < 0 || info.Size > 1<<20 || len(pins) >= 512 {
			return failure("NATIVE_PROOF_SOURCE_INVALID")
		}
		sha, err := hostvm.HashFile(path)
		if err == nil {
			pins[filepath.ToSlash(name)] = sha
		}
		return err
	}
	for _, name := range []string{"go.mod", "go.sum", "experiments/host/integrated_watchdog.m"} {
		if err := add(name); err != nil {
			return nil, err
		}
	}
	for _, base := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(repo, base), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := entry.Name()
			if strings.HasPrefix(name, ".env") || name == "secrets" || name == "credentials" || name == "client.json" || name == ".git" {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return failure("NATIVE_PROOF_SOURCE_SYMLINK")
			}
			if entry.IsDir() {
				return nil
			}
			switch filepath.Ext(name) {
			case ".go", ".c", ".h", ".m", ".s", ".S":
				relative, err := filepath.Rel(repo, path)
				if err != nil {
					return err
				}
				return add(relative)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return pins, nil
}

func verifyPins(repo string, pins map[string]string) error {
	current, err := sourcePins(repo)
	if err != nil || !hostvm.Equal(current, pins) {
		return failure("NATIVE_PROOF_SOURCES_CHANGED")
	}
	return nil
}

func saveBytes(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := file.Write(body)
	if err == nil && n != len(body) {
		err = failure("NATIVE_PROOF_SHORT_WRITE")
	}
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return hostvm.SyncDirectory(filepath.Dir(path))
}

func first(events []object, name string) object {
	for _, event := range events {
		if hostvm.Str(event, "event") == name {
			return event
		}
	}
	return nil
}

func objects(values []object) []any {
	result := make([]any, len(values))
	for i := range values {
		result[i] = values[i]
	}
	return result
}
