package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const fixtureRuntimeProfile = "filegate-update-fixture-v1"

type RuntimeManifest struct {
	Schema        int               `json:"schema"`
	Profile       string            `json:"profile"`
	FixtureOnly   bool              `json:"fixture_only"`
	LibrarySHA256 string            `json:"library_sha256"`
	Workspace     string            `json:"workspace"`
	LegacyPython  string            `json:"python,omitempty"`
	Runner        string            `json:"runner"`
	Helper        string            `json:"helper"`
	Proof         string            `json:"proof"`
	SHA256        map[string]string `json:"sha256"`
}

func runtimeJSON(data []byte, target any) error {
	if _, err := decode(data, 4<<20); err != nil {
		return Invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return Invalid
	}
	return nil
}

func runtimeRead(path string, maximum int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Getuid()) || before.Mode&0777 != 0600 || before.Size > maximum {
		return nil, Invalid
	}
	data, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || unix.Fstat(fd, &after) != nil || int64(len(data)) != before.Size || before.Size != after.Size || before.Mtim != after.Mtim {
		return nil, Invalid
	}
	return data, nil
}

func runtimeSyncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func runtimeWrite(path string, value any) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(encoded(value))
	if err == nil {
		err = runtimeSyncFile(f)
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return runtimeSyncDirectory(filepath.Dir(path))
}

func runtimeFileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ReadRuntimeManifest(path string) (RuntimeManifest, error) {
	var m RuntimeManifest
	body, err := runtimeRead(path, 1<<20)
	if err != nil || runtimeJSON(body, &m) != nil || m.Schema != 2 || m.LegacyPython != "" || m.Profile != fixtureRuntimeProfile || !m.FixtureOnly || !digestPattern.MatchString(m.LibrarySHA256) {
		return m, Invalid
	}
	var fields map[string]json.RawMessage
	if runtimeJSON(body, &fields) != nil || fields["python"] != nil {
		return m, Invalid
	}
	if m.Runner != filepath.Join(m.Workspace, ".build/filegate-update") || len(m.SHA256) < 12 || len(m.SHA256) > 512 {
		return m, Invalid
	}
	for _, path := range []string{m.Workspace, m.Runner, m.Helper, m.Proof} {
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil || !filepath.IsAbs(path) || canonical != path || path != filepath.Clean(path) {
			return m, Invalid
		}
		if path != m.Workspace && !digestPattern.MatchString(m.SHA256[path]) {
			return m, Invalid
		}
	}
	for path, expected := range m.SHA256 {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || !digestPattern.MatchString(expected) {
			return m, Invalid
		}
		actual, err := runtimeFileSHA(path)
		if err != nil || actual != expected {
			return m, Invalid
		}
	}
	info, err := os.Lstat(m.Runner)
	if err != nil || info.Mode().Perm()&0111 == 0 {
		return m, Invalid
	}
	return m, nil
}
