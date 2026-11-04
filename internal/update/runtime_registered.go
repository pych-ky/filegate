package update

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filegate.local/filegate/internal/av"
	"golang.org/x/sys/unix"
)

const RuntimeRegistration = "update-runtime.json"
const normalRuntimeProfile = "filegate-official-update-v1"
const adoptedAdapterManifest = "fefedac4e88ea3ee3402f2fc026a48941dc451f73175ffa6bc54bc8c20e7aa82"

type registeredManifest struct {
	RuntimeManifest
	RequestSchema   int          `json:"request_schema,omitempty"`
	Engine          string       `json:"engine"`
	Adapter         string       `json:"adapter"`
	Origin          string       `json:"origin"`
	Build           string       `json:"build"`
	AdapterManifest string       `json:"adapter_manifest"`
	ImageProfile    ImageProfile `json:"image_profile"`
	ImageTools      ImageTools   `json:"image_tools"`
}

// Runtime can only be obtained from the private broker registration.
type Runtime struct {
	manifest registeredManifest
	digest   string
	path     string
	pins     map[string]runtimePinIdentity
}

type runtimePinIdentity struct {
	device, inode, links uint64
	mode, uid, gid       uint32
	size                 int64
	modified, changed    unix.Timespec
}

func pinIdentity(info unix.Stat_t) runtimePinIdentity {
	return runtimePinIdentity{uint64(info.Dev), info.Ino, uint64(info.Nlink), uint32(info.Mode), info.Uid, info.Gid,
		info.Size, info.Mtim, info.Ctim}
}

func registeredPin(path, expected string) (runtimePinIdentity, error) {
	var empty runtimePinIdentity
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return empty, Invalid
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 {
		return empty, Invalid
	}
	hash := sha256.New()
	if _, err = io.CopyN(hash, file, before.Size); err != nil || hex.EncodeToString(hash.Sum(nil)) != expected ||
		unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || pinIdentity(before) != pinIdentity(after) || pinIdentity(before) != pinIdentity(named) {
		return empty, Invalid
	}
	return pinIdentity(before), nil
}

func readRegistration(path string) ([]byte, error) {
	canonical, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || !filepath.IsAbs(path) || filepath.Base(path) != RuntimeRegistration || canonical != filepath.Dir(path) {
		return nil, Invalid
	}
	var parent unix.Stat_t
	if err = unix.Lstat(filepath.Dir(path), &parent); err != nil {
		return nil, err
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != uint32(os.Getuid()) || parent.Mode&0777 != 0700 {
		return nil, Invalid
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Getuid()) || before.Mode&0777 != 0600 || before.Nlink != 1 || before.Size <= 0 || before.Size > 1<<20 {
		return nil, Invalid
	}
	data := make([]byte, before.Size)
	if n, err := f.ReadAt(data, 0); err != nil || n != len(data) || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || pinIdentity(before) != pinIdentity(after) || pinIdentity(before) != pinIdentity(named) {
		return nil, Invalid
	}
	return data, nil
}

func RegisteredRuntime(dataDirectory string) (*Runtime, error) {
	if err := CheckRuntimeTransition(dataDirectory); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDirectory, RuntimeRegistration)
	body, err := readRegistration(path)
	if err != nil {
		return nil, err
	}
	return registeredRuntime(path, body, false)
}

func registeredRuntime(path string, body []byte, previous bool) (*Runtime, error) {
	var m registeredManifest
	var fields map[string]json.RawMessage
	if runtimeJSON(body, &fields) != nil {
		return nil, Invalid
	}
	request, hasRequest := fields["request_schema"]
	if hasRequest && !bytes.Equal(request, []byte("2")) || !hasRequest && !previous {
		return nil, Invalid
	}
	if runtimeJSON(body, &m) != nil {
		return nil, Invalid
	}
	legacy := previous && m.Schema == 1
	maximumPins := 512
	if legacy {
		maximumPins = 160
	}
	_, hasPython := fields["python"]
	validRunner := m.Schema == 2 && !hasPython && m.LegacyPython == "" && m.Runner == filepath.Join(m.Workspace, ".build/filegate-update") ||
		legacy && m.LegacyPython != "" && m.Runner == filepath.Join(m.Workspace, "experiments/productupdate/normal_run.py")
	if !validRunner || m.Profile != normalRuntimeProfile || m.FixtureOnly ||
		m.Engine != Engine || m.Adapter != Adapter || m.Origin != "https://database.clamav.net" || !digestPattern.MatchString(m.LibrarySHA256) ||
		(m.RequestSchema != 2 && (!previous || m.RequestSchema != 0)) ||
		(!validImageProfile(m.ImageProfile) && (!previous || !av.KnownRevision(m.ImageProfile))) ||
		len(m.SHA256) < 16 || len(m.SHA256) > maximumPins {
		return nil, Invalid
	}
	paths := []string{m.Workspace, m.Runner, m.Helper, m.Proof, m.Build, m.AdapterManifest, m.ImageTools.Mke2fs, m.ImageTools.Debugfs, m.ImageTools.Mke2fsConfig}
	if legacy {
		paths = append(paths, m.LegacyPython)
	}
	for _, path := range paths {
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || canonical != path || path != m.Workspace && !digestPattern.MatchString(m.SHA256[path]) {
			return nil, Invalid
		}
	}
	pins := make(map[string]runtimePinIdentity, len(m.SHA256))
	for path, expected := range m.SHA256 {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') || !digestPattern.MatchString(expected) {
			return nil, Invalid
		}
		identity, err := registeredPin(path, expected)
		if err != nil {
			return nil, Invalid
		}
		pins[path] = identity
	}
	if !legacy && pins[m.Runner].mode&0111 == 0 {
		return nil, Invalid
	}
	if m.SHA256[m.AdapterManifest] != adoptedAdapterManifest {
		return nil, Invalid
	}
	adapterBytes, err := os.ReadFile(m.AdapterManifest)
	var adapter struct {
		Entries []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"entries"`
	}
	if err != nil || sha256Text(adapterBytes) != adoptedAdapterManifest || json.Unmarshal(adapterBytes, &adapter) != nil {
		return nil, Invalid
	}
	libraries := 0
	for _, entry := range adapter.Entries {
		if strings.HasPrefix(entry.Path, "lib/libfreshclam.so") && entry.SHA256 != "" {
			if entry.SHA256 != m.LibrarySHA256 {
				return nil, Invalid
			}
			libraries++
		}
	}
	if libraries != 1 {
		return nil, Invalid
	}
	var build struct {
		Schema              int                         `json:"schema"`
		RequestSchema       int                         `json:"request_schema,omitempty"`
		Profile             string                      `json:"profile"`
		FixtureOnly         bool                        `json:"fixture_only"`
		LibrarySHA256       string                      `json:"library_sha256"`
		AdapterSHA256       string                      `json:"adapter_manifest_sha256"`
		ImageProfile        ImageProfile                `json:"image_profile"`
		ImageTools          ImageTools                  `json:"image_tools"`
		SourcesSHA256       map[string]string           `json:"sources_sha256"`
		ArtifactsSHA256     map[string]string           `json:"artifacts_sha256"`
		Implementation      string                      `json:"implementation,omitempty"`
		PythonDependency    *bool                       `json:"python_dependency,omitempty"`
		PythonRuntime       *runtimePythonInventory     `json:"python_runtime,omitempty"`
		InitramfsInspection *runtimeInitramfsInspection `json:"initramfs_inspection,omitempty"`
	}
	data, err := runtimeRead(m.Build, 1<<20)
	var buildFields map[string]json.RawMessage
	if err != nil || runtimeJSON(data, &buildFields) != nil || !bytes.Equal(fields["request_schema"], buildFields["request_schema"]) {
		return nil, Invalid
	}
	if err != nil || runtimeJSON(data, &build) != nil || build.Schema != m.Schema || build.Profile != normalRuntimeProfile || build.FixtureOnly ||
		build.RequestSchema != m.RequestSchema || build.LibrarySHA256 != m.LibrarySHA256 || build.AdapterSHA256 != m.SHA256[m.AdapterManifest] || build.ImageProfile != m.ImageProfile || build.ImageTools != m.ImageTools || len(build.SourcesSHA256) < 10 || len(build.ArtifactsSHA256) < 4 {
		return nil, Invalid
	}
	if legacy {
		if build.Implementation != "" || build.PythonDependency != nil || build.PythonRuntime != nil || build.InitramfsInspection != nil {
			return nil, Invalid
		}
	} else if build.Implementation != "go" || build.PythonDependency == nil || *build.PythonDependency || !build.PythonRuntime.valid() || !build.InitramfsInspection.valid() {
		return nil, Invalid
	}
	for _, pins := range []map[string]string{build.SourcesSHA256, build.ArtifactsSHA256} {
		for path, digest := range pins {
			if m.SHA256[path] != digest || !digestPattern.MatchString(digest) {
				return nil, Invalid
			}
		}
	}
	return &Runtime{manifest: m, digest: sha256Text(body), path: path, pins: pins}, nil
}

func (r *Runtime) LibrarySHA256() string { return r.manifest.LibrarySHA256 }

func (r *Runtime) current() error {
	if err := CheckRuntimeTransition(filepath.Dir(r.path)); err != nil {
		return err
	}
	body, err := readRegistration(r.path)
	if err != nil || sha256Text(body) != r.digest {
		return Invalid
	}
	for path, expected := range r.pins {
		canonical, err := filepath.EvalSymlinks(path)
		var actual unix.Stat_t
		if err != nil || canonical != path || unix.Lstat(path, &actual) != nil || pinIdentity(actual) != expected {
			return Invalid
		}
	}
	return nil
}

func (s *Store) BeginRuntime(r *Runtime, directory, id string, now Clock) (Control, Attempt, error) {
	if r == nil || r.current() != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !identifier.MatchString(id) {
		return Control{}, Attempt{}, Invalid
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		return Control{}, Attempt{}, Invalid
	}
	return s.begin(id, now, func(tx *sql.Tx, c Control) error {
		if c.Binding.FixtureOnly || c.Binding.LibrarySHA256 != r.manifest.LibrarySHA256 {
			return fmt.Errorf("registered update binding mismatch")
		}
		if err := snapshotDefinitionCache(tx, id, c); err != nil {
			return errors.New("UPDATE_CACHE_INVALID")
		}
		_, err := tx.Exec("INSERT INTO update_runtime(update_id,directory,manifest_sha256,state) VALUES(?,?,?,'RESERVED')", id, directory, r.digest)
		return err
	})
}
