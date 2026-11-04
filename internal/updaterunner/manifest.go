package updaterunner

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filegate.local/filegate/internal/av"
	"filegate.local/filegate/internal/hostvm"
	updatecontrol "filegate.local/filegate/internal/update"
	"golang.org/x/sys/unix"
)

const Profile = "filegate-official-update-v1"
const FixtureProfile = "filegate-update-fixture-v1"
const adoptedAdapter = "fefedac4e88ea3ee3402f2fc026a48941dc451f73175ffa6bc54bc8c20e7aa82"
const rawBytes int64 = 4 << 30

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type object = hostvm.Object

type Manifest struct {
	Schema          int                      `json:"schema"`
	Profile         string                   `json:"profile"`
	FixtureOnly     bool                     `json:"fixture_only"`
	LibrarySHA256   string                   `json:"library_sha256"`
	Workspace       string                   `json:"workspace"`
	Runner          string                   `json:"runner"`
	Helper          string                   `json:"helper"`
	Proof           string                   `json:"proof"`
	SHA256          map[string]string        `json:"sha256"`
	Engine          string                   `json:"engine"`
	Adapter         string                   `json:"adapter"`
	Origin          string                   `json:"origin"`
	Build           string                   `json:"build"`
	AdapterManifest string                   `json:"adapter_manifest"`
	ImageProfile    av.Revision              `json:"image_profile"`
	ImageTools      updatecontrol.ImageTools `json:"image_tools"`
	RequestSchema   int                      `json:"request_schema"`
}

type Request struct {
	Schema         int                           `json:"schema"`
	Profile        string                        `json:"profile"`
	FixtureOnly    bool                          `json:"fixture_only"`
	Attempt        updatecontrol.Attempt         `json:"attempt"`
	Restore        updatecontrol.RestoreRequest  `json:"restore"`
	LibrarySHA256  string                        `json:"library_sha256"`
	ManifestSHA256 string                        `json:"manifest_sha256"`
	JobID          string                        `json:"job_id"`
	AttemptID      string                        `json:"attempt_id"`
	ExpectedSHA256 string                        `json:"expected_sha256"`
	ByteSize       int64                         `json:"byte_size"`
	Definition     *updatecontrol.ScanDefinition `json:"definition_cache"`
}

type fileIdentity struct {
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Links      uint64 `json:"links"`
	Bytes      int64  `json:"bytes"`
	ModifiedNS int64  `json:"modified_ns"`
	ChangedNS  int64  `json:"changed_ns"`
}

func identity(s unix.Stat_t) fileIdentity {
	return fileIdentity{uint64(s.Dev), s.Ino, uint32(s.Mode), s.Uid, s.Gid, uint64(s.Nlink), s.Size, s.Mtim.Sec*1e9 + s.Mtim.Nsec, s.Ctim.Sec*1e9 + s.Ctim.Nsec}
}

func invalid(reason string) error { return errors.New(reason) }

func strict(body []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return invalid("UPDATE_JSON_INVALID")
	}
	return nil
}

func fields(value object, names string) bool {
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

func canonical(path string) bool {
	actual, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path && actual == path
}

func hash(body []byte) string {
	d := sha256.Sum256(body)
	return hex.EncodeToString(d[:])
}

func owned(path string, kind, mode uint32) (unix.Stat_t, error) {
	var s unix.Stat_t
	if err := unix.Lstat(path, &s); err != nil {
		return s, err
	}
	if uint32(s.Mode)&unix.S_IFMT != kind || uint32(s.Mode)&07777 != mode || s.Uid != uint32(os.Getuid()) {
		return s, invalid("UPDATE_OWNER_INVALID")
	}
	return s, nil
}

func sourcePin(path, expected string) (fileIdentity, error) {
	var empty fileIdentity
	if !canonical(path) || !digestPattern.MatchString(expected) {
		return empty, invalid("UPDATE_SOURCE_CHANGED")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || before.Size < 0 {
		return empty, invalid("UPDATE_SOURCE_CHANGED")
	}
	h := sha256.New()
	if n, err := io.CopyN(h, f, before.Size); err != nil || n != before.Size || hex.EncodeToString(h.Sum(nil)) != expected {
		return empty, invalid("UPDATE_SOURCE_CHANGED")
	}
	var extra [1]byte
	n, err := f.Read(extra[:])
	if n != 0 || err != io.EOF || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || identity(before) != identity(after) || identity(before) != identity(named) {
		return empty, invalid("UPDATE_SOURCE_CHANGED")
	}
	return identity(before), nil
}

func registration(path string, verifyPins bool) (Manifest, []byte, map[string]fileIdentity, error) {
	var m Manifest
	if !filepath.IsAbs(path) || filepath.Base(path) != "update-runtime.json" || !canonical(filepath.Dir(path)) {
		return m, nil, nil, invalid("UPDATE_REGISTRATION_REQUIRED")
	}
	if _, err := owned(filepath.Dir(path), unix.S_IFDIR, 0700); err != nil {
		return m, nil, nil, err
	}
	value, body, err := hostvm.Read(path, 1<<20)
	if err != nil || strict(body, &m) != nil || m.Schema != 2 || value["fixture_only"] != m.FixtureOnly || !digestPattern.MatchString(m.LibrarySHA256) || m.Runner != filepath.Join(m.Workspace, ".build/filegate-update") {
		return m, nil, nil, invalid("UPDATE_REGISTRATION_INVALID")
	}
	paths := []string{m.Workspace, m.Runner, m.Helper, m.Proof}
	if m.Profile == FixtureProfile && m.FixtureOnly {
		if !fields(value, "schema profile fixture_only library_sha256 workspace runner helper proof sha256") || len(m.SHA256) < 12 || len(m.SHA256) > 512 {
			return m, nil, nil, invalid("UPDATE_FIXTURE_REGISTRATION_INVALID")
		}
		paths = append(paths, filepath.Join(m.Workspace, "experiments/vm/evidence/build.json"))
	} else if m.Profile == Profile && !m.FixtureOnly {
		if !fields(value, "schema profile fixture_only library_sha256 workspace runner helper proof sha256 engine adapter origin build adapter_manifest image_profile image_tools request_schema") || m.RequestSchema != 2 || m.Engine != updatecontrol.Engine || m.Adapter != updatecontrol.Adapter || m.Origin != "https://database.clamav.net" || m.ImageProfile != av.CurrentRevision() || len(m.SHA256) < 16 || len(m.SHA256) > 512 || m.SHA256[m.AdapterManifest] != adoptedAdapter {
			return m, nil, nil, invalid("UPDATE_REGISTRATION_INVALID")
		}
		paths = append(paths, m.Build, m.AdapterManifest, m.ImageTools.Mke2fs, m.ImageTools.Debugfs, m.ImageTools.Mke2fsConfig)
	} else {
		return m, nil, nil, invalid("UPDATE_REGISTRATION_INVALID")
	}
	for _, name := range paths {
		if !canonical(name) || name != m.Workspace && !digestPattern.MatchString(m.SHA256[name]) {
			return m, nil, nil, invalid("UPDATE_PIN_MISSING")
		}
	}
	pins := map[string]fileIdentity{}
	if !verifyPins {
		return m, body, pins, nil
	}
	for name, expected := range m.SHA256 {
		pin, err := sourcePin(name, expected)
		if err != nil {
			return m, nil, nil, err
		}
		pins[name] = pin
	}
	if m.FixtureOnly {
		return m, body, pins, nil
	}
	adapterBody, err := readPinned(m.AdapterManifest, adoptedAdapter, 1<<20)
	var adapter struct {
		Entries []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"entries"`
	}
	if err != nil || hash(adapterBody) != adoptedAdapter || json.Unmarshal(adapterBody, &adapter) != nil {
		return m, nil, nil, invalid("UPDATE_ADOPTED_ADAPTER_CHANGED")
	}
	libraries := 0
	for _, e := range adapter.Entries {
		if strings.HasPrefix(e.Path, "lib/libfreshclam.so") && e.SHA256 != "" {
			if e.SHA256 != m.LibrarySHA256 {
				return m, nil, nil, invalid("UPDATE_LIBRARY_BINDING_INVALID")
			}
			libraries++
		}
	}
	if libraries != 1 {
		return m, nil, nil, invalid("UPDATE_LIBRARY_BINDING_INVALID")
	}
	return m, body, pins, nil
}

func readPinned(path, expected string, maximum int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > maximum {
		return nil, invalid("UPDATE_SOURCE_CHANGED")
	}
	body, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(body)) != before.Size || hash(body) != expected || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || identity(before) != identity(after) || identity(before) != identity(named) {
		return nil, invalid("UPDATE_SOURCE_CHANGED")
	}
	return body, nil
}

func load(manifestPath, requestPath string) (Manifest, Request, object, string, error) {
	return loadBound(manifestPath, requestPath, false, "")
}

func loadRecovery(manifestPath, requestPath, recoverySHA string) (Manifest, Request, object, string, error) {
	return loadBound(manifestPath, requestPath, true, recoverySHA)
}

func loadBound(manifestPath, requestPath string, recovering bool, recoverySHA string) (Manifest, Request, object, string, error) {
	m, manifestBody, _, err := registration(manifestPath, false)
	var r Request
	if err != nil {
		return m, r, nil, "", err
	}
	if m.FixtureOnly {
		m, manifestBody, _, err = registration(manifestPath, true)
		if err != nil {
			return m, r, nil, "", err
		}
	}
	value, body, err := hostvm.Read(requestPath, 16384)
	names := "schema profile fixture_only attempt restore library_sha256 manifest_sha256 job_id attempt_id expected_sha256 byte_size"
	schema := 1
	if !m.FixtureOnly {
		names += " definition_cache"
		schema = 2
	}
	if err != nil || !fields(value, names) || strict(body, &r) != nil || r.Schema != schema || r.Profile != m.Profile || value["fixture_only"] != m.FixtureOnly || r.FixtureOnly != m.FixtureOnly || r.ManifestSHA256 != hash(manifestBody) || r.LibrarySHA256 != m.LibrarySHA256 {
		return m, r, nil, "", invalid("UPDATE_REQUEST_BINDING_CHANGED")
	}
	executable, err := os.Executable()
	if err != nil {
		return m, r, nil, "", err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return m, r, nil, "", invalid("UPDATE_RUNNER_BINDING_CHANGED")
	}
	if executable != m.Runner || recoverySHA != "" {
		if !recovering || !digestPattern.MatchString(recoverySHA) {
			return m, r, nil, "", invalid("UPDATE_RECOVERY_RUNNER_BINDING_REQUIRED")
		}
		for _, pin := range []struct{ path, expected string }{{m.Runner, m.SHA256[m.Runner]}, {executable, recoverySHA}} {
			info, ownerErr := owned(pin.path, unix.S_IFREG, 0500)
			if ownerErr != nil || info.Nlink != 1 {
				return m, r, nil, "", invalid("UPDATE_RECOVERY_RUNNER_BINDING_CHANGED")
			}
			if _, err = sourcePin(pin.path, pin.expected); err != nil {
				return m, r, nil, "", err
			}
		}
		build, buildErr := buildinfo.ReadFile(executable)
		if buildErr != nil || build.Path != "filegate.local/filegate/cmd/filegate-update" || build.Main.Path != "filegate.local/filegate" {
			return m, r, nil, "", invalid("UPDATE_RECOVERY_GO_RUNNER_REQUIRED")
		}
	}
	a, restore := r.Attempt, r.Restore
	if !identifier.MatchString(r.AttemptID) || r.JobID != "update_"+r.AttemptID || a.ID != r.AttemptID || restore.UpdateID != r.AttemptID || restore.BaseGeneration != a.BaseGeneration ||
		a.DeadlineContinuousNS < a.Started.ContinuousNS || a.DeadlineContinuousNS-a.Started.ContinuousNS != 600_000_000_000 || a.ReservedBytes != 6<<30 || a.AdoptionApproved || !a.Started.Valid() {
		return m, r, nil, "", invalid("UPDATE_REQUEST_INVALID")
	}
	attempt, ok := value["attempt"].(map[string]any)
	if !ok || attempt["adoption_approved"] != false {
		return m, r, nil, "", invalid("UPDATE_REQUEST_INVALID")
	}
	payload, err := json.Marshal(restore)
	if err != nil || r.ExpectedSHA256 != hash(payload) || r.ByteSize != int64(len(payload)) {
		return m, r, nil, "", invalid("UPDATE_RESTORE_CHANGED")
	}
	if r.Definition != nil {
		cache, ok := value["definition_cache"].(map[string]any)
		if !ok || hostvm.ValidateDefinition(cache, filepath.Dir(filepath.Dir(filepath.Dir(requestPath))), true) != nil {
			return m, r, nil, "", invalid("UPDATE_CACHE_INVALID")
		}
	}
	return m, r, value, hash(body), nil
}
