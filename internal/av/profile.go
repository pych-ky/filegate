package av

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const scannerManifestSHA256 = "47be9f07e65948d76d6cf46b38d2baf73cddcccd7562a7a3011e19af9d982b8c"
const scanner = "/usr/bin/clamscan"
const loader = "/lib/ld-musl-aarch64.so.1"

var invalid = errors.New("SCANNER_ERROR")
var hashMismatch = errors.New("INPUT_HASH_MISMATCH")
var objectID = regexp.MustCompile(`^object_[0-9]{6}$`)
var storedName = regexp.MustCompile(`^object_[0-9]{6}\.data$`)
var definitionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

var settings = map[string]string{
	"scan-archive": "yes", "scan-pe": "yes", "scan-elf": "yes", "scan-mail": "yes",
	"scan-html": "yes", "scan-ole2": "yes", "scan-pdf": "yes", "scan-swf": "yes",
	"scan-xmldocs": "yes", "scan-hwp3": "yes", "scan-onenote": "yes",
	"scan-image": "yes", "scan-image-fuzzy-hash": "yes", "normalize": "yes",
	"bytecode": "yes", "bytecode-unsigned": "no", "bytecode-mode": "Auto", "bytecode-timeout": "10000",
	"phishing-sigs": "yes", "phishing-scan-urls": "yes", "heuristic-alerts": "yes",
	"detect-structured": "no", "heuristic-scan-precedence": "no", "allmatch": "no",
	"alert-exceeds-max": "yes", "alert-encrypted": "yes", "alert-macros": "yes",
	"alert-broken": "yes", "alert-broken-media": "yes", "max-filesize": "262144000",
	"max-scansize": "1342177280", "max-files": "10000", "max-recursion": "17",
	"max-scantime": "120000", "max-embeddedpe": "41943040", "max-htmlnormalize": "41943040",
	"max-htmlnotags": "8388608", "max-scriptnormalize": "20971520", "max-ziptypercg": "1048576",
	"max-partitions": "50", "max-iconspe": "100", "max-rechwp3": "16",
	"pcre-match-limit": "100000", "pcre-recmatch-limit": "2000", "pcre-max-filesize": "104857600",
}

func hexDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

// DefinitionDigest binds a sorted set without depending on JSON object key order.
func DefinitionDigest(definitions []Definition) string {
	var encoded strings.Builder
	for _, definition := range definitions {
		encoded.WriteString(definition.Name)
		encoded.WriteByte(0)
		encoded.WriteString(definition.SHA256)
		encoded.WriteByte(0)
		body, _ := json.Marshal(definition.ByteSize)
		encoded.Write(body)
		encoded.WriteByte('\n')
	}
	return hexDigest([]byte(encoded.String()))
}

func trusted(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != 0 || before.Mode&022 != 0 || path == ProfilePath && before.Mode&0222 != 0 || before.Nlink != 1 || before.Size < 0 || before.Size > limit {
		return nil, invalid
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != before.Size || unix.Fstat(int(f.Fd()), &after) != nil || !sameMetadata(before, after) {
		return nil, invalid
	}
	return body, nil
}

func strictProfile(body []byte, profile *Profile) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 8 {
		return invalid
	}
	for _, name := range []string{"schema_version", "profile_id", "scanner_manifest_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only", "definitions"} {
		if len(fields[name]) == 0 || bytes.Equal(fields[name], []byte("null")) {
			return invalid
		}
	}
	var definitions []map[string]json.RawMessage
	if json.Unmarshal(fields["definitions"], &definitions) != nil {
		return invalid
	}
	for _, fields := range definitions {
		if len(fields) != 3 {
			return invalid
		}
		for _, name := range []string{"name", "sha256", "byte_size"} {
			if len(fields[name]) == 0 || bytes.Equal(fields[name], []byte("null")) {
				return invalid
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(body))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return invalid
		}
		t, err := d.Token()
		if err != nil {
			return invalid
		}
		if opening, ok := t.(json.Delim); ok {
			seen := map[string]bool{}
			for d.More() {
				if opening == '{' {
					key, e := d.Token()
					name, ok := key.(string)
					if e != nil || !ok || seen[name] {
						return invalid
					}
					seen[name] = true
				}
				if walk(depth+1) != nil {
					return invalid
				}
			}
			if _, err = d.Token(); err != nil {
				return invalid
			}
		}
		return nil
	}
	if walk(0) != nil {
		return invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid
	}
	d = json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(profile) != nil {
		return invalid
	}
	return nil
}

func loadProfile() (Profile, *Binding, error) {
	var profile Profile
	body, err := trusted(ProfilePath, 64<<10)
	if err != nil {
		return profile, nil, err
	}
	if strictProfile(body, &profile) != nil || profile.SchemaVersion != 1 || profile.ProfileID != ProfileID || profile.ScannerManifestSHA256 != scannerManifestSHA256 || profile.ConfigurationSHA256 != ConfigurationSHA256 || profile.ObservationSHA256 != ObservationSHA256 || len(profile.Definitions) == 0 || len(profile.Definitions) > 16 {
		return profile, nil, invalid
	}
	previous := ""
	var total int64
	for _, definition := range profile.Definitions {
		if !definitionName.MatchString(definition.Name) || definition.Name <= previous || !validDigest(definition.SHA256) || definition.ByteSize <= 0 || definition.ByteSize > 1<<30 {
			return profile, nil, invalid
		}
		previous = definition.Name
		total += definition.ByteSize
	}
	config, _ := json.Marshal(settings)
	if total > 2<<30 || profile.DefinitionSetSHA256 != DefinitionDigest(profile.Definitions) || hexDigest(config) != ConfigurationSHA256 {
		return profile, nil, invalid
	}
	return profile, &Binding{ProfileSHA256: hexDigest(body), ScannerManifestSHA256: scannerManifestSHA256, BinarySHA256: BinarySHA256, ConfigurationSHA256: ConfigurationSHA256, DefinitionSetSHA256: profile.DefinitionSetSHA256, ObservationSHA256: profile.ObservationSHA256, FixtureDefinitionsOnly: profile.FixtureDefinitionsOnly}, nil
}

type scannerManifest struct {
	Schema  int               `json:"schema"`
	Binary  string            `json:"binary"`
	Loader  string            `json:"loader"`
	Aliases map[string]string `json:"aliases"`
	Files   map[string]struct {
		ByteSize int64  `json:"bytes"`
		SHA256   string `json:"sha256"`
	} `json:"files"`
}

func hashFile(ctx context.Context, path string, size int64, expected string, rootOwned bool) error {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return invalid
	}
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || (rootOwned && (before.Uid != 0 || before.Gid != 0 || before.Mode&022 != 0)) {
		return invalid
	}
	if before.Size != size {
		return hashMismatch
	}
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var received int64
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, readErr := f.Read(buffer)
		received += int64(n)
		if received > size {
			return hashMismatch
		}
		h.Write(buffer[:n])
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return invalid
		}
	}
	if received != size || hex.EncodeToString(h.Sum(nil)) != expected {
		return hashMismatch
	}
	if unix.Fstat(int(f.Fd()), &after) != nil || !sameMetadata(before, after) {
		return invalid
	}
	var current unix.Stat_t
	if unix.Lstat(path, &current) != nil || current.Dev != before.Dev || current.Ino != before.Ino {
		return invalid
	}
	return nil
}

func sameMetadata(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode && before.Uid == after.Uid && before.Gid == after.Gid && before.Nlink == after.Nlink && before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

func verifyRuntime(ctx context.Context, profile Profile, binding *Binding) error {
	body, err := trusted(ProfilePath, 64<<10)
	if err != nil || hexDigest(body) != binding.ProfileSHA256 {
		return invalid
	}
	body, err = trusted(ManifestPath, 128<<10)
	if err != nil || hexDigest(body) != scannerManifestSHA256 {
		return invalid
	}
	var manifest scannerManifest
	if json.Unmarshal(body, &manifest) != nil || manifest.Schema != 1 || manifest.Binary != scanner || manifest.Loader != loader || len(manifest.Files) != 12 || manifest.Files[scanner].SHA256 != BinarySHA256 {
		return invalid
	}
	for alias, target := range manifest.Aliases {
		resolved, err := filepath.EvalSymlinks(alias)
		if err != nil || resolved != target {
			return invalid
		}
	}
	for path, file := range manifest.Files {
		if hashFile(ctx, path, file.ByteSize, file.SHA256, true) != nil {
			return invalid
		}
	}
	if _, err := os.Lstat("/etc/ld-musl-aarch64.path"); !errors.Is(err, os.ErrNotExist) {
		return invalid
	}
	var filesystem unix.Statfs_t
	if unix.Statfs("/.definitions", &filesystem) != nil || filesystem.Flags&1 == 0 {
		return invalid
	}
	for _, file := range profile.Definitions {
		if hashFile(ctx, "/.definitions/"+file.Name, file.ByteSize, file.SHA256, true) != nil {
			return invalid
		}
	}
	limited, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(limited, loader, "--list", scanner)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	var output bytes.Buffer
	command.Stdout = &limitedWriter{target: &output, remaining: 8192, cancel: cancel}
	var diagnostic bytes.Buffer
	command.Stderr = &limitedWriter{target: &diagnostic, remaining: 8192, cancel: cancel}
	command.WaitDelay = 2 * time.Second
	if command.Run() != nil || diagnostic.Len() != 0 {
		return invalid
	}
	paths := map[string]bool{}
	linePattern := regexp.MustCompile(`^\s*(?:[^\s/]+ => )?(/[^\s]+) \(0x[0-9a-f]+\)\s*$`)
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		match := linePattern.FindStringSubmatch(line)
		if match == nil {
			return invalid
		}
		path, err := filepath.EvalSymlinks(match[1])
		if err != nil {
			return invalid
		}
		if _, ok := manifest.Files[path]; !ok || path == scanner {
			return invalid
		}
		paths[path] = true
	}
	if len(paths) != len(manifest.Files)-1 {
		return invalid
	}
	return nil
}

func arguments(profile Profile, work string) []string {
	args := []string{"--stdout", "--no-summary", "--tempdir=" + work, "--file-list=" + work + "/inputs.list"}
	for _, file := range profile.Definitions {
		args = append(args, "--database=/.definitions/"+file.Name)
	}
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--"+key+"="+settings[key])
	}
	return args
}

type limitedWriter struct {
	target    io.Writer
	remaining int
	cancel    context.CancelFunc
}

func (w *limitedWriter) Write(body []byte) (int, error) {
	if len(body) > w.remaining {
		w.cancel()
		return 0, invalid
	}
	n, err := w.target.Write(body)
	w.remaining -= n
	return n, err
}
