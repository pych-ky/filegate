// Package updateworker transfers the fixed adapter's verified update candidates.
package updateworker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"filegate.local/filegate/internal/av"
	"filegate.local/filegate/internal/freshclamadapter"
	"golang.org/x/sys/unix"
)

const (
	adapterPath    = "/filegate-freshclam"
	libraryPath    = "/opt/filegate-av/lib/libfreshclam.so.3"
	workPath       = "/job/av-parent/official"
	cachePath      = "/.definitions"
	frameLimit     = 1 << 20
	candidateLimit = (1 << 30) - (64 << 20)
)

var invalid = errors.New("UPDATE_TRANSFER_INVALID")

func jsonValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return invalid
	}
	token, err := d.Token()
	if err != nil {
		return invalid
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return invalid
			}
			seen[name] = true
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return invalid
		}
	case json.Delim('['):
		for d.More() {
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return invalid
		}
	default:
		if _, bad := token.(json.Delim); bad {
			return invalid
		}
	}
	return nil
}

func object(body []byte) (map[string]json.RawMessage, error) {
	if len(body) > frameLimit || !utf8.Valid(body) {
		return nil, invalid
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if jsonValue(d, 0) != nil {
		return nil, invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, invalid
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(body, &value) != nil || value == nil {
		return nil, invalid
	}
	return value, nil
}

type channel struct {
	input  *bufio.Reader
	output io.Writer
}

func (c channel) exchange(value any) (map[string]json.RawMessage, error) {
	body, err := json.Marshal(value)
	if err != nil || len(body)+1 > frameLimit {
		return nil, invalid
	}
	body = append(body, '\n')
	if n, err := c.output.Write(body); err != nil || n != len(body) {
		return nil, invalid
	}
	var reply []byte
	for {
		part, err := c.input.ReadSlice('\n')
		if len(reply)+len(part) > 16384 {
			return nil, invalid
		}
		reply = append(reply, part...)
		if err == nil {
			return object(reply)
		}
		if err != bufio.ErrBufferFull {
			return nil, invalid
		}
	}
}

func event(value map[string]json.RawMessage, expected string) bool {
	var actual string
	return len(value) == 1 && json.Unmarshal(value["event"], &actual) == nil && actual == expected
}

func (c channel) accepted(value any) error {
	reply, err := c.exchange(value)
	if err != nil || !event(reply, "accepted") {
		return invalid
	}
	return nil
}

type budget struct {
	mu     sync.Mutex
	total  int
	stdout bytes.Buffer
	cancel context.CancelFunc
}

type capture struct {
	budget *budget
	stdout bool
}

func (w capture) Write(data []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	if len(data) > frameLimit-w.budget.total {
		w.budget.cancel()
		return 0, invalid
	}
	w.budget.total += len(data)
	if w.stdout {
		return w.budget.stdout.Write(data)
	}
	return len(data), nil
}

func adapter(request []byte, database, temporary string) (map[string]json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	b := &budget{cancel: cancel}
	command := exec.CommandContext(ctx, adapterPath, "--library", libraryPath, "--database-dir", database, "--temp-dir", temporary)
	command.Env = []string{"PATH=/bin:/usr/bin", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(request)
	command.Stdout, command.Stderr = capture{b, true}, capture{b, false}
	err := command.Run()
	var exit *exec.ExitError
	if ctx.Err() != nil || err != nil && !errors.As(err, &exit) {
		return nil, invalid
	}
	return object(b.stdout.Bytes())
}

type definition struct {
	Name     string `json:"definition"`
	Artifact struct {
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"artifact"`
}

func transfer(c channel, database string, row definition) error {
	var path string
	for _, suffix := range []string{".cvd", ".cld"} {
		name := filepath.Join(database, row.Name+suffix)
		if info, err := os.Lstat(name); err == nil && info.Mode().IsRegular() {
			if path != "" {
				return invalid
			}
			path = name
		}
	}
	if path == "" {
		return invalid
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return invalid
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size != row.Artifact.Bytes {
		return invalid
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, before.Size); err != nil || hex.EncodeToString(hash.Sum(nil)) != row.Artifact.SHA256 {
		return invalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return invalid
	}
	if err := c.accepted(map[string]any{"event": "update_candidate", "name": filepath.Base(path), "bytes": before.Size, "sha256": row.Artifact.SHA256}); err != nil {
		return err
	}
	hash.Reset()
	buffer := make([]byte, 49152)
	remaining := before.Size
	for remaining > 0 {
		n, err := io.ReadFull(file, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil {
			return invalid
		}
		hash.Write(buffer[:n])
		remaining -= int64(n)
		if err := c.accepted(map[string]any{"event": "update_chunk", "data": base64.StdEncoding.EncodeToString(buffer[:n])}); err != nil {
			return err
		}
	}
	var extra [1]byte
	n, readErr := file.Read(extra[:])
	if n != 0 || readErr != io.EOF || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || hex.EncodeToString(hash.Sum(nil)) != row.Artifact.SHA256 {
		return invalid
	}
	return c.accepted(map[string]any{"event": "update_candidate_end"})
}

func fields(body []byte, names ...string) (map[string]json.RawMessage, error) {
	value, err := object(body)
	if err != nil || len(value) != len(names) {
		return nil, invalid
	}
	for _, name := range names {
		if value[name] == nil || bytes.Equal(bytes.TrimSpace(value[name]), []byte("null")) {
			return nil, invalid
		}
	}
	return value, nil
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func sameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func cacheFile(directory int, name string, maximum int64) (*os.File, unix.Stat_t, error) {
	var info unix.Stat_t
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, info, invalid
	}
	file := os.NewFile(uintptr(fd), name)
	if unix.Fstat(fd, &info) != nil || info.Mode != unix.S_IFREG|0444 || info.Uid != 0 || info.Gid != 0 || info.Nlink != 1 || info.Size <= 0 || info.Size > maximum {
		file.Close()
		return nil, info, invalid
	}
	return file, info, nil
}

func cacheUnchanged(directory int, name string, file *os.File, before unix.Stat_t) bool {
	var after, named unix.Stat_t
	return unix.Fstat(int(file.Fd()), &after) == nil && unix.Fstatat(directory, name, &named, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		sameFile(before, after) && sameFile(after, named)
}

func copyCachedFile(source, target int, row av.Definition) error {
	file, before, err := cacheFile(source, row.Name, row.ByteSize)
	if err != nil {
		return err
	}
	defer file.Close()
	if before.Size != row.ByteSize {
		return invalid
	}
	fd, err := unix.Openat(target, row.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return invalid
	}
	output := os.NewFile(uintptr(fd), row.Name)
	defer output.Close()
	hash := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(output, hash), file, row.ByteSize); err != nil {
		return invalid
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if n != 0 || err != io.EOF || hex.EncodeToString(hash.Sum(nil)) != row.SHA256 || !cacheUnchanged(source, row.Name, file, before) || output.Sync() != nil {
		return invalid
	}
	return output.Close()
}

func copyCache(body []byte, generation int64, database string) error {
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return nil
	}
	cache, err := fields(body, "update_id", "generation", "confirmed", "manifest_sha256", "image_manifest_sha256", "image_path", "image", "profile", "binding")
	var current int64
	if err != nil || json.Unmarshal(cache["generation"], &current) != nil || current <= 0 || current > generation {
		return invalid
	}
	profileFields, err := fields(cache["profile"], "schema_version", "profile_id", "scanner_manifest_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only", "definitions")
	if err != nil {
		return invalid
	}
	if _, err = fields(cache["binding"], "profile_sha256", "scanner_manifest_sha256", "binary_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only"); err != nil {
		return invalid
	}
	var profile av.Profile
	var binding av.Binding
	var rawDefinitions []json.RawMessage
	if json.Unmarshal(cache["profile"], &profile) != nil || json.Unmarshal(cache["binding"], &binding) != nil ||
		json.Unmarshal(profileFields["definitions"], &rawDefinitions) != nil || len(rawDefinitions) != 3 ||
		profile.SchemaVersion != 1 || !av.KnownRevision(av.Revision{ProfileID: profile.ProfileID,
		ScannerManifestSHA256: profile.ScannerManifestSHA256, BinarySHA256: binding.BinarySHA256,
		ConfigurationSHA256: profile.ConfigurationSHA256, ObservationSHA256: profile.ObservationSHA256}) ||
		profile.FixtureDefinitionsOnly {
		return invalid
	}
	names, total, previous := map[string]bool{}, int64(0), ""
	for i, row := range profile.Definitions {
		if _, err := fields(rawDefinitions[i], "name", "sha256", "byte_size"); err != nil {
			return invalid
		}
		stem, suffix, ok := strings.Cut(row.Name, ".")
		if !ok || (stem != "main" && stem != "daily" && stem != "bytecode") || (suffix != "cvd" && suffix != "cld") || names[stem] ||
			row.Name <= previous || row.ByteSize <= 0 || row.ByteSize > candidateLimit-total || !validDigest(row.SHA256) {
			return invalid
		}
		names[stem], total, previous = true, total+row.ByteSize, row.Name
	}
	canonical, err := json.Marshal(profile)
	digest := sha256.Sum256(canonical)
	if err != nil || profile.DefinitionSetSHA256 != av.DefinitionDigest(profile.Definitions) || binding != (av.Binding{
		ProfileSHA256: hex.EncodeToString(digest[:]), ScannerManifestSHA256: profile.ScannerManifestSHA256,
		BinarySHA256: binding.BinarySHA256, ConfigurationSHA256: profile.ConfigurationSHA256,
		DefinitionSetSHA256: profile.DefinitionSetSHA256, ObservationSHA256: profile.ObservationSHA256}) {
		return invalid
	}
	fd, err := unix.Open(cachePath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return invalid
	}
	directory := os.NewFile(uintptr(fd), cachePath)
	defer directory.Close()
	entries, err := directory.Readdirnames(6)
	if err != nil && err != io.EOF || len(entries) != 5 {
		return invalid
	}
	allowed := map[string]bool{"product-profile.json": true, "lost+found": true}
	for _, row := range profile.Definitions {
		allowed[row.Name] = true
	}
	for _, name := range entries {
		if !allowed[name] {
			return invalid
		}
	}
	var lostInfo unix.Stat_t
	if unix.Fstatat(fd, "lost+found", &lostInfo, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		lostInfo.Mode&unix.S_IFMT != unix.S_IFDIR || lostInfo.Uid != 0 || lostInfo.Gid != 0 || lostInfo.Mode&0022 != 0 {
		return invalid
	}
	file, before, err := cacheFile(fd, "product-profile.json", 16384)
	if err != nil {
		return err
	}
	actual, err := io.ReadAll(io.LimitReader(file, 16385))
	unchanged := cacheUnchanged(fd, "product-profile.json", file, before)
	file.Close()
	if err != nil || !bytes.Equal(actual, canonical) || !unchanged {
		return invalid
	}
	target, err := unix.Open(database, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return invalid
	}
	defer unix.Close(target)
	for _, row := range profile.Definitions {
		if err := copyCachedFile(fd, target, row); err != nil {
			return err
		}
	}
	return unix.Fsync(target)
}

func Run(input io.Reader, output io.Writer) error {
	library, err := filepath.EvalSymlinks(libraryPath)
	if err != nil {
		return invalid
	}
	librarySHA, _, err := freshclamadapter.FileDigest(library)
	if err != nil {
		return invalid
	}
	c := channel{bufio.NewReader(input), output}
	reply, err := c.exchange(map[string]any{"event": "freshclam_control_ready", "library_sha256": librarySHA})
	var name string
	if err != nil || len(reply) != 3 || reply["definition_cache"] == nil || json.Unmarshal(reply["event"], &name) != nil || name != "freshclam_control_request" {
		return invalid
	}
	request := reply["request"]
	restore, err := freshclamadapter.ParseRequest(request, false)
	if err != nil {
		return invalid
	}
	database, temporary := filepath.Join(workPath, "database"), filepath.Join(workPath, "temporary")
	for _, path := range []string{workPath, database, temporary} {
		if os.Mkdir(path, 0700) != nil {
			return invalid
		}
	}
	if err := copyCache(reply["definition_cache"], restore.BaseGeneration, database); err != nil {
		return err
	}
	report, err := adapter(request, database, temporary)
	if err != nil {
		return invalid
	}
	reply, err = c.exchange(map[string]any{"event": "freshclam_control_final", "report": report})
	if err != nil || !event(reply, "freshclam_control_committed") {
		return invalid
	}
	if bytes.Equal(report["all_required_origin_confirmations"], []byte("true")) && bytes.Equal(report["all_required_artifacts_verified"], []byte("true")) {
		var rows []definition
		if json.Unmarshal(report["definitions"], &rows) != nil || len(rows) != 3 {
			return invalid
		}
		var rawRows []map[string]json.RawMessage
		if json.Unmarshal(report["definitions"], &rawRows) != nil {
			return invalid
		}
		seen := map[string]bool{}
		for i, row := range rows {
			artifact, err := object(rawRows[i]["artifact"])
			if err != nil || len(artifact) != 2 || artifact["bytes"] == nil || artifact["sha256"] == nil ||
				(row.Name != "main" && row.Name != "daily" && row.Name != "bytecode") || seen[row.Name] {
				return invalid
			}
			seen[row.Name] = true
		}
		var total int64
		for _, row := range rows {
			if row.Artifact.Bytes <= 0 || row.Artifact.Bytes > candidateLimit-total {
				return invalid
			}
			decoded, err := hex.DecodeString(row.Artifact.SHA256)
			if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != row.Artifact.SHA256 {
				return invalid
			}
			total += row.Artifact.Bytes
			if err := transfer(c, database, row); err != nil {
				return err
			}
		}
	}
	return c.accepted(map[string]any{"event": "update_done"})
}
