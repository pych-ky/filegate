package updatebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"filegate.local/filegate/internal/av"
	"golang.org/x/sys/unix"
)

func hashFile(file *os.File, size int64) (string, error) {
	h := sha256.New()
	if _, err := io.CopyN(h, file, size); err != nil {
		return "", err
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || err != io.EOF {
		return "", errInvalid
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func pinned(path string, expected any, limit int64) (unix.Stat_t, error) {
	if !canonical(path) || !validDigest(expected) {
		return unix.Stat_t{}, errInvalid
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return unix.Stat_t{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, err := fileStat(f)
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size <= 0 || before.Size > limit {
		return before, errInvalid
	}
	actual, err := hashFile(f, before.Size)
	after, e1 := fileStat(f)
	named, e2 := statPath(path)
	if err != nil || e1 != nil || e2 != nil || actual != expected || !sameIdentity(before, after) || !sameIdentity(before, named) {
		return before, errInvalid
	}
	return before, nil
}

func tool(arguments, environment []string, maximum int64, expected string, expectedSize int64) ([]byte, error) {
	command := exec.Command(arguments[0], arguments[1:]...)
	command.Env = environment
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = command.Start(); err != nil {
		return nil, err
	}
	waited := false
	defer func() {
		output.Close()
		if !waited {
			command.Process.Kill()
			command.Wait()
		}
	}()
	var body bytes.Buffer
	h := sha256.New()
	var count int64
	buffer := make([]byte, 65536)
	for {
		n, e := output.Read(buffer[:min(int64(len(buffer)), maximum-count+1)])
		count += int64(n)
		if count > maximum {
			return nil, errInvalid
		}
		if expected == "" {
			body.Write(buffer[:n])
		} else {
			h.Write(buffer[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
	}
	output.Close()
	err = command.Wait()
	waited = true
	if err != nil {
		return nil, err
	}
	if expected != "" && (count != expectedSize || hex.EncodeToString(h.Sum(nil)) != expected) {
		return nil, errInvalid
	}
	return body.Bytes(), nil
}

func createSmall(path string, body []byte) error {
	if len(body) > 65536 {
		return errInvalid
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func quote(path string) (string, error) {
	if strings.ContainsAny(path, "\"\\\n\r\x00") {
		return "", errInvalid
	}
	return "\"" + path + "\"", nil
}

func checkCandidate(path string, row object) error {
	f, info, err := openOwned(path, 0400)
	if err != nil {
		return err
	}
	defer f.Close()
	named, err := statPath(path)
	if err != nil || info.Nlink != 1 || !sameIdentity(info, named) || !same(object{"device": info.Dev, "inode": info.Ino, "bytes": info.Size, "modified_ns": info.Mtim.Nano(), "changed_ns": info.Ctim.Nano()}, object{"device": row["device"], "inode": row["inode"], "bytes": row["bytes"], "modified_ns": row["modified_ns"], "changed_ns": row["changed_ns"]}) {
		return errInvalid
	}
	return nil
}

func imageProfile(spec any, candidates []object) (av.Profile, av.Binding, []byte, error) {
	return imageProfileRevision(spec, candidates, false)
}

func imageProfileRevision(spec any, candidates []object, historical bool) (av.Profile, av.Binding, []byte, error) {
	var profile av.Profile
	var binding av.Binding
	body, err := encoded(spec)
	var revision av.Revision
	if err != nil || json.Unmarshal(body, &revision) != nil ||
		!same(spec, object{"profile_id": revision.ProfileID, "scanner_manifest_sha256": revision.ScannerManifestSHA256,
			"binary_sha256": revision.BinarySHA256, "configuration_sha256": revision.ConfigurationSHA256,
			"observation_sha256": revision.ObservationSHA256}) ||
		(!historical && revision != av.CurrentRevision()) || !av.KnownRevision(revision) || len(candidates) != 3 {
		return profile, binding, nil, errInvalid
	}
	names := map[string]bool{}
	definitions := []av.Definition{}
	var total int64
	for _, row := range candidates {
		name, ok := row["name"].(string)
		if !ok || !definitionName.MatchString(name) || !validDigest(row["sha256"]) || !integer(row["bytes"], 1, candidateLimit) {
			return profile, binding, nil, errInvalid
		}
		stem := strings.SplitN(name, ".", 2)[0]
		if names[stem] {
			return profile, binding, nil, errInvalid
		}
		names[stem] = true
		total += number(row["bytes"])
		definitions = append(definitions, av.Definition{Name: name, SHA256: row["sha256"].(string), ByteSize: number(row["bytes"])})
	}
	if total > candidateLimit {
		return profile, binding, nil, errInvalid
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].Name < definitions[j].Name })
	profile = av.Profile{SchemaVersion: 1, ProfileID: revision.ProfileID, ScannerManifestSHA256: revision.ScannerManifestSHA256, ConfigurationSHA256: revision.ConfigurationSHA256, DefinitionSetSHA256: av.DefinitionDigest(definitions), ObservationSHA256: revision.ObservationSHA256, Definitions: definitions}
	body, err = json.Marshal(profile)
	if err != nil {
		return profile, binding, nil, err
	}
	binding = av.Binding{ProfileSHA256: digest(body), ScannerManifestSHA256: revision.ScannerManifestSHA256, BinarySHA256: revision.BinarySHA256, ConfigurationSHA256: revision.ConfigurationSHA256, DefinitionSetSHA256: profile.DefinitionSetSHA256, ObservationSHA256: revision.ObservationSHA256}
	return profile, binding, body, nil
}

func buildImage(out string, requested, manifest object, candidates []object) error {
	id, ok := requested["attempt_id"].(string)
	if !ok || !updateID.MatchString(id) || requested["profile"] != updateProfile || requested["fixture_only"] != false || manifest["profile"] != updateProfile || manifest["fixture_only"] != false || filepath.Base(out) != "output" || filepath.Base(filepath.Dir(out)) != id {
		return errInvalid
	}
	attempt, ok := requested["attempt"].(object)
	if !ok || !integer(attempt["deadline_continuous_ns"], 1, 1<<63-1) || !integer(attempt["base_generation"], 0, 1<<63-1) {
		return errInvalid
	}
	directory := filepath.Join(out, "candidates")
	info, err := statPath(directory)
	if err != nil || !canonical(out) || !canonical(directory) || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != uint32(os.Getuid()) || uint32(info.Mode)&07777 != 0700 {
		return errInvalid
	}
	owner, _, err := readControl(filepath.Join(out, "candidate-directory.json"), 4096)
	if err != nil || !same(owner, object{"schema": 1, "update_id": id, "device": info.Dev, "inode": info.Ino}) {
		return errInvalid
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(candidates) {
		return errInvalid
	}
	names := map[string]bool{}
	for _, row := range candidates {
		name, ok := row["name"].(string)
		if !ok {
			return errInvalid
		}
		names[name] = true
	}
	for _, entry := range entries {
		if !names[entry.Name()] {
			return errInvalid
		}
	}
	profile, binding, profileBytes, err := imageProfile(manifest["image_profile"], candidates)
	if err != nil {
		return err
	}
	tools, ok := manifest["image_tools"].(object)
	if !ok || !fields(tools, "mke2fs debugfs mke2fs_config") {
		return errInvalid
	}
	pins, ok := manifest["sha256"].(object)
	if !ok {
		return errInvalid
	}
	workspace, ok := manifest["workspace"].(string)
	if !ok {
		return errInvalid
	}
	toolPaths := map[string]string{}
	for name, value := range tools {
		path, ok := value.(string)
		if !ok {
			return errInvalid
		}
		toolPaths[name] = path
	}
	clock := filepath.Join(workspace, "experiments/host/.build/integrated-watchdog")
	limits := map[string]int64{toolPaths["mke2fs"]: 32 << 20, toolPaths["debugfs"]: 32 << 20, toolPaths["mke2fs_config"]: 65536, clock: 32 << 20}
	identities := map[string]unix.Stat_t{}
	for path, limit := range limits {
		s, e := pinned(path, pins[path], limit)
		if e != nil {
			return e
		}
		identities[path] = s
	}
	environment := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "MKE2FS_CONFIG=" + toolPaths["mke2fs_config"]}
	phase := func() error {
		for path, expected := range identities {
			current, e := statPath(path)
			if e != nil || !canonical(path) || !sameIdentity(expected, current) {
				return errInvalid
			}
		}
		body, e := tool([]string{clock, "clock"}, environment, 128, "", 0)
		if e != nil {
			return e
		}
		if !regexp.MustCompile(`^[0-9]+\n$`).Match(body) {
			return errInvalid
		}
		now, e := strconv.ParseInt(strings.TrimSuffix(string(body), "\n"), 10, 64)
		if e != nil || now >= number(attempt["deadline_continuous_ns"]) {
			return errInvalid
		}
		return nil
	}
	if err = phase(); err != nil {
		return err
	}
	for _, row := range candidates {
		if err = checkCandidate(filepath.Join(directory, row["name"].(string)), row); err != nil {
			return err
		}
	}
	profilePath := filepath.Join(out, "image-profile.json")
	if err = createSmall(profilePath, profileBytes); err != nil {
		return err
	}
	type install struct {
		source, target, sha string
		size                int64
	}
	installs := []install{}
	for _, row := range candidates {
		name := row["name"].(string)
		installs = append(installs, install{filepath.Join(directory, name), "/" + name, row["sha256"].(string), number(row["bytes"])})
	}
	installs = append(installs, install{profilePath, "/product-profile.json", binding.ProfileSHA256, int64(len(profileBytes))})
	commands := []string{}
	for _, item := range installs {
		source, e := quote(item.source)
		if e != nil {
			return e
		}
		target, e := quote(item.target)
		if e != nil {
			return e
		}
		commands = append(commands, "write "+source+" "+target, "set_inode_field "+target+" uid 0", "set_inode_field "+target+" gid 0", "set_inode_field "+target+" mode 0100444")
	}
	script := filepath.Join(out, "image-install.txt")
	if err = createSmall(script, []byte(strings.Join(commands, "\n")+"\n")); err != nil {
		return err
	}
	plan := object{"schema": 1, "update_id": id, "name": "definitions.ext4", "bytes": imageBytes, "profile_sha256": binding.ProfileSHA256, "device": info.Dev, "inode": info.Ino}
	if _, err = writeControl(filepath.Join(out, "image-plan.json"), plan); err != nil {
		return err
	}
	pending := filepath.Join(directory, "definitions.ext4.pending")
	fd, err := unix.Open(pending, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), pending)
	original, e := fileStat(f)
	if e != nil {
		f.Close()
		return e
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = syncDirectory(directory); err != nil {
		return err
	}
	plan["device"], plan["inode"] = original.Dev, original.Ino
	if _, err = writeControl(filepath.Join(out, "image-owner.json"), plan); err != nil {
		return err
	}
	if err = phase(); err != nil {
		return err
	}
	if _, err = tool([]string{toolPaths["mke2fs"], "-q", "-t", "ext4", "-F", "-m", "0", "-b", "4096", "-I", "256", "-i", "16384", "-E", "root_owner=0:0,nodiscard,lazy_itable_init=0,lazy_journal_init=0", pending, strconv.FormatInt(imageBytes/4096, 10)}, environment, 65536, "", 0); err != nil {
		return err
	}
	if err = phase(); err != nil {
		return err
	}
	if _, err = tool([]string{toolPaths["debugfs"], "-w", "-f", script, pending}, environment, 65536, "", 0); err != nil {
		return err
	}
	for _, item := range installs {
		if err = phase(); err != nil {
			return err
		}
		target, _ := quote(item.target)
		metadata, e := tool([]string{toolPaths["debugfs"], "-R", "stat " + target, pending}, environment, 65536, "", 0)
		if e != nil {
			return e
		}
		for _, pattern := range []string{`User:\s+0\s+Group:\s+0\b`, `\bSize:\s+` + strconv.FormatInt(item.size, 10) + `\b`, `Type:\s+regular\s+Mode:\s+0*444\b`, `Links:\s+1\b`} {
			if !regexp.MustCompile(pattern).Match(metadata) {
				return errInvalid
			}
		}
		if _, err = tool([]string{toolPaths["debugfs"], "-R", "cat " + target, pending}, environment, item.size, item.sha, item.size); err != nil {
			return err
		}
	}
	if err = phase(); err != nil {
		return err
	}
	for _, row := range candidates {
		if err = checkCandidate(filepath.Join(directory, row["name"].(string)), row); err != nil {
			return err
		}
	}
	image := filepath.Join(directory, "definitions.ext4")
	if !absent(image) {
		return errInvalid
	}
	if err = os.Rename(pending, image); err != nil {
		return err
	}
	if err = syncDirectory(directory); err != nil {
		return err
	}
	fd, err = unix.Open(image, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f = os.NewFile(uintptr(fd), image)
	defer f.Close()
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	before, err := fileStat(f)
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Getuid()) || before.Nlink != 1 || before.Size != imageBytes || before.Dev != original.Dev || before.Ino != original.Ino {
		return errInvalid
	}
	imageSHA, err := hashFile(f, imageBytes)
	if err != nil {
		return err
	}
	after, e1 := fileStat(f)
	named, e2 := statPath(image)
	if e1 != nil || e2 != nil || !sameIdentity(before, after) || !sameIdentity(after, named) {
		return errInvalid
	}
	if err = phase(); err != nil {
		return err
	}
	v, finalBytes, err := readControl(filepath.Join(out, "final.json"), 1<<20)
	final, ok := v.(object)
	if err != nil || !ok || final["fixture_only"] != false || final["all_required_origin_confirmations"] != true || final["all_required_artifacts_verified"] != true {
		return errInvalid
	}
	_, err = writeControl(filepath.Join(out, "definition-image.json"), object{"schema": 1, "update_id": id, "base_generation": attempt["base_generation"], "final_sha256": digest(finalBytes), "image": object{"name": "definitions.ext4", "sha256": imageSHA, "bytes": imageBytes, "device": after.Dev, "inode": after.Ino, "modified_ns": after.Mtim.Nano(), "changed_ns": after.Ctim.Nano()}, "profile": profile, "binding": binding})
	return err
}
