package updatebridge

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"

	"filegate.local/filegate/internal/av"
	"golang.org/x/sys/unix"
)

var cacheBoot = regexp.MustCompile(`^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

func definitionCache(value any, dataDirectory string, manifest, attempt object) bool {
	if value == nil {
		return true
	}
	c, ok := value.(object)
	if !ok || !fields(c, "update_id generation confirmed manifest_sha256 image_manifest_sha256 image_path image profile binding") {
		return false
	}
	id, ok := c["update_id"].(string)
	if !ok || !updateID.MatchString(id) || !integer(c["generation"], 1, 1<<63-1) ||
		!integer(attempt["base_generation"], number(c["generation"]), 1<<63-1) ||
		!validDigest(c["manifest_sha256"]) || !validDigest(c["image_manifest_sha256"]) {
		return false
	}
	clock, ok := c["confirmed"].(object)
	if !ok || !fields(clock, "boot utc continuous_ns") || !integer(clock["utc"], 1, 253402300799) {
		return false
	}
	boot, ok := clock["boot"].(string)
	continuous, num := clock["continuous_ns"].(json.Number)
	if !ok || !cacheBoot.MatchString(boot) || !num {
		return false
	}
	if _, err := strconv.ParseUint(string(continuous), 10, 64); err != nil {
		return false
	}
	image, ok := c["image"].(object)
	if !ok || !fields(image, "name sha256 bytes device inode modified_ns changed_ns") || image["name"] != "definitions.ext4" ||
		!validDigest(image["sha256"]) || !integer(image["bytes"], imageBytes, imageBytes) {
		return false
	}
	for _, name := range []string{"device", "inode", "modified_ns", "changed_ns"} {
		if !integer(image[name], 1, 1<<63-1) {
			return false
		}
	}
	profile, ok := c["profile"].(object)
	if !ok {
		return false
	}
	rows, ok := profile["definitions"].([]any)
	if !ok || len(rows) != 3 {
		return false
	}
	candidates := make([]object, 0, 3)
	for _, row := range rows {
		file, ok := row.(object)
		if !ok || !fields(file, "name sha256 byte_size") {
			return false
		}
		candidates = append(candidates, object{"name": file["name"], "sha256": file["sha256"], "bytes": file["byte_size"]})
	}
	binding, ok := c["binding"].(object)
	if !ok {
		return false
	}
	spec := object{"profile_id": profile["profile_id"], "scanner_manifest_sha256": profile["scanner_manifest_sha256"],
		"binary_sha256": binding["binary_sha256"], "configuration_sha256": profile["configuration_sha256"],
		"observation_sha256": profile["observation_sha256"]}
	var previous, next av.Revision
	previousBytes, _ := encoded(spec)
	nextBytes, _ := encoded(manifest["image_profile"])
	if json.Unmarshal(previousBytes, &previous) != nil || json.Unmarshal(nextBytes, &next) != nil ||
		!av.CompatibleRevision(previous, next) {
		return false
	}
	expectedProfile, expectedBinding, _, err := imageProfileRevision(spec, candidates, true)
	if err != nil {
		return false
	}
	profileBytes, _ := encoded(expectedProfile)
	bindingBytes, _ := encoded(expectedBinding)
	profileValue, _ := decode(profileBytes)
	bindingValue, _ := decode(bindingBytes)
	if !same(profile, profileValue) || !same(c["binding"], bindingValue) {
		return false
	}
	path := filepath.Join(dataDirectory, "definitions", id, "definitions.ext4")
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path || c["image_path"] != path {
		return false
	}
	file, info, err := openOwned(path, 0400)
	if err != nil {
		return false
	}
	defer file.Close()
	var named unix.Stat_t
	return info.Nlink == 1 && info.Size == imageBytes && int64(info.Dev) == number(image["device"]) &&
		info.Ino == uint64(number(image["inode"])) && info.Mtim.Nano() == number(image["modified_ns"]) &&
		info.Ctim.Nano() == number(image["changed_ns"]) && unix.Lstat(path, &named) == nil && sameIdentity(info, named)
}

func cachePreflight(ready object, cache any) bool {
	if cache == nil {
		_, exists := ready["definition_profile_sha256"]
		return !exists
	}
	c := cache.(object)
	return ready["definition_profile_sha256"] == c["binding"].(object)["profile_sha256"] &&
		same(ready["blocks"].(object)["vdb"], object{"sectors": strconv.FormatInt(number(c["image"].(object)["bytes"])/512, 10), "read_only": "1"})
}
