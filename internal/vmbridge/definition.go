package vmbridge

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"filegate.local/filegate/internal/av"
)

var updateID = regexp.MustCompile(`^update_[0-9a-f]{32}$`)
var bootID = regexp.MustCompile(`^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)
var definitionName = regexp.MustCompile(`^(?:main|daily|bytecode)\.(?:cvd|cld)$`)

func definition(value any, dataDirectory string) bool {
	m, ok := value.(object)
	if !ok || !fields(m, "update_id generation confirmed manifest_sha256 image_manifest_sha256 image_path image profile binding") {
		return false
	}
	id, ok := m["update_id"].(string)
	if !ok || !updateID.MatchString(id) || !integer(m["generation"], 1, 1<<63-1) || !validDigest(m["manifest_sha256"]) || !validDigest(m["image_manifest_sha256"]) || m["image_path"] != filepath.Join(dataDirectory, "definitions", id, "definitions.ext4") {
		return false
	}
	clock, ok := m["confirmed"].(object)
	if !ok || !fields(clock, "boot utc continuous_ns") || !integer(clock["utc"], 1, 253402300799) {
		return false
	}
	boot, ok := clock["boot"].(string)
	continuous, nOK := clock["continuous_ns"].(json.Number)
	if !ok || !bootID.MatchString(boot) || !nOK {
		return false
	}
	if _, err := strconv.ParseUint(string(continuous), 10, 64); err != nil {
		return false
	}
	image, ok := m["image"].(object)
	if !ok || !fields(image, "name sha256 bytes device inode modified_ns changed_ns") || image["name"] != "definitions.ext4" || !validDigest(image["sha256"]) || !integer(image["bytes"], 1<<30, 1<<30) {
		return false
	}
	for _, k := range []string{"device", "inode", "modified_ns", "changed_ns"} {
		if !integer(image[k], 1, 1<<63-1) {
			return false
		}
	}
	p, ok := m["profile"].(object)
	if !ok || !fields(p, "schema_version profile_id scanner_manifest_sha256 configuration_sha256 definition_set_sha256 observation_sha256 fixture_definitions_only definitions") || !integer(p["schema_version"], 1, 1) || p["profile_id"] != av.ProfileID || p["fixture_definitions_only"] != false {
		return false
	}
	b, ok := m["binding"].(object)
	if !ok || !fields(b, "profile_sha256 scanner_manifest_sha256 binary_sha256 configuration_sha256 definition_set_sha256 observation_sha256 fixture_definitions_only") || b["fixture_definitions_only"] != false {
		return false
	}
	for k, v := range b {
		if k != "fixture_definitions_only" && !validDigest(v) {
			return false
		}
	}
	for _, k := range []string{"scanner_manifest_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256"} {
		if p[k] != b[k] {
			return false
		}
	}
	rows, ok := p["definitions"].([]any)
	if !ok || len(rows) != 3 {
		return false
	}
	var total int64
	previous := ""
	seen := map[string]bool{}
	var definitionBytes strings.Builder
	for _, value := range rows {
		r, ok := value.(object)
		if !ok || !fields(r, "name sha256 byte_size") || !validDigest(r["sha256"]) || !integer(r["byte_size"], 1, (1<<30)-(64<<20)) {
			return false
		}
		name, ok := r["name"].(string)
		if !ok || !definitionName.MatchString(name) || name <= previous || seen[strings.Split(name, ".")[0]] {
			return false
		}
		seen[strings.Split(name, ".")[0]] = true
		previous = name
		total += number(r["byte_size"])
		definitionBytes.WriteString(name + "\x00" + r["sha256"].(string) + "\x00" + strconv.FormatInt(number(r["byte_size"]), 10) + "\n")
	}
	if total > (1<<30)-(64<<20) || digest([]byte(definitionBytes.String())) != p["definition_set_sha256"] {
		return false
	}
	// Profile struct order is the adopted image's canonical representation.
	body, err := encoded(p)
	if err != nil {
		return false
	}
	var profile av.Profile
	if json.Unmarshal(body, &profile) != nil {
		return false
	}
	canonical, err := encoded(profile)
	return err == nil && digest(canonical[:len(canonical)-1]) == b["profile_sha256"]
}
