package hostvm

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"filegate.local/filegate/internal/av"
	"filegate.local/filegate/internal/vmbridge"
	"golang.org/x/sys/unix"
)

var updatePattern = regexp.MustCompile(`^update_[0-9a-f]{32}$`)
var definitionPattern = regexp.MustCompile(`^(?:main|daily|bytecode)\.(?:cvd|cld)$`)

func ValidateDefinition(m Object, dataDirectory string, allowHistorical bool) error {
	if !Fields(m, "update_id", "generation", "confirmed", "manifest_sha256", "image_manifest_sha256", "image_path", "image", "profile", "binding") || !updatePattern.MatchString(Str(m, "update_id")) || Int(m, "generation") <= 0 || !digestPattern.MatchString(Str(m, "manifest_sha256")) || !digestPattern.MatchString(Str(m, "image_manifest_sha256")) || Str(m, "image_path") != filepath.Join(dataDirectory, "definitions", Str(m, "update_id"), "definitions.ext4") {
		return Error("PRODUCT_DEFINITION_INVALID")
	}
	clock := Map(m, "confirmed")
	if !Fields(clock, "boot", "utc", "continuous_ns") || !bootPattern.MatchString(Str(clock, "boot")) || Int(clock, "utc") <= 0 || Int(clock, "utc") > 253402300799 {
		return Error("PRODUCT_DEFINITION_CLOCK_INVALID")
	}
	if _, ok := Uint(clock, "continuous_ns"); !ok {
		return Error("PRODUCT_DEFINITION_CLOCK_INVALID")
	}
	image := Map(m, "image")
	if !Fields(image, "name", "sha256", "bytes", "device", "inode", "modified_ns", "changed_ns") || Str(image, "name") != "definitions.ext4" || !digestPattern.MatchString(Str(image, "sha256")) || Int(image, "bytes") != 1<<30 {
		return Error("PRODUCT_DEFINITION_IMAGE_INVALID")
	}
	for _, k := range []string{"device", "inode", "modified_ns", "changed_ns"} {
		if Int(image, k) <= 0 {
			return Error("PRODUCT_DEFINITION_IMAGE_INVALID")
		}
	}
	profile := Map(m, "profile")
	binding := Map(m, "binding")
	if !Fields(profile, "schema_version", "profile_id", "scanner_manifest_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only", "definitions") || Int(profile, "schema_version") != 1 || profile["fixture_definitions_only"] != false || !Fields(binding, "profile_sha256", "scanner_manifest_sha256", "binary_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only") || binding["fixture_definitions_only"] != false {
		return Error("PRODUCT_DEFINITION_PROFILE_INVALID")
	}
	for k, v := range binding {
		if k != "fixture_definitions_only" {
			text, ok := v.(string)
			if !ok || !digestPattern.MatchString(text) {
				return Error("PRODUCT_DEFINITION_PROFILE_INVALID")
			}
		}
	}
	for _, k := range []string{"scanner_manifest_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256"} {
		if profile[k] != binding[k] {
			return Error("PRODUCT_DEFINITION_PROFILE_INVALID")
		}
	}
	revision := av.Revision{ProfileID: Str(profile, "profile_id"), ScannerManifestSHA256: Str(binding, "scanner_manifest_sha256"), BinarySHA256: Str(binding, "binary_sha256"), ConfigurationSHA256: Str(binding, "configuration_sha256"), ObservationSHA256: Str(binding, "observation_sha256")}
	if revision != av.CurrentRevision() && (!allowHistorical || !av.KnownRevision(revision)) {
		return Error("PRODUCT_DEFINITION_REVISION_INVALID")
	}
	rows := List(profile, "definitions")
	if len(rows) != 3 {
		return Error("PRODUCT_DEFINITION_SET_INVALID")
	}
	defs := make([]av.Definition, 0, 3)
	previous := ""
	seen := map[string]bool{}
	var total int64
	for _, row := range rows {
		v, ok := row.(Object)
		if !ok || !Fields(v, "name", "sha256", "byte_size") || !definitionPattern.MatchString(Str(v, "name")) || !digestPattern.MatchString(Str(v, "sha256")) || Int(v, "byte_size") <= 0 || Int(v, "byte_size") > (1<<30)-(64<<20) {
			return Error("PRODUCT_DEFINITION_SET_INVALID")
		}
		name := Str(v, "name")
		base := strings.Split(name, ".")[0]
		if name <= previous || seen[base] {
			return Error("PRODUCT_DEFINITION_SET_INVALID")
		}
		previous = name
		seen[base] = true
		total += Int(v, "byte_size")
		defs = append(defs, av.Definition{Name: name, SHA256: Str(v, "sha256"), ByteSize: Int(v, "byte_size")})
	}
	if total > (1<<30)-(64<<20) || av.DefinitionDigest(defs) != Str(profile, "definition_set_sha256") {
		return Error("PRODUCT_DEFINITION_DIGEST_INVALID")
	}
	p := av.Profile{SchemaVersion: 1, ProfileID: Str(profile, "profile_id"), ScannerManifestSHA256: Str(profile, "scanner_manifest_sha256"), ConfigurationSHA256: Str(profile, "configuration_sha256"), DefinitionSetSHA256: Str(profile, "definition_set_sha256"), ObservationSHA256: Str(profile, "observation_sha256"), Definitions: defs}
	body, e := json.Marshal(p)
	if e != nil || HashBytes(body) != Str(binding, "profile_sha256") {
		return Error("PRODUCT_DEFINITION_DIGEST_INVALID")
	}
	return nil
}
func DefinitionFresh(value Object, boot string, utc int64, continuous uint64) bool {
	confirmed := Map(value, "confirmed")
	started, ok := Uint(confirmed, "continuous_ns")
	return ok && bootPattern.MatchString(boot) && utc > 0 && utc <= 253402300799 && boot == Str(confirmed, "boot") && utc >= Int(confirmed, "utc") && utc-Int(confirmed, "utc") <= 86400 && continuous >= started && continuous-started <= 86400*1e9
}
func SelectedDefinition(requestPath string, verify bool) (Object, error) {
	req, e := ReadScanRequest(requestPath, false)
	if e != nil {
		return nil, e
	}
	if Int(req, "schema_version") != 3 {
		return nil, Error("PRODUCT_DEFINITION_REQUEST_REQUIRED")
	}
	value := Map(req, "definition")
	path := Str(value, "image_path")
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || canonical != path || strings.Contains(path, ",") {
		return nil, Error("PRODUCT_DEFINITION_IMAGE_PATH")
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	image := Map(value, "image")
	match := func(s unix.Stat_t) bool {
		return s.Mode&unix.S_IFMT == unix.S_IFREG && s.Uid == uint32(os.Getuid()) && s.Mode&07777 == 0400 && s.Nlink == 1 && SameDirectory(s, image) && s.Size == Int(image, "bytes") && s.Mtim.Nano() == Int(image, "modified_ns") && s.Ctim.Nano() == Int(image, "changed_ns")
	}
	var before, after, pathInfo unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !match(before) {
		return nil, Error("PRODUCT_DEFINITION_IMAGE_CHANGED")
	}
	if verify {
		bodyHash, e := hashReader(file, before.Size)
		if e != nil || bodyHash != Str(image, "sha256") {
			return nil, Error("PRODUCT_DEFINITION_IMAGE_HASH")
		}
		var b [1]byte
		n, e := file.Read(b[:])
		if n != 0 || e != io.EOF {
			return nil, Error("PRODUCT_DEFINITION_IMAGE_TRUNCATED")
		}
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(path, &pathInfo) != nil || !match(after) || !match(pathInfo) {
		return nil, Error("PRODUCT_DEFINITION_IMAGE_CHANGED")
	}
	return value, nil
}
func ReadScanRequest(path string, cleanup bool) (Object, error) {
	_, body, e := Read(path, RequestLimit)
	if e != nil {
		return nil, e
	}
	if !cleanup {
		m, e := vmbridge.ReadProductRequest(path, HashBytes(body))
		if e == nil && Int(m, "schema_version") == 3 {
			e = ValidateDefinition(Map(m, "definition"), filepath.Dir(filepath.Dir(Str(m, "input_path"))), false)
		}
		return m, e
	}
	m, e := Decode(body)
	if e != nil {
		return nil, e
	}
	schema := Int(m, "schema_version")
	if schema == 2 || schema == 3 {
		m, e := vmbridge.ReadProductRequest(path, HashBytes(body))
		if e == nil && schema == 3 {
			e = ValidateDefinition(Map(m, "definition"), filepath.Dir(filepath.Dir(Str(m, "input_path"))), true)
		}
		return m, e
	}
	if schema != 1 || Str(m, "policy_digest") != "filegate-product-formats-v3" && Str(m, "policy_digest") != "filegate-product-formats-v2" {
		return nil, Error("PRODUCT_REQUEST_INVALID")
	}
	copy := Clone(m)
	copy["schema_version"] = 2
	copy["policy_digest"] = "filegate-product-scan-v4"
	if !Fields(copy, "schema_version", "job_id", "attempt_id", "policy_digest", "input_path", "expected_sha256", "byte_size", "metadata") || !regexp.MustCompile(`^job_[0-9a-f]{32}$`).MatchString(Str(copy, "job_id")) || !regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(Str(copy, "attempt_id")) || !digestPattern.MatchString(Str(copy, "expected_sha256")) || Int(copy, "byte_size") < 0 || Int(copy, "byte_size") > 250<<20 || !filepath.IsAbs(Str(copy, "input_path")) {
		return nil, Error("PRODUCT_REQUEST_INVALID")
	}
	metadata := Map(copy, "metadata")
	if metadata == nil {
		return nil, Error("PRODUCT_METADATA_INVALID")
	}
	limits := map[string]int{"display_name": 2048, "declared_media_type": 256, "expected_type": 32}
	for k, v := range metadata {
		s, ok := v.(string)
		limit, known := limits[k]
		if !ok || !known || len(s) > limit {
			return nil, Error("PRODUCT_METADATA_INVALID")
		}
	}
	return m, nil
}
func (r *Runtime) FreshBeforeStart(req Object) error {
	if Int(req, "schema_version") != 3 {
		return nil
	}
	boot, e := BootUUID()
	if e != nil {
		return e
	}
	now, e := r.Clock()
	if e != nil {
		return e
	}
	if !DefinitionFresh(Map(req, "definition"), boot, time.Now().Unix(), now) {
		return Error("DATABASE_STALE")
	}
	return nil
}
