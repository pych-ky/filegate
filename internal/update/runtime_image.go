package update

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"filegate.local/filegate/internal/av"
)

const DefinitionImageBytes int64 = 1 << 30
const DefinitionCandidateLimit int64 = (1 << 30) - (64 << 20)

type ImageProfile = av.Revision

type ImageTools struct {
	Mke2fs       string `json:"mke2fs"`
	Debugfs      string `json:"debugfs"`
	Mke2fsConfig string `json:"mke2fs_config"`
}

type DefinitionImageManifest struct {
	Schema         int           `json:"schema"`
	UpdateID       string        `json:"update_id"`
	BaseGeneration int64         `json:"base_generation"`
	FinalSHA256    string        `json:"final_sha256"`
	Image          candidateFile `json:"image"`
	Profile        av.Profile    `json:"profile"`
	Binding        av.Binding    `json:"binding"`
}

type ScanDefinition struct {
	UpdateID            string        `json:"update_id"`
	Generation          int64         `json:"generation"`
	Confirmed           Clock         `json:"confirmed"`
	ManifestSHA256      string        `json:"manifest_sha256"`
	ImageManifestSHA256 string        `json:"image_manifest_sha256"`
	ImagePath           string        `json:"image_path"`
	Image               candidateFile `json:"image"`
	Profile             av.Profile    `json:"profile"`
	Binding             av.Binding    `json:"binding"`
}

func validImageProfile(p ImageProfile) bool {
	return p == av.CurrentRevision()
}

func validateDefinitionImage(image DefinitionImageManifest, candidates candidateManifest, expected ImageProfile) error {
	if !av.KnownRevision(expected) || image.Schema != 1 || image.UpdateID != candidates.UpdateID ||
		image.BaseGeneration != candidates.BaseGeneration || image.FinalSHA256 != candidates.FinalSHA256 ||
		image.Image.Name != "definitions.ext4" || image.Image.Bytes != DefinitionImageBytes || image.Image.Inode == 0 ||
		image.Image.ModifiedNS <= 0 || image.Image.ChangedNS <= 0 || !digestPattern.MatchString(image.Image.SHA256) || len(candidates.Files) != 3 {
		return Invalid
	}
	definitions := make([]av.Definition, 0, 3)
	names, total := map[string]bool{}, int64(0)
	for _, file := range candidates.Files {
		if !candidateName(file.Name) || names[file.Name[:len(file.Name)-4]] || !digestPattern.MatchString(file.SHA256) ||
			file.Bytes <= 0 || file.Bytes > DefinitionCandidateLimit {
			return Invalid
		}
		names[file.Name[:len(file.Name)-4]] = true
		total += file.Bytes
		definitions = append(definitions, av.Definition{Name: file.Name, SHA256: file.SHA256, ByteSize: file.Bytes})
	}
	if total > DefinitionCandidateLimit {
		return Invalid
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].Name < definitions[j].Name })
	profile := av.Profile{SchemaVersion: 1, ProfileID: expected.ProfileID, ScannerManifestSHA256: expected.ScannerManifestSHA256,
		ConfigurationSHA256: expected.ConfigurationSHA256, DefinitionSetSHA256: av.DefinitionDigest(definitions),
		ObservationSHA256: expected.ObservationSHA256, FixtureDefinitionsOnly: false, Definitions: definitions}
	body, err := json.Marshal(profile)
	if err != nil || !bytes.Equal(encoded(image.Profile), body) {
		return Invalid
	}
	binding := av.Binding{ProfileSHA256: sha256Text(body), ScannerManifestSHA256: expected.ScannerManifestSHA256,
		BinarySHA256: expected.BinarySHA256, ConfigurationSHA256: expected.ConfigurationSHA256,
		DefinitionSetSHA256: profile.DefinitionSetSHA256, ObservationSHA256: expected.ObservationSHA256, FixtureDefinitionsOnly: false}
	if image.Binding != binding {
		return Invalid
	}
	return nil
}

func readDefinitionImage(path string, candidates candidateManifest, expected ImageProfile) (DefinitionImageManifest, string, error) {
	var image DefinitionImageManifest
	body, err := runtimeRead(path, 64<<10)
	if err != nil || runtimeJSON(body, &image) != nil || validateDefinitionImage(image, candidates, expected) != nil {
		return image, "", Invalid
	}
	fields, err := imageFields(body, "schema", "update_id", "base_generation", "final_sha256", "image", "profile", "binding")
	if err != nil {
		return image, "", err
	}
	if _, err = imageFields(fields["image"], "name", "sha256", "bytes", "device", "inode", "modified_ns", "changed_ns"); err != nil {
		return image, "", err
	}
	profile, err := imageFields(fields["profile"], "schema_version", "profile_id", "scanner_manifest_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only", "definitions")
	if err != nil {
		return image, "", err
	}
	if _, err = imageFields(fields["binding"], "profile_sha256", "scanner_manifest_sha256", "binary_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only"); err != nil {
		return image, "", err
	}
	var definitions []json.RawMessage
	if json.Unmarshal(profile["definitions"], &definitions) != nil || len(definitions) != 3 {
		return image, "", Invalid
	}
	for _, definition := range definitions {
		if _, err = imageFields(definition, "name", "sha256", "byte_size"); err != nil {
			return image, "", err
		}
	}
	return image, sha256Text(encoded(image)), nil
}

func imageFields(body []byte, names ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != len(names) {
		return nil, Invalid
	}
	for _, name := range names {
		if value, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, Invalid
		}
	}
	return fields, nil
}

// ScanDefinition returns a host-approved generation without rereading the large image.
func (s *Store) ScanDefinition(now Clock) (ScanDefinition, error) {
	return s.scanDefinition(now, true, nil)
}

// CurrentScanDefinition validates the adopted version; scan-start freshness is checked separately.
func (s *Store) CurrentScanDefinition(now Clock) (ScanDefinition, error) {
	return s.scanDefinition(now, false, nil)
}

// CurrentScanDefinitionAdmitted runs a non-nil admit first in the same transaction, as ReadAdmitted does.
func (s *Store) CurrentScanDefinitionAdmitted(now Clock, admit func(*sql.Tx) error) (ScanDefinition, error) {
	return s.scanDefinition(now, false, admit)
}

// ScanDefinitionState separates a committed control read from the adopted definition's validation result.
type ScanDefinitionState struct {
	Control         Control
	Definition      ScanDefinition
	DefinitionError error
}

// ReadScanDefinitionAdmitted commits the clock advance even when definition validation fails; control/admission/commit
// errors stay separate so an optional display never uses an uncommitted Control. Strict scan readers keep scanDefinition.
func (s *Store) ReadScanDefinitionAdmitted(now Clock, admit func(*sql.Tx) error) (ScanDefinitionState, error) {
	var result ScanDefinitionState
	control, err := s.apply(now, func(tx *sql.Tx, control *Control, now Clock) error {
		if admit != nil {
			if err := admit(tx); err != nil {
				return err
			}
		}
		result.Definition, result.DefinitionError = currentScanDefinition(tx, *control, now, false)
		return nil
	})
	if err == nil {
		result.Control = control
	}
	return result, err
}

func (s *Store) scanDefinition(now Clock, requireFresh bool, admit func(*sql.Tx) error) (ScanDefinition, error) {
	var result ScanDefinition
	_, err := s.apply(now, func(tx *sql.Tx, control *Control, now Clock) error {
		if admit != nil {
			if err := admit(tx); err != nil {
				return err
			}
		}
		var err error
		result, err = currentScanDefinition(tx, *control, now, requireFresh)
		return err
	})
	return result, err
}

func currentScanDefinition(tx *sql.Tx, control Control, now Clock, requireFresh bool) (ScanDefinition, error) {
	var result ScanDefinition
	if control.Binding.FixtureOnly || control.Definition == nil || (requireFresh && (!Fresh(control, now) || control.ActiveUpdateID != "")) {
		return result, Error("DATABASE_STALE")
	}
	if err := readScanDefinition(tx, control.Definition, &result, ""); err != nil {
		return result, err
	}
	if !validImageProfile(ImageProfile{ProfileID: result.Profile.ProfileID, ScannerManifestSHA256: result.Binding.ScannerManifestSHA256,
		BinarySHA256: result.Binding.BinarySHA256, ConfigurationSHA256: result.Binding.ConfigurationSHA256, ObservationSHA256: result.Binding.ObservationSHA256}) {
		return result, Error("REVALIDATION_REQUIRED")
	}
	return result, nil
}

func readScanDefinition(tx *sql.Tx, definition *DefinitionSet, result *ScanDefinition, cacheBoot string) error {
	var body []byte
	if err := tx.QueryRow("SELECT data FROM update_adoptions WHERE update_id=?", definition.UpdateID).Scan(&body); err != nil {
		return err
	}
	var adopted adoptionRecord
	if decodeStored(body, &adopted) != nil || adopted.Schema != 1 || adopted.Manifest.UpdateID != definition.UpdateID ||
		adopted.Directory.UpdateID != definition.UpdateID || !digestPattern.MatchString(adopted.RuntimeSHA) ||
		adopted.Manifest.BaseGeneration+1 != definition.Generation || adopted.ManifestSHA != definition.ManifestSHA256 ||
		sha256Text(encoded(adopted.Manifest)) != definition.ManifestSHA256 || !adopted.Approved.Valid() {
		return Invalid
	}
	attempt, err := loadAttempt(tx, definition.UpdateID)
	if err != nil || !attempt.AdoptionApproved || !attempt.ControlCommitted || !attempt.OriginConfirmed ||
		!attempt.StopConfirmed || !attempt.CleanupConfirmed || attempt.State != "FINISHED" || attempt.ReservedBytes != 0 ||
		attempt.Reason != "" || attempt.BaseGeneration != adopted.Manifest.BaseGeneration ||
		attempt.FinalReceived == nil || *attempt.FinalReceived != definition.Confirmed || attempt.FinalSHA256 != adopted.Manifest.FinalSHA256 ||
		deadline(attempt, adopted.Approved) != nil {
		return Invalid
	}
	var directory, runtimeSHA, state string
	if err = tx.QueryRow("SELECT directory,manifest_sha256,state FROM update_runtime WHERE update_id=?", definition.UpdateID).
		Scan(&directory, &runtimeSHA, &state); err != nil || runtimeSHA != adopted.RuntimeSHA || state != "FINISHED" {
		return Invalid
	}
	image := adopted.DefinitionImage
	expected := ImageProfile{ProfileID: image.Profile.ProfileID, ScannerManifestSHA256: image.Binding.ScannerManifestSHA256, BinarySHA256: image.Binding.BinarySHA256,
		ConfigurationSHA256: image.Binding.ConfigurationSHA256, ObservationSHA256: image.Binding.ObservationSHA256}
	target := filepath.Join(filepath.Dir(filepath.Dir(directory)), "definitions", definition.UpdateID)
	// A previous boot's image is not reused as an update cache; scan reads remain strict.
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) || cacheBoot != "" && definition.Confirmed.Boot != cacheBoot {
		if validateDefinitionImage(image, adopted.Manifest, expected) != nil ||
			sha256Text(encoded(image)) != definition.ImageManifestSHA256 || adopted.Directory.Schema != 1 || adopted.Directory.Inode == 0 {
			return Invalid
		}
		parent := filepath.Dir(target)
		if canonical, err := filepath.EvalSymlinks(parent); err == nil && canonical == parent {
			return Error("DEFINITION_CACHE_MISSING")
		}
	}
	canonical, err := filepath.EvalSymlinks(target)
	if err != nil || canonical != target || matchCandidateDirectory(target, adopted.Directory) != nil {
		return Invalid
	}
	manifest, err := runtimeRead(filepath.Join(target, "manifest.json"), 16384)
	if err != nil || !bytes.Equal(manifest, encoded(adopted.Manifest)) {
		return Invalid
	}
	actual, digest, err := readDefinitionImage(filepath.Join(target, "definition-image.json"), adopted.Manifest, expected)
	if err != nil || digest != definition.ImageManifestSHA256 || !bytes.Equal(encoded(image), encoded(actual)) {
		return Invalid
	}
	path := filepath.Join(target, "definitions.ext4")
	if err = candidateIdentity(context.Background(), path, image.Image); err != nil {
		return err
	}
	*result = ScanDefinition{definition.UpdateID, definition.Generation, definition.Confirmed, definition.ManifestSHA256,
		definition.ImageManifestSHA256, path, image.Image, image.Profile, image.Binding}
	return nil
}
