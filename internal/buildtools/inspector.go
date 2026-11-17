package buildtools

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// build-inspector may replace only the guest binaries that compile the ZIP inspector and the installed ZIP contract.
var inspectorReplaceable = map[string]string{"/filegate-worker": "filegate-worker", "/filegate-av-fixture": "filegate-av-fixture", "/filegate-fixtures": "filegate-fixtures"}

// The guest-image sources build-inspector accepts besides the fixture-only ones build-guest already allows.
var inspectorSources = map[string]bool{"internal/inspect/zip.go": true, "internal/inspect/zip_extra.go": true}

// The reviewed ZIP32 Profile 2 contract keeps the Profile 1 file name and installed path; both byte versions are pinned.
const (
	zipContract          = "experiments/contracts/zip32-v1.json"
	zipContractImagePath = "/contracts/zip32-v1.json"
	zipContractV1        = "b30a17d426ef64f8c0d4f027835a09a4a50543614eb3c71f13e113266bbcb5b5"
	zipContractV2        = "a313236eabb951eb30941b579ac7ad9a6b9f431e59149a018dbd149898e37d1d"
)

// guestChange classifies one changed guest-input source: "inspector" for an approved build-inspector source, "guest" for a
// source that only replaceable build-guest binaries read and that is not installed in the image; anything else is rejected.
func guestChange(name string, imageInput bool, targetInputs map[string]map[string]bool, options BuildOptions) (string, error) {
	if options.Inspector && (inspectorSources[name] || name == zipContract) {
		return "inspector", inspectorReaders(name, targetInputs)
	}
	replaceable := options.GuestFixtures && !imageInput
	for _, target := range hostGuestTargets {
		if targetInputs[target.name][name] && guestReplaceable["/"+target.name] == "" {
			replaceable = false
		}
	}
	if !replaceable {
		return "", fmt.Errorf("changed source is a guest image input: %s", name)
	}
	return "guest", nil
}

// inspectorReaders requires every guest target reading a changed inspector source to be one build-inspector replaces.
func inspectorReaders(name string, targetInputs map[string]map[string]bool) error {
	for _, target := range hostGuestTargets {
		if targetInputs[target.name][name] && inspectorReplaceable["/"+target.name] == "" {
			return fmt.Errorf("changed inspector source is read by a fixed guest binary: %s", name)
		}
	}
	return nil
}

// inspectorContract accepts only the reviewed Profile 1 to Profile 2 contract bytes and records that policy change.
func inspectorContract(oldPath, oldSHA, newPath, newSHA string) (map[string]any, error) {
	if oldSHA != zipContractV1 || newSHA != zipContractV2 {
		return nil, errors.New("INSPECTOR_CONTRACT_NOT_APPROVED")
	}
	profiles := []string{}
	for _, item := range []struct{ path, sha string }{{oldPath, oldSHA}, {newPath, newSHA}} {
		body, err := os.ReadFile(item.path)
		if err != nil {
			return nil, err
		}
		var contract struct {
			ProfileID string `json:"profile_id"`
		}
		if digest(body) != item.sha || json.Unmarshal(body, &contract) != nil {
			return nil, fmt.Errorf("pinned source/artifact changed: %s", item.path)
		}
		profiles = append(profiles, contract.ProfileID)
	}
	if profiles[0] != "filegate-zip32-v1" || profiles[1] != "filegate-zip32-v2" {
		return nil, errors.New("INSPECTOR_CONTRACT_NOT_APPROVED")
	}
	return map[string]any{"path": zipContract, "image_path": zipContractImagePath, "superseded_profile_id": profiles[0], "superseded_sha256": oldSHA, "profile_id": profiles[1], "sha256": newSHA, "contract_change": true}, nil
}
