package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var nativeBootUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var nativeControlDirectory = regexp.MustCompile(`^/private/tmp/fgw-[0-9a-f]{32}$`)
var nativeRunDirectory = regexp.MustCompile(`^/private/tmp/filegate-vm-[0-9a-f]{32}$`)

type nativeDirectoryIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func (identity nativeDirectoryIdentity) valid() bool {
	return identity.Device != 0 && identity.Inode != 0
}

func strictNativeIntent(body []byte, value any) error {
	if err := strictJSONKeys(body, value, 4096); err != nil {
		return err
	}
	var intent, config map[string]json.RawMessage
	if json.Unmarshal(body, &intent) != nil || json.Unmarshal(intent["config"], &config) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	var pins map[string]string
	if json.Unmarshal(config["helper_pins"], &pins) != nil || len(pins) < 2 || len(pins) > 8 {
		return failure("VM_STOP_FAILED", 503)
	}
	for path, digest := range pins {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) || len(path) > 4096 || !validDigest(digest) {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	// Only canonical helper pin paths use the native argv path budget.
	delete(config, "helper_pins")
	intent["config"], _ = json.Marshal(config)
	ordinary, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return strictJSON(ordinary, new(any))
}

func validateNativePreviousBoot(body []byte, run *scanRun, directories json.RawMessage) error {
	var proof struct {
		Schema                   int                      `json:"schema"`
		JobID                    string                   `json:"job_id"`
		AttemptID                string                   `json:"attempt_id"`
		InputSHA256              string                   `json:"input_sha256"`
		ByteSize                 int64                    `json:"byte_size"`
		Kind                     string                   `json:"kind"`
		NativeIntentSHA256       string                   `json:"native_intent_sha256"`
		PreparationIntentSHA256  string                   `json:"preparation_intent_sha256"`
		PreparedIdentitySHA256   string                   `json:"prepared_identity_sha256"`
		NativeDirectorySHA256    *string                  `json:"native_directory_sha256"`
		PreviousBootUUID         string                   `json:"previous_boot_uuid"`
		ObservedBootUUID         string                   `json:"observed_boot_uuid"`
		ControlDirectory         string                   `json:"control_directory"`
		ControlDirectoryIdentity *nativeDirectoryIdentity `json:"control_directory_identity"`
		RunDirectory             string                   `json:"run_directory"`
		RunDirectoryIdentity     nativeDirectoryIdentity  `json:"run_directory_identity"`
		BootChanged              bool                     `json:"boot_changed"`
		ServiceAbsent            bool                     `json:"service_absent"`
	}
	if strictJSON(body, &proof) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 18 {
		return failure("VM_STOP_FAILED", 503)
	}
	for _, name := range []string{"schema", "job_id", "attempt_id", "input_sha256", "byte_size", "kind", "native_intent_sha256", "preparation_intent_sha256", "prepared_identity_sha256", "native_directory_sha256", "previous_boot_uuid", "observed_boot_uuid", "control_directory", "control_directory_identity", "run_directory", "run_directory_identity", "boot_changed", "service_absent"} {
		value, ok := fields[name]
		if !ok || (string(value) == "null" && name != "native_directory_sha256" && name != "control_directory_identity") {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	input := run.job.InputReceipt
	boot, err := releaseBootID()
	boot = strings.ToLower(boot)
	if input == nil || proof.Schema != 1 || proof.Kind != "native_previous_boot" || proof.JobID != run.job.JobID || proof.AttemptID != run.job.AttemptID || proof.InputSHA256 != input.SHA256 || proof.ByteSize != input.ByteSize || !proof.BootChanged || !proof.ServiceAbsent || !nativeBootUUID.MatchString(proof.PreviousBootUUID) || !nativeBootUUID.MatchString(proof.ObservedBootUUID) || proof.PreviousBootUUID == proof.ObservedBootUUID || err != nil || !nativeBootUUID.MatchString(boot) || boot == proof.PreviousBootUUID || !nativeControlDirectory.MatchString(proof.ControlDirectory) || !nativeRunDirectory.MatchString(proof.RunDirectory) || !proof.RunDirectoryIdentity.valid() || (proof.NativeDirectorySHA256 == nil) != (proof.ControlDirectoryIdentity == nil) {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(fields["run_directory_identity"], "device", "inode"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if proof.ControlDirectoryIdentity != nil {
		if _, err = requiredFields(fields["control_directory_identity"], "device", "inode"); err != nil || !proof.ControlDirectoryIdentity.valid() {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	plan, err := readRuntimeEvidence(run, "native-intent.json", proof.NativeIntentSHA256, 64<<10)
	var intent struct {
		Schema             int             `json:"schema"`
		JobID              string          `json:"job_id"`
		AttemptID          string          `json:"attempt_id"`
		InputSHA256        string          `json:"input_sha256"`
		ByteSize           int64           `json:"byte_size"`
		ControlDirectory   string          `json:"control_directory"`
		Config             json.RawMessage `json:"config"`
		NativeBinarySHA256 string          `json:"native_binary_sha256"`
		NativeSourceSHA256 string          `json:"native_source_sha256"`
		BootSessionUUID    string          `json:"boot_session_uuid"`
	}
	if err != nil || strictNativeIntent(plan, &intent) != nil || intent.Schema != 2 || intent.JobID != proof.JobID || intent.AttemptID != proof.AttemptID || intent.InputSHA256 != proof.InputSHA256 || intent.ByteSize != proof.ByteSize || intent.ControlDirectory != proof.ControlDirectory || intent.BootSessionUUID != proof.PreviousBootUUID || !validDigest(intent.NativeBinarySHA256) || !validDigest(intent.NativeSourceSHA256) {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(plan, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "control_directory", "config", "native_binary_sha256", "native_source_sha256", "boot_session_uuid"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	var config struct {
		Schema     int    `json:"schema"`
		Mode       string `json:"mode"`
		OwnerKind  string `json:"owner_kind"`
		Control    string `json:"control_directory"`
		Run        string `json:"run_directory"`
		StartNS    uint64 `json:"continuous_start_ns"`
		DeadlineNS uint64 `json:"continuous_deadline_ns"`
	}
	if json.Unmarshal(intent.Config, &config) != nil || config.Schema != 1 || config.Mode != "qemu" || config.OwnerKind != "scan" || config.Control != proof.ControlDirectory || config.Run != proof.RunDirectory || config.DeadlineNS < config.StartNS || config.DeadlineNS-config.StartNS != 300*1e9 {
		return failure("VM_STOP_FAILED", 503)
	}
	preparation, err := readRuntimeEvidence(run, "preparation-intent.json", proof.PreparationIntentSHA256, 64<<10)
	var prep struct {
		Schema      int                     `json:"schema"`
		JobID       string                  `json:"job_id"`
		AttemptID   string                  `json:"attempt_id"`
		Run         string                  `json:"run_directory"`
		Identity    nativeDirectoryIdentity `json:"run_directory_identity"`
		Reservation int64                   `json:"reservation_charge_bytes"`
	}
	if err != nil || strictJSON(preparation, &prep) != nil || prep.Schema != 1 || prep.JobID != proof.JobID || prep.AttemptID != proof.AttemptID || prep.Run != proof.RunDirectory || prep.Identity != proof.RunDirectoryIdentity || prep.Reservation != 4294967296 {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(preparation, "schema", "job_id", "attempt_id", "run_directory", "run_directory_identity", "reservation_charge_bytes"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	prepared, err := readRuntimeEvidence(run, "prepared-identity.json", proof.PreparedIdentitySHA256, 64<<10)
	var raw struct {
		Run      string                  `json:"run_directory"`
		Identity nativeDirectoryIdentity `json:"raw_identity"`
	}
	if err != nil || strictJSON(prepared, &raw) != nil || raw.Run != proof.RunDirectory || !raw.Identity.valid() {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(prepared, "run_directory", "raw_identity"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if proof.NativeDirectorySHA256 != nil {
		owner, e := readRuntimeEvidence(run, "native-directory.json", *proof.NativeDirectorySHA256, 64<<10)
		var record struct {
			Schema      int    `json:"schema"`
			JobID       string `json:"job_id"`
			AttemptID   string `json:"attempt_id"`
			InputSHA256 string `json:"input_sha256"`
			ByteSize    int64  `json:"byte_size"`
			Device      uint64 `json:"device"`
			Inode       uint64 `json:"inode"`
		}
		if e != nil || strictJSON(owner, &record) != nil || record.Schema != 1 || record.JobID != proof.JobID || record.AttemptID != proof.AttemptID || record.InputSHA256 != proof.InputSHA256 || record.ByteSize != proof.ByteSize || record.Device != proof.ControlDirectoryIdentity.Device || record.Inode != proof.ControlDirectoryIdentity.Inode {
			return failure("VM_STOP_FAILED", 503)
		}
		if _, err = requiredFields(owner, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "device", "inode"); err != nil {
			return failure("VM_STOP_FAILED", 503)
		}
	} else if _, err = os.Lstat(filepath.Join(run.directory, "output", "native-directory.json")); !os.IsNotExist(err) {
		return failure("VM_STOP_FAILED", 503)
	}
	var records []struct {
		Path   string          `json:"path"`
		Device uint64          `json:"device"`
		Inode  uint64          `json:"inode"`
		Files  json.RawMessage `json:"files"`
	}
	if strictJSON(directories, &records) != nil || records == nil || len(records) > 2 {
		return failure("VM_STOP_FAILED", 503)
	}
	seen := make(map[string]bool)
	for _, record := range records {
		identity := &proof.RunDirectoryIdentity
		if record.Path == proof.ControlDirectory {
			identity = proof.ControlDirectoryIdentity
		} else if record.Path != proof.RunDirectory {
			return failure("VM_STOP_FAILED", 503)
		}
		if identity == nil || record.Device != identity.Device || record.Inode != identity.Inode || seen[record.Path] || len(record.Files) == 0 || string(record.Files) == "null" {
			return failure("VM_STOP_FAILED", 503)
		}
		seen[record.Path] = true
	}
	for _, path := range []string{proof.RunDirectory, proof.ControlDirectory} {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	return nil
}
