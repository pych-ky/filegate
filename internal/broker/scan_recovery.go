package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (b *Broker) validateScanRequest(run *scanRun) error {
	if run.job.InputReceipt == nil {
		return failure("VM_STOP_FAILED", 503)
	}
	requestPath := filepath.Join(run.directory, "request.json")
	body, err := readPrivate(requestPath, 16<<10)
	var request scanRequest
	if err != nil || strictJSON(body, &request) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	fields := []string{"schema_version", "job_id", "attempt_id", "policy_digest", "input_path", "expected_sha256", "byte_size", "metadata"}
	if request.SchemaVersion == 3 {
		fields = append(fields, "definition")
	}
	if _, err = requiredFields(body, fields...); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	input := run.job.InputReceipt
	definition, err := b.readScanDefinition(run.job.AttemptID)
	if err != nil || !bytes.Equal(encode(definition), encode(request.Definition)) {
		return failure("VM_STOP_FAILED", 503)
	}
	run.definition = definition
	knownVersion := request.SchemaVersion == 3 && request.PolicyDigest == formatPolicy && definition != nil || request.SchemaVersion == 2 && request.PolicyDigest == formatPolicy && definition == nil || request.SchemaVersion == 1 && definition == nil && (request.PolicyDigest == "filegate-product-formats-v3" || request.PolicyDigest == "filegate-product-formats-v2")
	if !knownVersion || request.JobID != run.job.JobID || request.AttemptID != run.job.AttemptID || request.InputPath != filepath.Join(b.config.DataDir, "objects", input.ObjectID) || request.ExpectedSHA256 != input.SHA256 || request.ByteSize != input.ByteSize {
		return failure("VM_STOP_FAILED", 503)
	}
	return nil
}

func (b *Broker) recoverRuntime(run *scanRun) error {
	vm := b.config.VM
	if vm == nil || b.validateScanRequest(run) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	requestPath := filepath.Join(run.directory, "request.json")
	for _, expected := range []struct{ path, digest string }{{vm.RunnerPath, b.runnerSHA}, {vm.Proof, b.proofSHA}} {
		info, e := os.Lstat(expected.path)
		if e != nil || !info.Mode().IsRegular() {
			return failure("VM_STOP_FAILED", 503)
		}
		if digest, e := digestFile(expected.path); e != nil || digest != expected.digest {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	// This mode only resumes owned cleanup; its timeout never signals native VM processes.
	ctx, cancel := context.WithTimeout(context.Background(), 39*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, vm.RunnerPath, "--recover", "--request", requestPath, "--out", filepath.Join(run.directory, "output"), "--proof", vm.Proof)
	cmd.Dir = vm.Workspace
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	_, err := readRuntimeSummary(run)
	return err
}

type cleanupComplete struct {
	Schema                       int    `json:"schema"`
	JobID                        string `json:"job_id"`
	AttemptID                    string `json:"attempt_id"`
	InputSHA256                  string `json:"input_sha256"`
	ByteSize                     int64  `json:"byte_size"`
	Kind                         string `json:"kind"`
	CleanupIntentSHA256          string `json:"cleanup_intent_sha256"`
	StopProofSHA256              string `json:"stop_proof_sha256"`
	RawReclaimed                 bool   `json:"raw_reclaimed"`
	ExternalDirectoriesReclaimed bool   `json:"external_directories_reclaimed"`
}

type cleanupIntent struct {
	Schema          int             `json:"schema"`
	JobID           string          `json:"job_id"`
	AttemptID       string          `json:"attempt_id"`
	InputSHA256     string          `json:"input_sha256"`
	ByteSize        int64           `json:"byte_size"`
	Kind            string          `json:"kind"`
	StopProofSHA256 string          `json:"stop_proof_sha256"`
	SlotOwnerSHA256 string          `json:"slot_owner_sha256"`
	Directories     json.RawMessage `json:"directories"`
}

type runtimeStopProof struct {
	Schema      int             `json:"schema"`
	JobID       string          `json:"job_id"`
	AttemptID   string          `json:"attempt_id"`
	InputSHA256 string          `json:"input_sha256"`
	ByteSize    int64           `json:"byte_size"`
	Kind        string          `json:"kind"`
	Stopped     bool            `json:"stopped"`
	Evidence    runtimeEvidence `json:"evidence"`
	Checks      json.RawMessage `json:"checks"`
}

func readRuntimeEvidence(run *scanRun, path, digest string, limit int64) ([]byte, error) {
	if !validDigest(digest) {
		return nil, failure("VM_STOP_FAILED", 503)
	}
	body, err := readPrivate(filepath.Join(run.directory, "output", path), limit)
	actual := sha256.Sum256(body)
	if err != nil || hex.EncodeToString(actual[:]) != digest {
		return nil, failure("VM_STOP_FAILED", 503)
	}
	return body, nil
}

func validateRecoveryEvidence(run *scanRun, summary runtimeSummary) error {
	if summary.RecoveryEvidence.Path != "cleanup-complete.json" || run.job.InputReceipt == nil {
		return failure("VM_STOP_FAILED", 503)
	}
	body, err := readRuntimeEvidence(run, "cleanup-complete.json", summary.RecoveryEvidence.SHA256, 64<<10)
	var complete cleanupComplete
	if err != nil || strictJSON(body, &complete) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(body, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "kind", "cleanup_intent_sha256", "stop_proof_sha256", "raw_reclaimed", "external_directories_reclaimed"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	input := run.job.InputReceipt
	if complete.Schema != 1 || complete.JobID != run.job.JobID || complete.AttemptID != run.job.AttemptID || complete.InputSHA256 != input.SHA256 || complete.ByteSize != input.ByteSize || !complete.RawReclaimed || !complete.ExternalDirectoriesReclaimed {
		return failure("VM_STOP_FAILED", 503)
	}
	body, err = readRuntimeEvidence(run, "cleanup-intent.json", complete.CleanupIntentSHA256, 64<<10)
	var intent cleanupIntent
	if err != nil || strictJSON(body, &intent) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(body, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "kind", "stop_proof_sha256", "slot_owner_sha256", "directories"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if intent.Schema != 1 || intent.JobID != complete.JobID || intent.AttemptID != complete.AttemptID || intent.InputSHA256 != complete.InputSHA256 || intent.ByteSize != complete.ByteSize || intent.Kind != complete.Kind || intent.StopProofSHA256 != complete.StopProofSHA256 || !validDigest(intent.SlotOwnerSHA256) {
		return failure("VM_STOP_FAILED", 503)
	}
	body, err = readRuntimeEvidence(run, "stop-proof.json", complete.StopProofSHA256, 64<<10)
	var proof runtimeStopProof
	if err != nil || strictJSON(body, &proof) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	fields, err := requiredFields(body, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "kind", "stopped", "evidence", "checks")
	if err != nil || proof.Schema != 1 || proof.JobID != complete.JobID || proof.AttemptID != complete.AttemptID || proof.InputSHA256 != complete.InputSHA256 || proof.ByteSize != complete.ByteSize || proof.Kind != complete.Kind || !proof.Stopped {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(fields["evidence"], "path", "sha256"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	var checks []string
	var evidencePath string
	switch complete.Kind {
	case "native_guardian":
		checks = []string{"identities_stopped", "service_absent", "guardian_verified"}
		evidencePath = "watchdog/results.json"
		if summary.NativeEvidence == nil || summary.NativeEvidence.Path != evidencePath || summary.NativeEvidence.SHA256 != proof.Evidence.SHA256 {
			return failure("VM_STOP_FAILED", 503)
		}
	case "native_stopped_group":
		checks = []string{"identities_stopped", "group_empty", "service_absent"}
		evidencePath = "watchdog/results.json"
		if summary.NativeEvidence == nil || summary.NativeEvidence.Path != evidencePath || summary.NativeEvidence.SHA256 != proof.Evidence.SHA256 {
			return failure("VM_STOP_FAILED", 503)
		}
	case "native_unstarted":
		checks = []string{"terminal_empty", "transfer_disabled", "watchdog_stopped", "service_absent"}
		evidencePath = "watchdog/results.json"
		if summary.NativeEvidence != nil {
			return failure("VM_STOP_FAILED", 503)
		}
	case "native_prelaunch":
		checks = []string{"producer_stopped", "bootstrap_not_started", "service_absent"}
		evidencePath = "native-recovery.json"
		if summary.NativeEvidence != nil {
			return failure("VM_STOP_FAILED", 503)
		}
	case "native_previous_boot":
		checks = []string{"boot_changed", "producer_stopped", "service_absent"}
		evidencePath = "native-previous-boot.json"
		if summary.NativeEvidence != nil || summary.Passed || summary.ReportAccepted || summary.ReportSHA256 != nil {
			return failure("VM_STOP_FAILED", 503)
		}
	case "prepare_unstarted":
		checks = []string{"leader_stopped", "group_empty"}
		evidencePath = "preparation-owner.json"
		if summary.NativeEvidence != nil {
			return failure("VM_STOP_FAILED", 503)
		}
	case "resources_unstarted":
		checks = []string{"producer_stopped", "prepare_not_started"}
		evidencePath = "resource-intent.json"
		if summary.NativeEvidence != nil {
			return failure("VM_STOP_FAILED", 503)
		}
	default:
		return failure("VM_STOP_FAILED", 503)
	}
	values, err := requiredFields(proof.Checks, checks...)
	if err != nil || proof.Evidence.Path != evidencePath {
		return failure("VM_STOP_FAILED", 503)
	}
	for _, name := range checks {
		var passed bool
		if json.Unmarshal(values[name], &passed) != nil || !passed {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	cleanupBody, err := readPrivate(filepath.Join(run.directory, "output", "raw-cleanup.json"), 64<<10)
	var cleanup struct {
		Reclaimed                    bool   `json:"reclaimed"`
		ReservationChargeBytes       int64  `json:"reservation_charge_bytes"`
		ClosedFDEvidence             string `json:"closed_fd_evidence"`
		ExternalDirectoriesReclaimed bool   `json:"external_directories_reclaimed"`
	}
	if err != nil || strictJSON(cleanupBody, &cleanup) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(cleanupBody, "reclaimed", "reservation_charge_bytes", "closed_fd_evidence", "external_directories_reclaimed"); err != nil || !cleanup.Reclaimed || cleanup.ReservationChargeBytes != 0 || cleanup.ClosedFDEvidence != "identity-bound stop-proof.json" || !cleanup.ExternalDirectoriesReclaimed {
		return failure("VM_STOP_FAILED", 503)
	}
	limit := controlReservation
	if complete.Kind == "prepare_unstarted" {
		limit = 16 << 10
	}
	body, err = readRuntimeEvidence(run, evidencePath, proof.Evidence.SHA256, limit)
	if err != nil {
		return err
	}
	if complete.Kind == "native_unstarted" {
		return validateNativeUnstarted(body)
	}
	if complete.Kind == "native_prelaunch" {
		return validateNativePrelaunch(body, run)
	}
	if complete.Kind == "native_previous_boot" {
		return validateNativePreviousBoot(body, run, intent.Directories)
	}
	if complete.Kind == "prepare_unstarted" {
		return validatePreparationOwner(body)
	}
	if complete.Kind == "resources_unstarted" {
		return validateResourceIntent(body, run)
	}
	return nil
}

func validateNativePrelaunch(body []byte, run *scanRun) error {
	var proof struct {
		Schema                   int     `json:"schema"`
		JobID                    string  `json:"job_id"`
		AttemptID                string  `json:"attempt_id"`
		InputSHA256              string  `json:"input_sha256"`
		ByteSize                 int64   `json:"byte_size"`
		Kind                     string  `json:"kind"`
		NativeIntentSHA256       string  `json:"native_intent_sha256"`
		BootstrapOwnerSHA256     *string `json:"bootstrap_owner_sha256"`
		ControlDirectory         string  `json:"control_directory"`
		ControlDirectoryIdentity *struct {
			Device uint64 `json:"device"`
			Inode  uint64 `json:"inode"`
		} `json:"control_directory_identity"`
		BootstrapNotStarted bool `json:"bootstrap_not_started"`
		ServiceAbsent       bool `json:"service_absent"`
	}
	if strictJSON(body, &proof) != nil || proof.Schema != 1 || proof.Kind != "native_prelaunch" || proof.JobID != run.job.JobID || proof.AttemptID != run.job.AttemptID || proof.InputSHA256 != run.job.InputReceipt.SHA256 || proof.ByteSize != run.job.InputReceipt.ByteSize || !proof.BootstrapNotStarted || !proof.ServiceAbsent {
		return failure("VM_STOP_FAILED", 503)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 12 {
		return failure("VM_STOP_FAILED", 503)
	}
	for _, name := range []string{"schema", "job_id", "attempt_id", "input_sha256", "byte_size", "kind", "native_intent_sha256", "bootstrap_owner_sha256", "control_directory", "control_directory_identity", "bootstrap_not_started", "service_absent"} {
		value, ok := fields[name]
		if !ok || (string(value) == "null" && name != "bootstrap_owner_sha256" && name != "control_directory_identity") {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	if proof.ControlDirectoryIdentity != nil {
		if _, err := requiredFields(fields["control_directory_identity"], "device", "inode"); err != nil || proof.ControlDirectoryIdentity.Inode == 0 {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	plan, err := readRuntimeEvidence(run, "native-intent.json", proof.NativeIntentSHA256, 64<<10)
	if err != nil {
		return err
	}
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
		BootSessionUUID    *string         `json:"boot_session_uuid,omitempty"`
	}
	suffix := strings.TrimPrefix(filepath.Base(proof.ControlDirectory), "fgw-")
	decoded, decodeErr := hex.DecodeString(suffix)
	if strictNativeIntent(plan, &intent) != nil || !((intent.Schema == 1 && intent.BootSessionUUID == nil) || (intent.Schema == 2 && intent.BootSessionUUID != nil && nativeBootUUID.MatchString(*intent.BootSessionUUID))) || intent.JobID != proof.JobID || intent.AttemptID != proof.AttemptID || intent.InputSHA256 != proof.InputSHA256 || intent.ByteSize != proof.ByteSize || intent.ControlDirectory != proof.ControlDirectory || !validDigest(intent.NativeBinarySHA256) || !validDigest(intent.NativeSourceSHA256) || filepath.Dir(proof.ControlDirectory) != "/private/tmp" || filepath.Base(proof.ControlDirectory) != "fgw-"+suffix || decodeErr != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != suffix {
		return failure("VM_STOP_FAILED", 503)
	}
	if proof.BootstrapOwnerSHA256 != nil {
		owner, err := readRuntimeEvidence(run, "native-bootstrap-owner.json", *proof.BootstrapOwnerSHA256, 16<<10)
		if err != nil || validateControlOwner(owner, "native_bootstrap_group") != nil {
			return failure("VM_STOP_FAILED", 503)
		}
	} else if _, err := os.Lstat(filepath.Join(run.directory, "output", "native-bootstrap-owner.json")); !os.IsNotExist(err) {
		return failure("VM_STOP_FAILED", 503)
	}
	for _, name := range []string{"native-bootstrap-dispatched.json", "native-start.json"} {
		if _, err := os.Lstat(filepath.Join(run.directory, "output", name)); !os.IsNotExist(err) {
			return failure("VM_STOP_FAILED", 503)
		}
	}
	return nil
}

func validateResourceIntent(body []byte, run *scanRun) error {
	var intent struct {
		Schema       int    `json:"schema"`
		JobID        string `json:"job_id"`
		AttemptID    string `json:"attempt_id"`
		InputSHA256  string `json:"input_sha256"`
		ByteSize     int64  `json:"byte_size"`
		RunDirectory string `json:"run_directory"`
		SlotValue    struct {
			Schema          int    `json:"schema"`
			BrokerPID       int64  `json:"broker_pid"`
			OutputDirectory string `json:"output_directory"`
			Status          string `json:"status"`
		} `json:"slot_value"`
		SlotSHA256  string `json:"slot_sha256"`
		SlotPending string `json:"slot_pending"`
	}
	if strictJSON(body, &intent) != nil || run.job.InputReceipt == nil {
		return failure("VM_STOP_FAILED", 503)
	}
	fields, err := requiredFields(body, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "run_directory", "slot_value", "slot_sha256", "slot_pending")
	if err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(fields["slot_value"], "schema", "broker_pid", "output_directory", "status"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	input := run.job.InputReceipt
	if intent.Schema != 1 || intent.JobID != run.job.JobID || intent.AttemptID != run.job.AttemptID || intent.InputSHA256 != input.SHA256 || intent.ByteSize != input.ByteSize || !validDigest(intent.SlotSHA256) || intent.SlotValue.Schema != 1 || intent.SlotValue.BrokerPID <= 1 || intent.SlotValue.OutputDirectory != filepath.Join(run.directory, "output") || intent.SlotValue.Status != "ACTIVE" || filepath.Dir(intent.RunDirectory) != "/private/tmp" || filepath.Base(intent.SlotPending) != "active-vm."+run.job.AttemptID+".pending" {
		return failure("VM_STOP_FAILED", 503)
	}
	return nil
}

func validateNativeUnstarted(body []byte) error {
	var fields map[string]json.RawMessage
	if strictJSON(body, &fields) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	var native struct {
		QEMUStarted            *bool `json:"qemu_started"`
		CleanupAllExited       bool  `json:"cleanup_all_exited"`
		TemporaryServiceAbsent bool  `json:"temporary_service_absent"`
		EmergencyOwnedCleanup  *bool `json:"emergency_owned_cleanup"`
		Terminal               struct {
			AllExited       bool               `json:"all_exited"`
			TransferAllowed *bool              `json:"transfer_allowed"`
			Processes       *[]json.RawMessage `json:"processes"`
		} `json:"terminal"`
	}
	if json.Unmarshal(body, &native) != nil || native.QEMUStarted == nil || *native.QEMUStarted || !native.CleanupAllExited || !native.TemporaryServiceAbsent || (native.EmergencyOwnedCleanup != nil && *native.EmergencyOwnedCleanup) || !native.Terminal.AllExited || native.Terminal.TransferAllowed == nil || *native.Terminal.TransferAllowed || native.Terminal.Processes == nil || len(*native.Terminal.Processes) != 0 {
		return failure("VM_STOP_FAILED", 503)
	}
	return nil
}

func validatePreparationOwner(body []byte) error {
	return validateControlOwner(body, "prepare_process_group")
}

func validateControlOwner(body []byte, kind string) error {
	var owner struct {
		Schema int    `json:"schema"`
		Kind   string `json:"kind"`
		Leader struct {
			PID          int64  `json:"pid"`
			StartAbstime uint64 `json:"start_abstime"`
			ProcessGroup int64  `json:"process_group"`
			UID          int64  `json:"uid"`
		} `json:"leader"`
		CommandSHA256 string `json:"command_sha256"`
	}
	if strictJSON(body, &owner) != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	fields, err := requiredFields(body, "schema", "kind", "leader", "command_sha256")
	if err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if _, err = requiredFields(fields["leader"], "pid", "start_abstime", "process_group", "uid"); err != nil {
		return failure("VM_STOP_FAILED", 503)
	}
	if owner.Schema != 1 || owner.Kind != kind || !validDigest(owner.CommandSHA256) || owner.Leader.PID <= 1 || owner.Leader.PID >= 1<<31 || owner.Leader.ProcessGroup != owner.Leader.PID || owner.Leader.StartAbstime == 0 || owner.Leader.UID != int64(os.Getuid()) {
		return failure("VM_STOP_FAILED", 503)
	}
	return nil
}
