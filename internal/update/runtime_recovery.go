package update

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"filegate.local/filegate/internal/hostvm"
)

type fixtureRuntimeReceipt struct {
	Schema           int    `json:"schema"`
	Profile          string `json:"profile"`
	FixtureOnly      bool   `json:"fixture_only"`
	UpdateID         string `json:"update_id"`
	BaseGeneration   int64  `json:"base_generation"`
	RequestSHA256    string `json:"request_sha256"`
	StopConfirmed    bool   `json:"stop_confirmed"`
	CleanupConfirmed bool   `json:"cleanup_confirmed"`
	CleanupSHA256    string `json:"cleanup_sha256"`
	FinalSHA256      string `json:"final_sha256"`
	NetworkEnabled   bool   `json:"network_enabled"`
	AdoptionEnabled  bool   `json:"adoption_enabled"`
	StartupOnly      bool   `json:"startup_only"`
	StopProofSHA256  string `json:"stop_proof_sha256"`
}

func (s *Store) RecoverFixture(manifestPath, directory, id string) (RuntimeResult, error) {
	var result RuntimeResult
	m, err := ReadRuntimeManifest(manifestPath)
	if err != nil {
		return result, err
	}
	var marker, recorded, state string
	if s.db.QueryRow("SELECT value FROM filegate_update_fixture WHERE id=1").Scan(&marker) != nil || marker != "synthetic-no-product-adoption" ||
		s.db.QueryRow("SELECT directory,state FROM update_fixture_runtime WHERE update_id=?", id).Scan(&recorded, &state) != nil || recorded != directory {
		return result, Invalid
	}
	now, err := ReadClock()
	if err != nil {
		return result, err
	}
	c, err := s.Read(now)
	if err != nil || c.Binding != (Binding{m.LibrarySHA256, true}) || c.Definition != nil {
		return result, Invalid
	}
	if _, err = s.Recover(now); err != nil {
		return result, err
	}
	if state == "PLANNED" || state == "RESERVED" {
		if _, err = os.Lstat(filepath.Join(directory, "output")); !errors.Is(err, os.ErrNotExist) {
			return result, Error("VM_STOP_FAILED")
		}
		_, err = s.Stopped(id, true, now)
		if err == nil {
			_, err = s.db.Exec("UPDATE update_fixture_runtime SET state='FINISHED' WHERE update_id=?", id)
		}
		return RuntimeResult{UpdateID: id, StopConfirmed: err == nil, CleanupConfirmed: err == nil}, err
	}
	data, err := runtimeRead(filepath.Join(directory, "request.json"), 16<<10)
	var r runtimeRequest
	if err != nil || runtimeJSON(data, &r) != nil || r.Attempt.ID != id || r.Profile != fixtureRuntimeProfile || !r.FixtureOnly || r.Library != m.LibrarySHA256 {
		return result, Invalid
	}
	return s.finishFixture(manifestPath, m, directory, r)
}

func (s *Store) finishFixture(manifestPath string, m RuntimeManifest, directory string, r runtimeRequest) (RuntimeResult, error) {
	return s.finishRuntime(manifestPath, m, directory, r, "update_fixture_runtime")
}

func (s *Store) finishRuntime(manifestPath string, m RuntimeManifest, directory string, r runtimeRequest, table string) (RuntimeResult, error) {
	result := RuntimeResult{UpdateID: r.Attempt.ID}
	ctx, cancel := context.WithTimeout(context.Background(), 39*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.Runner, "--recover", "--manifest", manifestPath,
		"--request", filepath.Join(directory, "request.json"), "--out", filepath.Join(directory, "output"))
	cmd.Dir, cmd.Stdout, cmd.Stderr, cmd.WaitDelay = m.Workspace, io.Discard, io.Discard, time.Second
	if cmd.Run() != nil {
		return result, Error("VM_STOP_FAILED")
	}
	body, err := runtimeRead(filepath.Join(directory, "output/update-complete.json"), 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		body, err = runtimeRead(filepath.Join(directory, "output/update-pending.json"), 16<<10)
	}
	var receipt fixtureRuntimeReceipt
	requestSHA, hashErr := runtimeFileSHA(filepath.Join(directory, "request.json"))
	if err != nil || hashErr != nil || runtimeJSON(body, &receipt) != nil || receipt.Schema != 1 || receipt.Profile != m.Profile || receipt.FixtureOnly != m.FixtureOnly ||
		receipt.UpdateID != r.Attempt.ID || receipt.BaseGeneration != r.Attempt.BaseGeneration || receipt.RequestSHA256 != requestSHA ||
		!receipt.StopConfirmed || receipt.NetworkEnabled == m.FixtureOnly || receipt.AdoptionEnabled {
		return result, Error("VM_STOP_FAILED")
	}
	if !receipt.CleanupConfirmed {
		if receipt.StartupOnly || receipt.CleanupSHA256 != "" {
			return result, Invalid
		}
		err = validateFixtureStop(directory, r, receipt.StopProofSHA256)
	} else if receipt.StartupOnly {
		err = validateFixtureStartup(directory, r, receipt)
	} else {
		err = validateFixtureCleanup(directory, r, receipt.CleanupSHA256)
	}
	if err != nil {
		return result, err
	}
	now, err := ReadClock()
	if err != nil {
		return result, err
	}
	prior, err := s.Attempt(r.Attempt.ID)
	if err != nil {
		return result, err
	}
	if prior.CleanupConfirmed {
		if !receipt.CleanupConfirmed || (prior.ControlCommitted && prior.FinalSHA256 != receipt.FinalSHA256) {
			return result, Invalid
		}
		return RuntimeResult{UpdateID: prior.ID, ControlCommitted: prior.ControlCommitted, StopConfirmed: prior.StopConfirmed, CleanupConfirmed: true}, nil
	}
	var finalErr error
	if receipt.FinalSHA256 != "" {
		body, err = runtimeRead(filepath.Join(directory, "output/final.json"), 1<<20)
		if err != nil || sha256Text(body) != receipt.FinalSHA256 {
			return result, Invalid
		}
		_, finalErr = s.Final(r.Attempt.ID, body, now)
	}
	var nativeReason string
	var reasonErr error
	if !m.FixtureOnly && !receipt.StartupOnly && !prior.AdoptionApproved {
		nativeReason, err = normalRuntimeFailure(directory, r, receipt)
		if err != nil {
			return result, err
		}
		if nativeReason != "" {
			reasonErr = s.recordRuntimeFailure(r.Attempt.ID, nativeReason, now)
		}
	}
	cleaned := receipt.CleanupConfirmed && m.FixtureOnly
	if _, err = s.Stopped(r.Attempt.ID, cleaned, now); err != nil {
		return result, err
	}
	a, err := s.Attempt(r.Attempt.ID)
	if err != nil {
		return result, err
	}
	result.ControlCommitted, result.StopConfirmed, result.CleanupConfirmed = a.ControlCommitted, a.StopConfirmed, a.CleanupConfirmed
	result.Reason = a.Reason
	state := "CLEANUP_PENDING"
	if receipt.CleanupConfirmed && !m.FixtureOnly {
		state = "STOPPED"
	}
	if cleaned {
		state = "FINISHED"
	}
	_, err = s.db.Exec("UPDATE "+table+" SET state=? WHERE update_id=?", state, r.Attempt.ID)
	if err != nil {
		return result, err
	}
	if reasonErr != nil {
		return result, reasonErr
	}
	if nativeReason != "" {
		return result, Error(nativeReason)
	}
	if !receipt.CleanupConfirmed {
		return result, Error("CLEANUP_PENDING")
	}
	return result, finalErr
}

func (s *Store) recordRuntimeFailure(id, reason string, now Clock) error {
	_, err := s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if a.Reason == "" && !a.AdoptionApproved && !a.CleanupConfirmed {
			a.Reason = reason
			return saveAttempt(tx, a)
		}
		return nil
	})
	return err
}

// Normal adoption requires successful native completion in addition to the separately verified stop and cleanup.
func normalRuntimeFailure(directory string, r runtimeRequest, receipt fixtureRuntimeReceipt) (string, error) {
	if err := validateFixtureStop(directory, r, receipt.StopProofSHA256); err != nil {
		return "", err
	}
	output := filepath.Join(directory, "output")
	if receipt.CleanupConfirmed {
		body, err := runtimeRead(filepath.Join(output, "cleanup-complete.json"), 4<<20)
		var complete map[string]json.RawMessage
		if err != nil || sha256Text(body) != receipt.CleanupSHA256 || runtimeJSON(body, &complete) != nil {
			return "", Invalid
		}
		var stopSHA string
		if json.Unmarshal(complete["stop_proof_sha256"], &stopSHA) != nil || stopSHA != receipt.StopProofSHA256 {
			return "", Invalid
		}
	}
	body, err := runtimeRead(filepath.Join(output, "stop-proof.json"), 64<<10)
	var proof map[string]json.RawMessage
	if err != nil || sha256Text(body) != receipt.StopProofSHA256 || runtimeJSON(body, &proof) != nil {
		return "", Invalid
	}
	var kind string
	if json.Unmarshal(proof["kind"], &kind) != nil {
		return "", Invalid
	}
	if kind != "native_guardian" {
		return "INTERRUPTED", nil
	}
	var evidence struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	if runtimeJSON(proof["evidence"], &evidence) != nil || evidence.Path != "watchdog/results.json" {
		return "", Invalid
	}
	body, err = runtimeRead(filepath.Join(output, evidence.Path), 4<<20)
	var native map[string]json.RawMessage
	if err != nil || sha256Text(body) != evidence.SHA256 || runtimeJSON(body, &native) != nil {
		return "", Invalid
	}
	var passed bool
	var terminal struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(native["passed"], &passed) != nil || json.Unmarshal(native["terminal"], &terminal) != nil {
		return "INTERRUPTED", nil
	}
	if passed && terminal.Reason == "EXCHANGE_COMPLETE" {
		return "", nil
	}
	return runtimeReason(Error(terminal.Reason)), nil
}

func validateFixtureStartup(directory string, r runtimeRequest, receipt fixtureRuntimeReceipt) error {
	data, err := runtimeRead(filepath.Join(directory, "output/startup-complete.json"), 16384)
	var value struct {
		Schema              int    `json:"schema"`
		UpdateID            string `json:"update_id"`
		RequestSHA          string `json:"request_sha256"`
		ProducerStopped     bool   `json:"producer_stopped"`
		ResourcesNotCreated bool   `json:"resources_not_created"`
	}
	if err != nil || sha256Text(data) != receipt.CleanupSHA256 || runtimeJSON(data, &value) != nil || value.Schema != 1 || value.UpdateID != r.Attempt.ID || value.RequestSHA != receipt.RequestSHA256 || !value.ProducerStopped || !value.ResourcesNotCreated || receipt.FinalSHA256 != "" {
		return Invalid
	}
	for _, name := range []string{"resource-intent.json", "preparation-owner.json", "native-intent.json", "watchdog"} {
		if _, err = os.Lstat(filepath.Join(directory, "output", name)); !errors.Is(err, os.ErrNotExist) {
			return Invalid
		}
	}
	return nil
}

func validateFixtureCleanup(directory string, r runtimeRequest, digest string) error {
	readEvidence := func(name, expected string) (map[string]json.RawMessage, error) {
		data, err := runtimeRead(filepath.Join(directory, "output", name), 4<<20)
		if err != nil || !digestPattern.MatchString(expected) || sha256Text(data) != expected {
			return nil, Invalid
		}
		var value map[string]json.RawMessage
		if runtimeJSON(data, &value) != nil {
			return nil, Invalid
		}
		return value, nil
	}
	complete, err := readEvidence("cleanup-complete.json", digest)
	if err != nil {
		return err
	}
	getString := func(value map[string]json.RawMessage, key string) string {
		var s string
		_ = json.Unmarshal(value[key], &s)
		return s
	}
	getBool := func(value map[string]json.RawMessage, key string) bool {
		var b bool
		_ = json.Unmarshal(value[key], &b)
		return b
	}
	bound := func(value map[string]json.RawMessage) bool {
		var size int64
		return json.Unmarshal(value["byte_size"], &size) == nil && size == r.ByteSize && getString(value, "job_id") == r.JobID &&
			getString(value, "attempt_id") == r.AttemptID && getString(value, "input_sha256") == r.ExpectedSHA
	}
	if len(complete) != 10 || !bound(complete) || !getBool(complete, "raw_reclaimed") || !getBool(complete, "external_directories_reclaimed") {
		return Invalid
	}
	intent, err := readEvidence("cleanup-intent.json", getString(complete, "cleanup_intent_sha256"))
	if err != nil || len(intent) != 9 || !bound(intent) || getString(intent, "stop_proof_sha256") != getString(complete, "stop_proof_sha256") || getString(intent, "kind") != getString(complete, "kind") {
		return Invalid
	}
	proof, err := readEvidence("stop-proof.json", getString(complete, "stop_proof_sha256"))
	if err != nil || !bound(proof) || !getBool(proof, "stopped") || getString(proof, "kind") != getString(complete, "kind") {
		return Invalid
	}
	if err = validateFixtureStop(directory, r, getString(complete, "stop_proof_sha256")); err != nil {
		return err
	}
	var evidence struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	if runtimeJSON(proof["evidence"], &evidence) != nil {
		return Invalid
	}
	expected := map[string]string{"native_guardian": "watchdog/results.json", "native_stopped_group": "watchdog/results.json", "native_unstarted": "watchdog/results.json",
		"native_prelaunch": "native-recovery.json", "native_previous_boot": "native-previous-boot.json", "prepare_unstarted": "preparation-owner.json", "resources_unstarted": "resource-intent.json"}
	if evidence.Path != expected[getString(proof, "kind")] || evidence.Path == "" {
		return Invalid
	}
	if _, err = readEvidence(evidence.Path, evidence.SHA256); err != nil {
		return err
	}
	if _, err = readEvidence("slot-owner.json", getString(intent, "slot_owner_sha256")); err != nil {
		return err
	}
	var directories []struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(intent["directories"], &directories) != nil {
		return Invalid
	}
	for _, item := range directories {
		if _, err = os.Lstat(item.Path); !errors.Is(err, os.ErrNotExist) {
			return Error("CLEANUP_PENDING")
		}
	}
	return nil
}

func validateFixtureStop(directory string, r runtimeRequest, expectedSHA string) error {
	data, err := runtimeRead(filepath.Join(directory, "output/stop-proof.json"), 64<<10)
	var p struct {
		Schema    int    `json:"schema"`
		JobID     string `json:"job_id"`
		AttemptID string `json:"attempt_id"`
		InputSHA  string `json:"input_sha256"`
		ByteSize  int64  `json:"byte_size"`
		Kind      string `json:"kind"`
		Stopped   bool   `json:"stopped"`
		Evidence  struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"evidence"`
		Checks map[string]bool `json:"checks"`
	}
	if err != nil || !digestPattern.MatchString(expectedSHA) || sha256Text(data) != expectedSHA || runtimeJSON(data, &p) != nil || p.Schema != 1 || p.JobID != r.JobID || p.AttemptID != r.AttemptID || p.InputSHA != r.ExpectedSHA || p.ByteSize != r.ByteSize || !p.Stopped {
		return Invalid
	}
	paths := map[string]string{"native_guardian": "watchdog/results.json", "native_stopped_group": "watchdog/results.json", "native_unstarted": "watchdog/results.json", "native_prelaunch": "native-recovery.json", "native_previous_boot": "native-previous-boot.json", "prepare_unstarted": "preparation-owner.json", "resources_unstarted": "resource-intent.json"}
	checks := map[string][]string{"native_guardian": {"identities_stopped", "service_absent", "guardian_verified"}, "native_stopped_group": {"identities_stopped", "group_empty", "service_absent"}, "native_unstarted": {"terminal_empty", "transfer_disabled", "watchdog_stopped", "service_absent"}, "native_prelaunch": {"producer_stopped", "bootstrap_not_started", "service_absent"}, "native_previous_boot": {"boot_changed", "producer_stopped", "service_absent"}, "prepare_unstarted": {"leader_stopped", "group_empty"}, "resources_unstarted": {"producer_stopped", "prepare_not_started"}}
	if p.Evidence.Path == "" || p.Evidence.Path != paths[p.Kind] || len(p.Checks) != len(checks[p.Kind]) {
		return Invalid
	}
	for _, key := range checks[p.Kind] {
		if !p.Checks[key] {
			return Invalid
		}
	}
	data, err = runtimeRead(filepath.Join(directory, "output", p.Evidence.Path), 4<<20)
	if err != nil || !digestPattern.MatchString(p.Evidence.SHA256) || sha256Text(data) != p.Evidence.SHA256 {
		return Invalid
	}
	if p.Kind == "native_guardian" || p.Kind == "native_stopped_group" || p.Kind == "native_unstarted" {
		var native map[string]json.RawMessage
		if runtimeJSON(data, &native) != nil {
			return Invalid
		}
		for _, key := range []string{"cleanup_all_exited", "temporary_service_absent"} {
			var value bool
			if json.Unmarshal(native[key], &value) != nil || !value {
				return Invalid
			}
		}
		var emergency bool
		if value, exists := native["emergency_owned_cleanup"]; exists {
			if json.Unmarshal(value, &emergency) != nil || emergency {
				return Invalid
			}
		}
		var rows []struct {
			SameIdentityLive *bool `json:"same_identity_live"`
		}
		if json.Unmarshal(native["cleanup_after"], &rows) != nil || len(rows) == 0 || len(rows) > 8 {
			return Invalid
		}
		for _, row := range rows {
			if row.SameIdentityLive == nil || *row.SameIdentityLive {
				return Invalid
			}
		}
		var guardian bool
		_ = json.Unmarshal(native["guardian_result_verified"], &guardian)
		var terminal *struct {
			AllExited bool `json:"all_exited"`
		}
		if json.Unmarshal(native["terminal"], &terminal) != nil {
			return Invalid
		}
		if p.Kind == "native_stopped_group" {
			group, e := hostvm.Decode(data)
			if e != nil || terminal != nil {
				return Invalid
			}
			if _, e = hostvm.StoppedGroupIdentities(group); e != nil {
				return Invalid
			}
		} else if p.Kind == "native_guardian" && !guardian {
			return Invalid
		} else if terminal != nil && !terminal.AllExited {
			return Invalid
		} else if p.Kind == "native_unstarted" && terminal == nil {
			return Invalid
		}
	}
	if len(p.Kind) >= 7 && p.Kind[:7] == "native_" {
		data, err = runtimeRead(filepath.Join(directory, "output/native-intent.json"), 64<<10)
		var plan struct {
			Config struct {
				OwnerKind string `json:"owner_kind"`
				Started   uint64 `json:"continuous_start_ns"`
				Deadline  uint64 `json:"continuous_deadline_ns"`
			} `json:"config"`
		}
		if err != nil || json.Unmarshal(data, &plan) != nil || plan.Config.OwnerKind != "update" || plan.Config.Started != r.Attempt.Started.ContinuousNS || plan.Config.Deadline != r.Attempt.DeadlineContinuousNS {
			return Invalid
		}
	}
	return nil
}
