package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	updatecontrol "filegate.local/filegate/internal/update"
)

func completeScanReport(report scanReport) bool {
	r, a := report.Result, report.AV
	return report.ReportComplete && report.ManifestComplete && r.StructureStatus == "ACCEPT_FORMAT_STRUCTURE" &&
		r.StructureChecksComplete && r.FormatChecksComplete && len(r.Manifest) != 0 && len(r.Reasons) == 0 &&
		len(r.ConfirmedRejections) == 0 && a.ProcessStatus == "completed" && a.AVResult == "clean" && a.ResultsComplete &&
		a.BindingVerified && a.Binding != nil && !a.Binding.FixtureDefinitionsOnly && a.ExitCode != nil && *a.ExitCode == 0 &&
		len(a.ReasonCodes) == 0 && len(a.ConfirmedDetections) == 0 && a.RequiredInputCount == r.RequiredAVInputCount &&
		a.NormalResultCount == r.RequiredAVInputCount && report.avValidation.NormalResultCount == r.RequiredAVInputCount
}

func (b *Broker) readScanRelease(attempt string) (scanReleaseSnapshot, error) {
	var snapshot scanReleaseSnapshot
	var body []byte
	err := b.db.QueryRow("SELECT data FROM scan_release_snapshots WHERE attempt_id=?", attempt).Scan(&body)
	if err != nil || len(body) > 1<<20 || strictJSONKeys(body, &snapshot, 4096) != nil ||
		(snapshot.Schema != 1 && snapshot.Schema != 2) || snapshot.Schema == 1 && len(body) > 256<<10 || snapshot.AttemptID != attempt {
		return snapshot, failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	}
	return snapshot, nil
}

func (b *Broker) validateScanRelease(run *scanRun, report scanReport) (scanReleaseSnapshot, error) {
	s, err := b.readScanRelease(run.job.AttemptID)
	invalid := failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	if err != nil || run.definition == nil || !completeScanReport(report) || run.job.InputReceipt == nil ||
		s.Object != *run.job.InputReceipt || s.Policy != report.PolicyDigest || !s.current() ||
		*report.AV.Binding != run.definition.Binding {
		return s, invalid
	}
	vm := b.config.VM
	if vm == nil || s.Pins[vm.RunnerPath].SHA256 != b.runnerSHA || s.Pins[vm.Proof].SHA256 != b.proofSHA {
		return s, invalid
	}
	requestBody, err := readPrivate(filepath.Join(run.directory, "request.json"), 64<<10)
	var request scanRequest
	if err != nil || strictJSON(requestBody, &request) != nil || request.SchemaVersion != 3 || request.JobID != run.job.JobID ||
		request.AttemptID != s.AttemptID || request.PolicyDigest != s.Policy || request.ExpectedSHA256 != s.Object.SHA256 ||
		request.ByteSize != s.Object.ByteSize || request.InputPath != filepath.Join(b.config.DataDir, "objects", s.Object.ObjectID) ||
		!bytes.Equal(encode(request.Definition), encode(run.definition)) {
		return s, invalid
	}
	output := filepath.Join(run.directory, "output")
	body, err := readPrivate(filepath.Join(output, "prepared.json"), 64<<10)
	var prepared struct {
		Schema       int                           `json:"schema"`
		BlockIOFault bool                          `json:"block_io_fault"`
		QEMU         string                        `json:"qemu_sha256"`
		Images       map[string]string             `json:"images_before"`
		Boot         map[string]string             `json:"boot_artifacts"`
		Definition   *updatecontrol.ScanDefinition `json:"definition"`
	}
	base := filepath.Join(vm.Workspace, "experiments/vm")
	if err != nil || json.Unmarshal(body, &prepared) != nil || prepared.Schema != 3 || prepared.BlockIOFault ||
		!bytes.Equal(encode(prepared.Definition), encode(run.definition)) || prepared.QEMU != s.Pins[s.QEMU].SHA256 ||
		len(prepared.Images) != 2 || prepared.Images["base"] != s.Pins[filepath.Join(base, ".build/base.ext4")].SHA256 ||
		prepared.Images["definitions"] != run.definition.Image.SHA256 || len(prepared.Boot) != 2 ||
		prepared.Boot["kernel"] != s.Pins[filepath.Join(base, ".cache/boot/vmlinuz-virt")].SHA256 ||
		prepared.Boot["initramfs"] != s.Pins[filepath.Join(base, ".build/initramfs.cpio.gz")].SHA256 {
		return s, invalid
	}
	var native struct {
		Schema    int             `json:"schema"`
		JobID     string          `json:"job_id"`
		AttemptID string          `json:"attempt_id"`
		InputSHA  string          `json:"input_sha256"`
		ByteSize  int64           `json:"byte_size"`
		Boot      string          `json:"boot_session_uuid"`
		Config    json.RawMessage `json:"config"`
	}
	body, err = readPrivate(filepath.Join(output, "native-intent.json"), 64<<10)
	if err != nil || json.Unmarshal(body, &native) != nil || native.Schema != 2 || native.JobID != request.JobID ||
		native.AttemptID != s.AttemptID || native.InputSHA != s.Object.SHA256 || native.ByteSize != s.Object.ByteSize {
		return s, invalid
	}
	var config struct {
		Mode               string            `json:"mode"`
		Owner              string            `json:"owner_kind"`
		Fixture            string            `json:"fixture"`
		Start              uint64            `json:"continuous_start_ns"`
		Deadline           uint64            `json:"continuous_deadline_ns"`
		HelperPins         map[string]string `json:"helper_pins"`
		QEMU               string            `json:"qemu_sha256"`
		RequireLaunchAgent bool              `json:"require_launchagent"`
	}
	if json.Unmarshal(native.Config, &config) != nil || config.Mode != "qemu" || config.Owner != "scan" ||
		config.Fixture != "product-inspect" || !config.RequireLaunchAgent || config.QEMU != s.Pins[s.QEMU].SHA256 ||
		config.Start < s.Captured.ContinuousNS || config.Deadline-config.Start != 300_000_000_000 || native.Boot != s.Captured.Boot {
		return s, invalid
	}
	confirmed := run.definition.Confirmed
	if confirmed.Boot != native.Boot || config.Start < confirmed.ContinuousNS || config.Start-confirmed.ContinuousNS > 86_400_000_000_000 ||
		s.Captured.UTC < confirmed.UTC || s.Captured.UTC-confirmed.UTC > 86400 {
		return s, invalid
	}
	expectedPins := []string{vm.RunnerPath, filepath.Join(base, ".build/filegate-bridge"), filepath.Join(base, "fixtures.json"),
		filepath.Join(base, ".cache/boot/vmlinuz-virt"), filepath.Join(base, ".build/initramfs.cpio.gz"),
		filepath.Join(base, ".build/base.ext4"), run.definition.ImagePath, filepath.Join(base, "evidence/build.json")}
	if len(config.HelperPins) != len(expectedPins) {
		return s, invalid
	}
	for _, path := range expectedPins {
		expected, ok := s.Pins[path]
		if !ok || config.HelperPins[path] != expected.SHA256 {
			return s, invalid
		}
	}
	configBody, err := readPrivate(filepath.Join(output, "watchdog/config.json"), 64<<10)
	if err != nil {
		return s, invalid
	}
	actual, actualErr := canonicalRuntimeConfig(configBody)
	planned, plannedErr := canonicalRuntimeConfig(native.Config)
	if actualErr != nil || plannedErr != nil || !bytes.Equal(actual, planned) {
		return s, invalid
	}
	summary, err := readRuntimeSummary(run)
	if err != nil || !summary.Passed || !summary.ReportAccepted || summary.ReportSHA256 == nil || summary.NativeEvidence == nil || summary.Termination.ReasonCode != "EXCHANGE_COMPLETE" {
		return s, invalid
	}
	summaryBody, err := readPrivate(filepath.Join(output, "results.json"), 64<<10)
	if err != nil || !bytes.Equal(encode(summary), canonicalRuntimeSummary(summaryBody)) {
		return s, invalid
	}
	s.ReportSHA256 = *summary.ReportSHA256
	s.SummarySHA256 = releaseDigest(summaryBody)
	return s, nil
}

func canonicalRuntimeConfig(body []byte) ([]byte, error) {
	var checked json.RawMessage
	if err := strictJSONKeys(body, &checked, 4096); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func canonicalRuntimeSummary(body []byte) []byte {
	var value runtimeSummary
	if strictJSON(body, &value) != nil {
		return nil
	}
	return encode(value)
}

func (b *Broker) authorizedReleaseBinding(ctx context.Context, j Job) (releaseBinding, error) {
	invalid := failure("INCOMPLETE_REQUIRED_CHECKS", 409)
	if j.Phase != "FINISHED" || j.IntakeStatus != "COMMITTED" || len(j.ExecutionErrors) != 0 || len(j.ReasonCodes) != 0 ||
		len(j.ConfirmedRejections) != 0 || b.updates == nil || !b.updates.enabled || b.config.VM == nil {
		return releaseBinding{}, invalid
	}
	var attemptBody []byte
	if b.db.QueryRowContext(ctx, "SELECT data FROM attempts WHERE id=? AND job_id=?", j.AttemptID, j.JobID).Scan(&attemptBody) != nil {
		return releaseBinding{}, invalid
	}
	var attempt Job
	if strictJSON(attemptBody, &attempt) != nil {
		return releaseBinding{}, invalid
	}
	attempt.Release, j.Release = ReleaseEligibility{}, ReleaseEligibility{}
	attempt.NextAllowedAt, j.NextAllowedAt = nil, nil
	attempt.DisplayName, j.DisplayName = "", ""
	if !bytes.Equal(encode(attempt), encode(j)) {
		return releaseBinding{}, invalid
	}
	var object InputReceipt
	var available int
	if b.db.QueryRowContext(ctx, "SELECT id,sha256,size,available FROM objects WHERE id=? AND job_id=?", j.InputReceipt.ObjectID, j.JobID).Scan(&object.ObjectID, &object.SHA256, &object.ByteSize, &available) != nil {
		return releaseBinding{}, invalid
	}
	object.ContentAvailable = available == 1
	if object != *j.InputReceipt {
		return releaseBinding{}, failure("INPUT_MISSING", 409)
	}
	var directory, state, reportSHA string
	var reserved, written int64
	var cancelled int
	if b.db.QueryRowContext(ctx, "SELECT directory,state,report_sha256,raw_reserved,raw_written,cancel_requested FROM runtime_runs WHERE attempt_id=? AND job_id=?", j.AttemptID, j.JobID).Scan(&directory, &state, &reportSHA, &reserved, &written, &cancelled) != nil ||
		directory != filepath.Join(b.config.DataDir, "runtime", j.AttemptID) || state != "FINISHED" || reserved != 0 || written != 0 || cancelled != 0 {
		return releaseBinding{}, invalid
	}
	definition, err := b.readScanDefinition(j.AttemptID)
	if err != nil || definition == nil {
		return releaseBinding{}, invalid
	}
	saved, err := b.readScanRelease(j.AttemptID)
	if err != nil || !validDigest(saved.ReportSHA256) || !validDigest(saved.SummarySHA256) {
		return releaseBinding{}, invalid
	}
	if !saved.current() {
		return releaseBinding{}, failure("REVALIDATION_REQUIRED", 409)
	}
	report, digest, err := decodeReport(filepath.Join(directory, "output/report.json"), j, &definition.Binding)
	if err != nil || digest != reportSHA || digest != saved.ReportSHA256 || j.Coverage.ProfileID != report.AV.ProfileID ||
		j.Coverage.AVProcessStatus != "completed" || j.Coverage.AVResult != "clean" || j.Coverage.RequiredAVInputCount != report.Result.RequiredAVInputCount || j.Coverage.AVNormalResultCount != report.avValidation.NormalResultCount {
		return releaseBinding{}, invalid
	}
	run := &scanRun{job: j, directory: directory, definition: definition}
	verified, err := b.validateScanRelease(run, report)
	if err != nil || !bytes.Equal(encode(saved), encode(verified)) {
		return releaseBinding{}, invalid
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return releaseBinding{}, failure("UPDATE_CLOCK_UNCERTAIN", 503)
	}
	current, err := b.updates.store.CurrentScanDefinition(now)
	if err != nil {
		return releaseBinding{}, invalid
	}
	if current.Binding != definition.Binding {
		return releaseBinding{}, failure("REVALIDATION_REQUIRED", 409)
	}
	now, err = updatecontrol.ReadClock()
	if err != nil {
		return releaseBinding{}, failure("UPDATE_CLOCK_UNCERTAIN", 503)
	}
	finished, err := time.Parse(time.RFC3339Nano, j.FinishedAt)
	checked := time.Unix(now.UTC, 0).UTC()
	if err != nil || saved.Finished == nil || !saved.Finished.Valid() || saved.Finished.UTC != finished.Unix() || now.Boot != saved.Finished.Boot ||
		now.ContinuousNS < saved.Finished.ContinuousNS || now.ContinuousNS-saved.Finished.ContinuousNS >= 86_400_000_000_000 ||
		checked.Before(finished) || !checked.Before(finished.Add(24*time.Hour)) {
		return releaseBinding{}, failure("REVALIDATION_REQUIRED", 409)
	}
	a := definition.Binding
	return releaseBinding{AttemptID: j.AttemptID, PolicySHA256: hash(formatPolicy), WorkerSHA256: saved.WorkerSHA256,
		EngineSHA256: a.BinarySHA256, BuildSHA256: releaseDigest(encode([]string{saved.BuildSHA256, a.ScannerManifestSHA256})),
		ConfigSHA256: a.ConfigurationSHA256, DefinitionsSHA256: a.DefinitionSetSHA256, FormatsSHA256: saved.FormatsSHA256,
		ObservationsSHA256: a.ObservationSHA256, ReportSHA256: digest, AuthorizedAt: checked.Format(time.RFC3339Nano),
		ExpiresAt: finished.Add(24 * time.Hour).UTC().Format(time.RFC3339Nano), Format: report.Result.Manifest[0].Format}, nil
}
