package broker

import (
	"context"
	"database/sql"
	"errors"
)

type ScanDetails struct {
	ManifestComplete     bool          `json:"manifest_complete"`
	FormatTargetCount    *int          `json:"format_target_count"`
	FormatCompletedCount *int          `json:"format_completed_count"`
	AVInputCount         int           `json:"av_input_count"`
	AVNormalResultCount  int           `json:"av_normal_result_count"`
	Versions             *ScanVersions `json:"versions,omitempty"`
}

type ScanVersions struct {
	PolicyID              string `json:"policy_id"`
	HostSHA256            string `json:"host_sha256"`
	WorkerSHA256          string `json:"worker_sha256"`
	BuildSHA256           string `json:"build_sha256"`
	FormatsSHA256         string `json:"formats_sha256"`
	AVProfileID           string `json:"av_profile_id"`
	Engine                string `json:"engine"`
	EngineSHA256          string `json:"engine_sha256"`
	ScannerManifestSHA256 string `json:"scanner_manifest_sha256"`
	ConfigurationSHA256   string `json:"configuration_sha256"`
	DefinitionsSHA256     string `json:"definitions_sha256"`
	ObservationsSHA256    string `json:"observations_sha256"`
	DefinitionUpdateID    string `json:"definition_update_id"`
	DefinitionGeneration  int64  `json:"definition_generation"`
}

func scanDetailsForReport(ctx context.Context, q queryer, run *scanRun, report scanReport) (*ScanDetails, error) {
	r := report.Result
	details := &ScanDetails{ManifestComplete: report.ManifestComplete, AVInputCount: r.RequiredAVInputCount,
		AVNormalResultCount: report.avValidation.NormalResultCount}
	if report.ManifestComplete && r.StructureStatus == "ACCEPT_FORMAT_STRUCTURE" && r.StructureChecksComplete && r.FormatChecksComplete {
		count := len(r.Manifest)
		details.FormatTargetCount, details.FormatCompletedCount = &count, &count
	}
	if run.definition == nil {
		return details, nil
	}
	var body []byte
	err := q.QueryRowContext(ctx, "SELECT data FROM scan_release_snapshots WHERE attempt_id=?", run.job.AttemptID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return details, nil
	}
	if err != nil {
		return nil, storageError()
	}
	var snapshot scanReleaseSnapshot
	if len(body) > 256<<10 || strictJSONKeys(body, &snapshot, 4096) != nil || snapshot.Schema != 1 ||
		snapshot.AttemptID != run.job.AttemptID || run.job.InputReceipt == nil || snapshot.Object != *run.job.InputReceipt || snapshot.Policy != report.PolicyDigest {
		return details, nil
	}
	definition, binding := run.definition, run.definition.Binding
	versions := &ScanVersions{PolicyID: snapshot.Policy, HostSHA256: snapshot.Pins[snapshot.Host].SHA256,
		WorkerSHA256: snapshot.WorkerSHA256, BuildSHA256: snapshot.BuildSHA256, FormatsSHA256: snapshot.FormatsSHA256,
		AVProfileID: definition.Profile.ProfileID, Engine: "ClamAV 1.4.6", EngineSHA256: binding.BinarySHA256,
		ScannerManifestSHA256: binding.ScannerManifestSHA256, ConfigurationSHA256: binding.ConfigurationSHA256,
		DefinitionsSHA256: binding.DefinitionSetSHA256, ObservationsSHA256: binding.ObservationSHA256,
		DefinitionUpdateID: definition.UpdateID, DefinitionGeneration: definition.Generation}
	for _, digest := range []string{versions.HostSHA256, versions.WorkerSHA256, versions.BuildSHA256, versions.FormatsSHA256,
		versions.EngineSHA256, versions.ScannerManifestSHA256, versions.ConfigurationSHA256, versions.DefinitionsSHA256, versions.ObservationsSHA256} {
		if !validDigest(digest) {
			return details, nil
		}
	}
	details.Versions = versions
	return details, nil
}
