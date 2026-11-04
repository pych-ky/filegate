package broker

import (
	"bytes"
	"encoding/json"
)

type ScanProgress struct {
	SchemaVersion        int    `json:"schema_version"`
	Sequence             int    `json:"sequence"`
	Stage                string `json:"stage"`
	ManifestComplete     bool   `json:"manifest_complete"`
	FormatTargetCount    *int   `json:"format_target_count"`
	FormatCompletedCount *int   `json:"format_completed_count"`
	AVInputCount         *int   `json:"av_input_count"`
	AVNormalResultCount  *int   `json:"av_normal_result_count"`
}

func (b *Broker) scanProgress(run *scanRun, body json.RawMessage) error {
	var value ScanProgress
	if len(body) > 1024 || strictJSON(body, &value) != nil {
		return failure("REPORT_VALIDATION_FAILED", 503)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 8 {
		return failure("REPORT_VALIDATION_FAILED", 503)
	}
	for index, name := range []string{"schema_version", "sequence", "stage", "manifest_complete", "format_target_count", "format_completed_count", "av_input_count", "av_normal_result_count"} {
		raw, exists := fields[name]
		if !exists || index < 4 && bytes.Equal(raw, []byte("null")) {
			return failure("REPORT_VALIDATION_FAILED", 503)
		}
	}
	if value.SchemaVersion != 1 || value.Sequence < 1 || value.Sequence > 3 {
		return failure("REPORT_VALIDATION_FAILED", 503)
	}
	if value.Sequence == 1 {
		if value.Stage != "format" || value.ManifestComplete || value.FormatTargetCount != nil || value.FormatCompletedCount != nil || value.AVInputCount != nil || value.AVNormalResultCount != nil {
			return failure("REPORT_VALIDATION_FAILED", 503)
		}
	} else {
		if !value.ManifestComplete || value.FormatTargetCount == nil || value.FormatCompletedCount == nil || value.AVInputCount == nil || value.AVNormalResultCount == nil ||
			*value.FormatTargetCount < 1 || *value.FormatTargetCount > 10001 || *value.FormatCompletedCount != *value.FormatTargetCount ||
			*value.AVInputCount < 1 || *value.AVInputCount > *value.FormatTargetCount || *value.AVNormalResultCount < 0 || *value.AVNormalResultCount > *value.AVInputCount ||
			value.Sequence == 2 && (value.Stage != "av" || *value.AVNormalResultCount != 0) || value.Sequence == 3 && value.Stage != "finalizing" {
			return failure("REPORT_VALIDATION_FAILED", 503)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.scanActive != run || run.progress == nil && value.Sequence != 1 || run.progress != nil && value.Sequence != run.progress.Sequence+1 {
		return failure("REPORT_VALIDATION_FAILED", 503)
	}
	if run.progress != nil && run.progress.ManifestComplete && (*run.progress.FormatTargetCount != *value.FormatTargetCount || *run.progress.AVInputCount != *value.AVInputCount) {
		return failure("REPORT_VALIDATION_FAILED", 503)
	}
	run.progress = &value
	return nil
}

func (b *Broker) progressMatchesReport(run *scanRun, report scanReport) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := run.progress
	return p == nil || !p.ManifestComplete || report.ManifestComplete &&
		*p.FormatTargetCount == len(report.Result.Manifest) && *p.AVInputCount == report.Result.RequiredAVInputCount &&
		(p.Sequence != 3 || *p.AVNormalResultCount == report.avValidation.NormalResultCount)
}

// Live observations are projected only for the current run, never stored in attempts.
func (b *Broker) projectScanProgress(job *Job) {
	job.Progress = nil
	if run := b.scanActive; !job.Terminal() && run != nil && run.job.JobID == job.JobID && run.job.AttemptID == job.AttemptID && run.progress != nil {
		value := *run.progress
		job.Progress = &value
	}
}
