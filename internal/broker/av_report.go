package broker

import (
	"bytes"
	"encoding/json"

	"filegate.local/filegate/internal/av"
)

type avReportValidation struct {
	NormalResultCount   int
	ConfirmedRejections []formatRejection
}

func validateAVFields(body json.RawMessage) error {
	names := []string{"schema_version", "profile_id", "process_status", "av_result", "results_complete", "binding_verified", "binding", "required_input_count", "normal_result_count", "exit_code", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256", "reason_codes", "objects", "confirmed_detections"}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != len(names) {
		return failure("REPORT_VALIDATION_FAILED", 409)
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || (bytes.Equal(value, []byte("null")) && name != "binding" && name != "exit_code") {
			return failure("REPORT_VALIDATION_FAILED", 409)
		}
	}
	if !bytes.Equal(fields["binding"], []byte("null")) {
		if _, err := requiredFields(fields["binding"], "profile_sha256", "scanner_manifest_sha256", "binary_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only"); err != nil {
			return failure("REPORT_VALIDATION_FAILED", 409)
		}
	}
	for _, name := range []string{"reason_codes", "objects", "confirmed_detections"} {
		var values []json.RawMessage
		if json.Unmarshal(fields[name], &values) != nil || values == nil {
			return failure("REPORT_VALIDATION_FAILED", 409)
		}
		for _, value := range values {
			var err error
			switch name {
			case "reason_codes":
				var reason string
				if bytes.Equal(value, []byte("null")) || json.Unmarshal(value, &reason) != nil {
					return failure("REPORT_VALIDATION_FAILED", 409)
				}
			case "objects":
				_, err = requiredFields(value, "object_id", "sha256", "byte_size", "status", "reason_code", "signature_sha256", "input_verified", "normal_result_present")
			case "confirmed_detections":
				_, err = requiredFields(value, "object_id", "sha256", "byte_size", "reason_code", "signature_sha256")
			}
			if err != nil {
				return failure("REPORT_VALIDATION_FAILED", 409)
			}
		}
	}
	return nil
}

func validateAVReport(r formatResult, a av.Result, expected *av.Binding) (avReportValidation, error) {
	invalid := func() (avReportValidation, error) {
		return avReportValidation{}, failure("REPORT_VALIDATION_FAILED", 409)
	}
	validated := avReportValidation{ConfirmedRejections: []formatRejection{}}
	if a.SchemaVersion != 1 || a.ProfileID != av.ProfileID || a.ReasonCodes == nil || a.Objects == nil || a.ConfirmedDetections == nil {
		return invalid()
	}
	if a.ProcessStatus == "not_started" {
		if a.AVResult != "inconclusive" || a.ResultsComplete || a.BindingVerified || a.Binding != nil || a.RequiredInputCount != 0 || a.NormalResultCount != 0 || a.ExitCode != nil || a.StdoutBytes != 0 || a.StdoutSHA256 != "" || a.StderrBytes != 0 || a.StderrSHA256 != "" || len(a.Objects) != 0 || len(a.ConfirmedDetections) != 0 || len(a.ReasonCodes) != 1 || a.ReasonCodes[0] != "INCOMPLETE_REQUIRED_CHECKS" {
			return invalid()
		}
		return validated, nil
	}
	// The expected binding comes from dispatch state, never from the report itself.
	if expected == nil || a.Binding == nil || *a.Binding != *expected || a.Binding.BinarySHA256 != av.BinarySHA256 || a.Binding.ConfigurationSHA256 != av.ConfigurationSHA256 {
		return invalid()
	}
	for _, digest := range []string{a.Binding.ProfileSHA256, a.Binding.ScannerManifestSHA256, a.Binding.BinarySHA256, a.Binding.ConfigurationSHA256, a.Binding.DefinitionSetSHA256, a.Binding.ObservationSHA256} {
		if !validDigest(digest) {
			return invalid()
		}
	}
	if r.StructureStatus != "ACCEPT_FORMAT_STRUCTURE" || !r.StructureChecksComplete || !r.FormatChecksComplete || r.RequiredAVInputCount < 1 || r.RequiredAVInputCount > 10001 || a.RequiredInputCount != r.RequiredAVInputCount || len(a.Objects) != a.RequiredInputCount {
		return invalid()
	}
	required := make(map[string]formatObject, r.RequiredAVInputCount)
	for _, object := range r.Manifest {
		if object.AVRequired {
			if _, duplicate := required[object.ID]; duplicate {
				return invalid()
			}
			required[object.ID] = object
		}
	}
	if len(required) != a.RequiredInputCount {
		return invalid()
	}
	if a.ExitCode == nil {
		if a.ProcessStatus != "failed" || a.BindingVerified || a.StdoutBytes != 0 || a.StdoutSHA256 != "" || a.StderrBytes != 0 || a.StderrSHA256 != "" {
			return invalid()
		}
	} else {
		exit := *a.ExitCode
		if exit < -1 || exit > 2 || !avStream(a.StdoutBytes, a.StdoutSHA256, (4<<20)+1) || !avStream(a.StderrBytes, a.StderrSHA256, (1<<20)+1) {
			return invalid()
		}
	}
	reasons := make(map[string]bool)
	switch a.ProcessStatus {
	case "completed":
		if a.ExitCode == nil || (*a.ExitCode != 0 && *a.ExitCode != 1) || !a.BindingVerified || a.StdoutBytes > 4<<20 || a.StderrBytes != 0 {
			return invalid()
		}
	case "failed":
		reasons["SCANNER_ERROR"] = true
	case "timed_out":
		if a.ExitCode == nil {
			return invalid()
		}
		reasons["SCAN_TIMEOUT"] = true
	default:
		return invalid()
	}
	if !a.BindingVerified {
		reasons["SCANNER_ERROR"] = true
	}
	complete, allClean, found := true, true, false
	detections := make(map[string]av.Detection)
	for _, object := range a.Objects {
		input, exists := required[object.ObjectID]
		if !exists || object.SHA256 != input.SHA256 || object.ByteSize != input.ByteSize {
			return invalid()
		}
		delete(required, object.ObjectID)
		if a.ExitCode == nil && (object.Status != "pending" || object.InputVerified || object.NormalResultPresent) {
			return invalid()
		}
		if object.NormalResultPresent {
			validated.NormalResultCount++
		}
		if !object.NormalResultPresent || !object.InputVerified {
			complete = false
		}
		if object.Status != "clean" {
			allClean = false
		}
		switch object.Status {
		case "pending":
			if object.ReasonCode != "INCOMPLETE_REQUIRED_CHECKS" || object.SignatureSHA256 != "" || object.NormalResultPresent {
				return invalid()
			}
			complete = false
		case "clean":
			if object.ReasonCode != "" || object.SignatureSHA256 != "" || !object.NormalResultPresent || !object.InputVerified {
				return invalid()
			}
		case "detected":
			if object.ReasonCode != "MALWARE_DETECTED" || !validDigest(object.SignatureSHA256) || !object.NormalResultPresent || !object.InputVerified || a.ExitCode == nil || *a.ExitCode == 0 {
				return invalid()
			}
			found = true
			if a.BindingVerified {
				detections[object.ObjectID] = av.Detection{ObjectID: object.ObjectID, SHA256: object.SHA256, ByteSize: object.ByteSize, ReasonCode: object.ReasonCode, SignatureSHA256: object.SignatureSHA256}
			}
		case "hold":
			if (object.ReasonCode != "LIMIT_EXCEEDED" && object.ReasonCode != "ENCRYPTED_ARCHIVE" && object.ReasonCode != "ACTIVE_CONTENT_REQUIRES_REVIEW" && object.ReasonCode != "SCANNER_ERROR") || !validDigest(object.SignatureSHA256) || !object.NormalResultPresent || !object.InputVerified {
				return invalid()
			}
			found, complete = true, false
		case "error":
			if (object.ReasonCode != "SCANNER_ERROR" && object.ReasonCode != "INPUT_HASH_MISMATCH") || object.SignatureSHA256 != "" || (object.NormalResultPresent && !object.InputVerified) {
				return invalid()
			}
			if object.ReasonCode == "INPUT_HASH_MISMATCH" {
				if object.InputVerified || object.NormalResultPresent {
					return invalid()
				}
				reasons["SCANNER_ERROR"] = true
			}
			complete = false
		default:
			return invalid()
		}
		if object.ReasonCode != "" && object.ReasonCode != "MALWARE_DETECTED" {
			reasons[object.ReasonCode] = true
		}
		if a.ProcessStatus == "completed" && (!object.NormalResultPresent || !object.InputVerified || object.Status == "pending" || object.Status == "error") {
			return invalid()
		}
	}
	if len(required) != 0 || validated.NormalResultCount != a.NormalResultCount || len(detections) != len(a.ConfirmedDetections) {
		return invalid()
	}
	if a.ProcessStatus == "completed" && ((*a.ExitCode == 0 && !allClean) || (*a.ExitCode == 1 && !found)) {
		return invalid()
	}
	for _, detection := range a.ConfirmedDetections {
		expected, exists := detections[detection.ObjectID]
		if !exists || detection != expected {
			return invalid()
		}
		delete(detections, detection.ObjectID)
		validated.ConfirmedRejections = append(validated.ConfirmedRejections, formatRejection{ObjectID: detection.ObjectID, ReasonCode: detection.ReasonCode})
	}
	if len(a.ReasonCodes) != len(reasons) {
		return invalid()
	}
	for _, reason := range a.ReasonCodes {
		if !reasons[reason] {
			return invalid()
		}
		delete(reasons, reason)
	}
	complete = complete && a.BindingVerified && a.ProcessStatus == "completed" && len(a.ReasonCodes) == 0
	result := "inconclusive"
	if len(validated.ConfirmedRejections) != 0 {
		result = "detected"
	} else if complete && allClean {
		result = "clean"
	}
	if a.ResultsComplete != complete || a.AVResult != result {
		return invalid()
	}
	return validated, nil
}

func avStream(size int64, digest string, limit int64) bool {
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	return size >= 0 && size <= limit && validDigest(digest) && (size != 0 || digest == emptySHA256)
}
