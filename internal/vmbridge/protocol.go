package vmbridge

import (
	"path/filepath"
	"regexp"
	"strings"

	"filegate.local/filegate/internal/av"
)

var (
	jobID     = regexp.MustCompile(`^job_[0-9a-f]{32}$`)
	attemptID = regexp.MustCompile(`^attempt_[0-9a-f]{32}$`)
)

func request(path, expected string) (object, error) {
	v, body, err := readControl(path, requestLimit)
	if err != nil || !validDigest(expected) || digest(body) != expected {
		return nil, errInvalid
	}
	m, ok := v.(object)
	if !ok {
		return nil, errInvalid
	}
	keys := "schema_version job_id attempt_id policy_digest input_path expected_sha256 byte_size metadata"
	if number(m["schema_version"]) == 3 {
		keys += " definition"
	}
	j, jOK := m["job_id"].(string)
	a, aOK := m["attempt_id"].(string)
	p, pOK := m["input_path"].(string)
	if !fields(m, keys) || !integer(m["schema_version"], 2, 3) || m["policy_digest"] != policy || !jOK || !jobID.MatchString(j) || !aOK || !attemptID.MatchString(a) || !validDigest(m["expected_sha256"]) || !integer(m["byte_size"], 0, inputLimit) || !pOK || strings.ContainsRune(p, 0) || !filepath.IsAbs(p) {
		return nil, errInvalid
	}
	metadata, ok := m["metadata"].(object)
	if !ok {
		return nil, errInvalid
	}
	limits := map[string]int{"display_name": 2048, "declared_media_type": 256, "expected_type": 32}
	for key, item := range metadata {
		text, ok := item.(string)
		limit, known := limits[key]
		if !ok || !known || len(text) > limit {
			return nil, errInvalid
		}
	}
	if number(m["schema_version"]) == 3 && !definition(m["definition"], filepath.Dir(filepath.Dir(p))) {
		return nil, errInvalid
	}
	return m, nil
}

func progress(value any) (object, error) {
	m, ok := value.(object)
	if !ok || !fields(m, "schema_version sequence stage manifest_complete format_target_count format_completed_count av_input_count av_normal_result_count") || !integer(m["schema_version"], 1, 1) || !integer(m["sequence"], 1, 3) || !boolean(m["manifest_complete"]) {
		return nil, errInvalid
	}
	body, err := encoded(m)
	if err != nil || len(body) > 1024 {
		return nil, errInvalid
	}
	if number(m["sequence"]) == 1 {
		if m["stage"] != "format" || m["manifest_complete"] != false || m["format_target_count"] != nil || m["format_completed_count"] != nil || m["av_input_count"] != nil || m["av_normal_result_count"] != nil {
			return nil, errInvalid
		}
	} else {
		if m["manifest_complete"] != true || !integer(m["format_target_count"], 1, 10001) || !integer(m["format_completed_count"], 1, 10001) || number(m["format_target_count"]) != number(m["format_completed_count"]) || !integer(m["av_input_count"], 1, number(m["format_target_count"])) || !integer(m["av_normal_result_count"], 0, number(m["av_input_count"])) {
			return nil, errInvalid
		}
		if number(m["sequence"]) == 2 && (m["stage"] != "av" || number(m["av_normal_result_count"]) != 0) || number(m["sequence"]) == 3 && m["stage"] != "finalizing" {
			return nil, errInvalid
		}
	}
	return m, nil
}

func report(m, req object) error {
	if !fields(m, "schema_version event job_id attempt_id policy_digest input worker_uid report_complete manifest_complete av_process_status av_result result av") || !integer(m["schema_version"], 2, 2) || m["event"] != "product_result" || !integer(m["worker_uid"], 65534, 65534) || m["report_complete"] != true || !boolean(m["manifest_complete"]) || !oneOf(m["av_process_status"], "not_started", "completed", "failed", "timed_out") || !oneOf(m["av_result"], "inconclusive", "clean", "detected") || m["job_id"] != req["job_id"] || m["attempt_id"] != req["attempt_id"] || m["policy_digest"] != req["policy_digest"] || !same(m["input"], object{"sha256": req["expected_sha256"], "byte_size": req["byte_size"]}) {
		return errInvalid
	}
	r, ok := m["result"].(object)
	if !ok || !fields(r, "schema_version structure_status structure_checks_complete format_checks_complete required_checks_complete reason_codes completed_checks archive_entry_count extracted_file_count required_av_input_count extracted_bytes manifest confirmed_rejections") || !integer(r["schema_version"], 1, 1) || !oneOf(r["structure_status"], "ACCEPT_FORMAT_STRUCTURE", "HOLD", "BLOCK") || r["required_checks_complete"] != false || !boolean(r["structure_checks_complete"]) || !boolean(r["format_checks_complete"]) || !integer(r["archive_entry_count"], 0, 10000) || !integer(r["extracted_file_count"], 0, 10000) || !integer(r["required_av_input_count"], 0, 10001) || !integer(r["extracted_bytes"], 0, 1<<30) || !array(r["manifest"], 10001) || !array(r["reason_codes"], 1) || !array(r["completed_checks"], 21) || !array(r["confirmed_rejections"], 1) {
		return errInvalid
	}
	complete := r["structure_status"] == "ACCEPT_FORMAT_STRUCTURE" && r["structure_checks_complete"] == true && r["format_checks_complete"] == true
	reasons := r["reason_codes"].([]any)
	rejections := r["confirmed_rejections"].([]any)
	if m["manifest_complete"] != complete || complete && (len(reasons) != 0 || len(rejections) != 0) {
		return errInvalid
	}
	if r["structure_status"] == "BLOCK" {
		if len(reasons) != 1 || !oneOf(reasons[0], "UNSAFE_ARCHIVE_PATH", "ARCHIVE_NAME_COLLISION", "ARCHIVE_PATH_TYPE_CONFLICT") || len(rejections) != 1 {
			return errInvalid
		}
	} else if len(rejections) != 0 {
		return errInvalid
	}
	a, ok := m["av"].(object)
	if !ok || !fields(a, "schema_version profile_id process_status av_result results_complete binding_verified binding required_input_count normal_result_count exit_code stdout_bytes stdout_sha256 stderr_bytes stderr_sha256 reason_codes objects confirmed_detections") || !integer(a["schema_version"], 1, 1) || a["profile_id"] != av.ProfileID || a["process_status"] != m["av_process_status"] || a["av_result"] != m["av_result"] || !boolean(a["results_complete"]) || !boolean(a["binding_verified"]) || !integer(a["required_input_count"], 0, 10001) || !integer(a["normal_result_count"], 0, 10001) || !integer(a["stdout_bytes"], 0, (4<<20)+1) || !integer(a["stderr_bytes"], 0, (1<<20)+1) || !array(a["reason_codes"], 16) || !array(a["objects"], 10001) || !array(a["confirmed_detections"], 10001) {
		return errInvalid
	}
	if a["process_status"] == "not_started" && (a["av_result"] != "inconclusive" || a["results_complete"] != false || a["binding_verified"] != false || a["binding"] != nil || a["exit_code"] != nil || number(a["required_input_count"]) != 0 || number(a["normal_result_count"]) != 0 || number(a["stdout_bytes"]) != 0 || number(a["stderr_bytes"]) != 0 || a["stdout_sha256"] != "" || a["stderr_sha256"] != "" || len(a["objects"].([]any)) != 0 || len(a["confirmed_detections"].([]any)) != 0 || !same(a["reason_codes"], []string{"INCOMPLETE_REQUIRED_CHECKS"})) {
		return errInvalid
	}
	body, err := encoded(m)
	if err != nil || len(body) > reportLimit {
		return errInvalid
	}
	return nil
}
