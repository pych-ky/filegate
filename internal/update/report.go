package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Final struct {
	UpdateID       string
	BaseGeneration int64
	Snapshot       Snapshot
	SnapshotBytes  []byte
	WaitSeconds    int64
	OriginVerified bool
	SHA256         string
}

func sha256Text(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func ascii(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, c := range value {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func SnapshotBytes(s Snapshot) ([]byte, error) {
	if s.SchemaVersion != 1 || s.Engine != Engine || s.Adapter != Adapter || !uuidPattern.MatchString(s.UUID) ||
		s.RetryAfterUTC < 0 || s.MaxRetryAfterUTC < s.RetryAfterUTC || s.MaxRetryAfterUTC > MaxUTC || !ascii(s.LastRay, 20) {
		return nil, Invalid
	}
	value := map[string]any{"schema_version": s.SchemaVersion, "engine": s.Engine, "adapter": s.Adapter, "uuid": s.UUID,
		"retry_after_utc": s.RetryAfterUTC, "max_retry_after_utc": s.MaxRetryAfterUTC, "last_ray": s.LastRay}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil, Invalid
	}
	data := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	if len(data) > 4096 {
		return nil, Invalid
	}
	return data, nil
}

func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, Invalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, Invalid
	}
	switch t {
	case json.Delim('{'):
		out := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, Invalid
			}
			name, ok := key.(string)
			if !ok {
				return nil, Invalid
			}
			if _, exists := out[name]; exists {
				return nil, Invalid
			}
			value, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			out[name] = value
		}
		if token, err := d.Token(); err != nil || token != json.Delim('}') {
			return nil, Invalid
		}
		return out, nil
	case json.Delim('['):
		out := []any{}
		for d.More() {
			value, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		if token, err := d.Token(); err != nil || token != json.Delim(']') {
			return nil, Invalid
		}
		return out, nil
	default:
		if _, invalid := t.(json.Delim); invalid {
			return nil, Invalid
		}
		return t, nil
	}
}

func decode(data []byte, limit int) (map[string]any, error) {
	if len(data) > limit {
		return nil, Invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := readValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, Invalid
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, Invalid
	}
	return result, nil
}

func object(value any, fields string) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	keys := strings.Fields(fields)
	if !ok || len(m) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, exists := m[key]; !exists {
			return nil, false
		}
	}
	return m, true
}

func number(value any, maximum int64) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	result, err := n.Int64()
	return result, err == nil && result >= 0 && result <= maximum
}

func textValue(value any) (string, bool) { s, ok := value.(string); return s, ok }
func boolValue(value any) (bool, bool)   { b, ok := value.(bool); return b, ok }

func parseSnapshot(value any) (Snapshot, []byte, error) {
	m, ok := object(value, "schema_version engine adapter uuid retry_after_utc max_retry_after_utc last_ray")
	if !ok {
		return Snapshot{}, nil, Invalid
	}
	schema, validSchema := number(m["schema_version"], 1)
	retry, validRetry := number(m["retry_after_utc"], MaxUTC)
	maximum, validMaximum := number(m["max_retry_after_utc"], MaxUTC)
	engine, validEngine := textValue(m["engine"])
	adapter, validAdapter := textValue(m["adapter"])
	uuid, validUUID := textValue(m["uuid"])
	ray, validRay := textValue(m["last_ray"])
	if !validSchema || schema != 1 || !validRetry || !validMaximum || !validEngine || !validAdapter || !validUUID || !validRay {
		return Snapshot{}, nil, Invalid
	}
	s := Snapshot{int(schema), engine, adapter, uuid, retry, maximum, ray}
	data, err := SnapshotBytes(s)
	return s, data, err
}

func httpDate(raw string) (int64, error) {
	t, err := http.ParseTime(raw)
	if err != nil || t.Unix() < 0 || t.Unix() > MaxUTC {
		return 0, ClockUncertain
	}
	return t.Unix(), nil
}

func ValidateFinal(data []byte, now Clock, previous Snapshot, binding Binding) (Final, error) {
	var final Final
	r, err := decode(data, 1<<20)
	if err != nil {
		return final, err
	}
	if r["control_complete"] != true || r["final"] != true {
		return final, Unknown
	}
	if _, ok := object(r, "schema_version update_id base_generation engine adapter final all_network_requests_finished control_complete control_snapshot reason_code snapshot_sha256 request_count response_count response dat_save_attempts dat_save_failures definitions all_required_origin_confirmations all_required_artifacts_verified fixture_only host_deadline_and_adoption_not_evaluated adapter_library_sha256"); !ok {
		return final, Invalid
	}
	schema, validSchema := number(r["schema_version"], 1)
	generation, validGeneration := number(r["base_generation"], 1<<63-2)
	id, validID := textValue(r["update_id"])
	fixture, validFixture := boolValue(r["fixture_only"])
	if !now.Valid() || !digestPattern.MatchString(binding.LibrarySHA256) {
		return final, ClockUncertain
	}
	if !validSchema || schema != 1 || !validGeneration || !validID || !identifier.MatchString(id) ||
		r["engine"] != Engine || r["adapter"] != Adapter || r["all_network_requests_finished"] != true ||
		!validFixture || fixture != binding.FixtureOnly || r["host_deadline_and_adoption_not_evaluated"] != true ||
		r["adapter_library_sha256"] != binding.LibrarySHA256 || (r["reason_code"] != nil && r["reason_code"] != "UPDATE_COOLDOWN") {
		return final, Invalid
	}
	snapshot, snapshotBytes, err := parseSnapshot(r["control_snapshot"])
	if err != nil {
		return final, err
	}
	if _, err = SnapshotBytes(previous); err != nil {
		return final, err
	}
	if snapshot.UUID != previous.UUID || snapshot.MaxRetryAfterUTC < previous.MaxRetryAfterUTC || r["snapshot_sha256"] != sha256Text(snapshotBytes) {
		return final, Invalid
	}
	counts := map[string]int64{}
	for _, field := range []string{"request_count", "response_count", "dat_save_attempts", "dat_save_failures"} {
		n, ok := number(r[field], 1<<32-1)
		if !ok {
			return final, Invalid
		}
		counts[field] = n
	}
	if counts["response_count"] > counts["request_count"] || counts["dat_save_failures"] > counts["dat_save_attempts"] {
		return final, Invalid
	}
	response, ok := object(r["response"], "http_status guest_utc retry_after_kind retry_after_raw date_raw wait_seconds")
	if !ok {
		return final, Invalid
	}
	status, validStatus := number(response["http_status"], 599)
	guest, validGuest := number(response["guest_utc"], MaxUTC)
	reportedWait, validWait := number(response["wait_seconds"], MaxUTC)
	raw, validRaw := textValue(response["retry_after_raw"])
	dateRaw, validDate := textValue(response["date_raw"])
	if !validStatus || !validGuest || !validWait || !validRaw || !validDate || !ascii(raw, 127) || !ascii(dateRaw, 127) {
		return final, Invalid
	}
	kind := "fallback"
	if raw != "" {
		kind = "delta_seconds"
		for _, c := range raw {
			if c < '0' || c > '9' {
				kind = "http_date"
				break
			}
		}
	}
	if response["retry_after_kind"] != kind {
		return final, ClockUncertain
	}
	if counts["request_count"] == 0 && (status != 0 || guest != 0 || raw != "" || dateRaw != "") {
		return final, Invalid
	}
	var wait int64
	if status == 403 || status == 429 {
		if counts["request_count"] == 0 || counts["response_count"] == 0 || guest == 0 {
			return final, Unknown
		}
		if r["reason_code"] != "UPDATE_COOLDOWN" || counts["request_count"] != counts["response_count"] {
			return final, Invalid
		}
		fallback := int64(14400)
		if status == 403 {
			fallback = 86400
		}
		switch kind {
		case "delta_seconds":
			seconds, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || seconds < 0 || seconds > MaxUTC {
				return final, ClockUncertain
			}
			wait = seconds
			if status == 403 {
				wait = max(wait, fallback)
			} else if wait == 0 {
				wait = fallback
			}
			if reportedWait != wait {
				return final, ClockUncertain
			}
		case "http_date":
			until, err := httpDate(raw)
			if err != nil {
				return final, err
			}
			date, err := httpDate(dateRaw)
			if err != nil {
				return final, err
			}
			wait = max(int64(0), until-date, until-now.UTC, reportedWait)
			if status == 403 {
				wait = max(wait, fallback)
			}
		case "fallback":
			wait = fallback
			if reportedWait != wait {
				return final, ClockUncertain
			}
		}
		reportedMaximum := guest + reportedWait
		if reportedMaximum > MaxUTC || snapshot.MaxRetryAfterUTC < reportedMaximum || snapshot.MaxRetryAfterUTC > max(previous.MaxRetryAfterUTC, snapshot.RetryAfterUTC, reportedMaximum) {
			return final, ClockUncertain
		}
		wait += max(int64(0), snapshot.RetryAfterUTC-reportedMaximum)
	} else if reportedWait != 0 || snapshot.MaxRetryAfterUTC > previous.MaxRetryAfterUTC {
		return final, ClockUncertain
	}
	if wait > MaxUTC-now.UTC {
		return final, ClockUncertain
	}
	rows, ok := r["definitions"].([]any)
	if !ok || len(rows) != 3 {
		return final, Invalid
	}
	names := []string{"main", "daily", "bytecode"}
	if fixture {
		names = []string{"fixture_0", "fixture_1", "fixture_2"}
	}
	origins, artifacts := true, true
	var confirmedCount int64
	for i, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || row["definition"] != names[i] {
			return final, Invalid
		}
		origin, validOrigin := boolValue(row["origin_confirmed"])
		artifact, validArtifact := boolValue(row["artifact_verified"])
		if !validOrigin || !validArtifact || artifact && !origin {
			return final, Invalid
		}
		origins = origins && origin
		artifacts = artifacts && artifact
		if origin {
			confirmedCount++
		}
		if row["status"] == "not_requested_cooldown_or_invalid" {
			if _, ok := object(row, "definition status origin_confirmed artifact_verified"); !ok || origin || artifact {
				return final, Invalid
			}
			continue
		}
		if _, ok := object(row, "definition status origin_confirmed artifact_verified artifact http_status"); !ok {
			return final, Invalid
		}
		code, validCode := number(row["status"], 255)
		httpStatus, validHTTP := number(row["http_status"], 599)
		if !validCode || !validHTTP || origin && (code != 0 && code != 1 || httpStatus != 200 && httpStatus != 206 && httpStatus != 304) {
			return final, Invalid
		}
		if artifact {
			item, ok := object(row["artifact"], "sha256 bytes")
			if !ok {
				return final, Invalid
			}
			digest, validDigest := textValue(item["sha256"])
			size, validSize := number(item["bytes"], WorkspaceReservation)
			if !validDigest || !digestPattern.MatchString(digest) || !validSize || size == 0 {
				return final, Invalid
			}
		} else if row["artifact"] != nil {
			return final, Invalid
		}
	}
	if confirmedCount > counts["response_count"] || origins && status != 200 && status != 206 && status != 304 || r["all_required_origin_confirmations"] != origins || r["all_required_artifacts_verified"] != artifacts || (status == 403 || status == 429) && (origins || artifacts) {
		return final, Invalid
	}
	return Final{id, generation, snapshot, snapshotBytes, wait, origins && artifacts && !fixture, sha256Text(data)}, nil
}
