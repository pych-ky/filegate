package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"unicode/utf8"

	"filegate.local/filegate/internal/av"
	updatecontrol "filegate.local/filegate/internal/update"
)

const formatPolicy = "filegate-product-scan-v4"
const reportLimit int64 = 32 << 20

type scanMetadata struct {
	DisplayName       string `json:"display_name,omitempty"`
	DeclaredMediaType string `json:"declared_media_type,omitempty"`
	ExpectedType      string `json:"expected_type,omitempty"`
}

type scanRequest struct {
	SchemaVersion  int                           `json:"schema_version"`
	JobID          string                        `json:"job_id"`
	AttemptID      string                        `json:"attempt_id"`
	PolicyDigest   string                        `json:"policy_digest"`
	InputPath      string                        `json:"input_path"`
	ExpectedSHA256 string                        `json:"expected_sha256"`
	ByteSize       int64                         `json:"byte_size"`
	Metadata       scanMetadata                  `json:"metadata"`
	Definition     *updatecontrol.ScanDefinition `json:"definition,omitempty"`
}

type formatObject struct {
	ID                string `json:"object_id"`
	ParentID          string `json:"parent_id,omitempty"`
	Kind              string `json:"kind"`
	Format            string `json:"format,omitempty"`
	SHA256            string `json:"sha256,omitempty"`
	ByteSize          int64  `json:"byte_size"`
	AVRequired        bool   `json:"av_required"`
	AVExclusionReason string `json:"av_exclusion_reason,omitempty"`
	Path              string `json:"path,omitempty"`
}

type formatRejection struct {
	ObjectID   string `json:"object_id"`
	ReasonCode string `json:"reason_code"`
}

type formatResult struct {
	SchemaVersion           int               `json:"schema_version"`
	StructureStatus         string            `json:"structure_status"`
	StructureChecksComplete bool              `json:"structure_checks_complete"`
	FormatChecksComplete    bool              `json:"format_checks_complete"`
	RequiredChecksComplete  bool              `json:"required_checks_complete"`
	Reasons                 []string          `json:"reason_codes"`
	Checks                  []string          `json:"completed_checks"`
	ArchiveEntryCount       int               `json:"archive_entry_count"`
	ExtractedFileCount      int               `json:"extracted_file_count"`
	RequiredAVInputCount    int               `json:"required_av_input_count"`
	ExtractedBytes          int64             `json:"extracted_bytes"`
	Manifest                []formatObject    `json:"manifest"`
	ConfirmedRejections     []formatRejection `json:"confirmed_rejections"`
}

type scanReport struct {
	SchemaVersion int    `json:"schema_version"`
	Event         string `json:"event"`
	JobID         string `json:"job_id"`
	AttemptID     string `json:"attempt_id"`
	PolicyDigest  string `json:"policy_digest"`
	Input         struct {
		SHA256   string `json:"sha256"`
		ByteSize int64  `json:"byte_size"`
	} `json:"input"`
	WorkerUID        int          `json:"worker_uid"`
	AVProcessStatus  string       `json:"av_process_status"`
	AVResult         string       `json:"av_result"`
	ReportComplete   bool         `json:"report_complete"`
	ManifestComplete bool         `json:"manifest_complete"`
	Result           formatResult `json:"result"`
	AV               av.Result    `json:"av"`
	avValidation     avReportValidation
}

var objectPattern = regexp.MustCompile(`^object_[0-9]{6}$`)
var storedPattern = regexp.MustCompile(`^object_[0-9]{6}\.data$`)

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func decodeReport(path string, j Job, expected *av.Binding) (scanReport, string, error) {
	var report scanReport
	body, err := readPrivate(path, reportLimit)
	if err != nil {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	if strictJSON(body, &report) != nil {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	fields, err := requiredFields(body, "schema_version", "event", "job_id", "attempt_id", "policy_digest", "input", "worker_uid", "av_process_status", "av_result", "report_complete", "manifest_complete", "result", "av")
	if err != nil {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	if _, err = requiredFields(fields["input"], "sha256", "byte_size"); err != nil {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	if _, err = requiredFields(fields["result"], "schema_version", "structure_status", "structure_checks_complete", "format_checks_complete", "required_checks_complete", "reason_codes", "completed_checks", "archive_entry_count", "extracted_file_count", "required_av_input_count", "extracted_bytes", "manifest", "confirmed_rejections"); err != nil {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	if j.InputReceipt == nil || report.SchemaVersion != 2 || report.Event != "product_result" || report.JobID != j.JobID || report.AttemptID != j.AttemptID || report.PolicyDigest != formatPolicy || report.WorkerUID != 65534 || !report.ReportComplete || report.Input.SHA256 != j.InputReceipt.SHA256 || report.Input.ByteSize != j.InputReceipt.ByteSize || report.AVProcessStatus != report.AV.ProcessStatus || report.AVResult != report.AV.AVResult {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	r := report.Result
	if r.SchemaVersion != 1 || r.RequiredChecksComplete || r.ArchiveEntryCount < 0 || r.ArchiveEntryCount > 10000 || r.ExtractedFileCount < 0 || r.ExtractedFileCount > 10000 || r.RequiredAVInputCount < 0 || r.RequiredAVInputCount > 10001 || r.ExtractedBytes < 0 || r.ExtractedBytes > 1<<30 || len(r.Manifest) > 10001 || len(r.Checks) > 21 || len(r.Reasons) > 1 {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	checkNames := map[string]bool{"header-match": true, "intervals": true, "coverage": true, "crc-stream": true, "deflate-end": true, "entry-kind": true, "tree": true, "path-rules": true, "zip-profile": true, "limits": true, "manifest": true, "decoder-boundary": true, "txt-encoding": true, "txt-controls": true, "txt-identification": true, "declared-type": true, "image-structure": true, "image-decode": true, "ooxml-package": true, "ooxml-xml": true, "ooxml-profile": true}
	for _, check := range r.Checks {
		if !checkNames[check] {
			return report, "", failure("REPORT_VALIDATION_FAILED", 409)
		}
		delete(checkNames, check)
	}
	objects := make(map[string]formatObject, len(r.Manifest))
	paths := make(map[string]bool, len(r.Manifest))
	avCount := 0
	var extracted int64
	for i, o := range r.Manifest {
		if !objectPattern.MatchString(o.ID) || o.ByteSize < 0 {
			return report, "", failure("REPORT_VALIDATION_FAILED", 409)
		}
		if _, exists := objects[o.ID]; exists {
			return report, "", failure("REPORT_VALIDATION_FAILED", 409)
		}
		if i == 0 {
			if o.ParentID != "" || o.Path != "" || o.SHA256 != report.Input.SHA256 || o.ByteSize != report.Input.ByteSize {
				return report, "", failure("REPORT_VALIDATION_FAILED", 409)
			}
		} else {
			parent, exists := objects[o.ParentID]
			if !exists || parent.Kind != "container" || o.ByteSize > 100<<20 {
				return report, "", failure("REPORT_VALIDATION_FAILED", 409)
			}
			if o.Format == "ooxml-part" && parent.Format != "docx" && parent.Format != "xlsx" {
				return report, "", failure("REPORT_VALIDATION_FAILED", 409)
			}
			extracted += o.ByteSize
		}
		if o.Kind == "verified_empty_directory" {
			if i == 0 || o.AVRequired || o.AVExclusionReason != "VERIFIED_EMPTY_DIRECTORY" || o.Format != "" || o.SHA256 != "" || o.ByteSize != 0 || o.Path != "" {
				return report, "", failure("REPORT_VALIDATION_FAILED", 409)
			}
		} else {
			if !o.AVRequired || !validDigest(o.SHA256) || o.AVExclusionReason != "" || (i != 0 && !storedPattern.MatchString(o.Path)) || (o.Kind != "container" && o.Kind != "regular_file") || (o.Kind == "container" && o.Format != "zip" && o.Format != "docx" && o.Format != "xlsx") || (o.Kind == "regular_file" && o.Format != "txt" && o.Format != "png" && o.Format != "jpeg" && (o.Format != "ooxml-part" || i == 0)) {
				return report, "", failure("REPORT_VALIDATION_FAILED", 409)
			}
			avCount++
			if i != 0 {
				if paths[o.Path] {
					return report, "", failure("REPORT_VALIDATION_FAILED", 409)
				}
				paths[o.Path] = true
			}
		}
		objects[o.ID] = o
	}
	if avCount != r.RequiredAVInputCount || extracted > r.ExtractedBytes || r.ExtractedFileCount > r.ArchiveEntryCount || avCount > r.ExtractedFileCount+1 {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	switch r.StructureStatus {
	case "ACCEPT_FORMAT_STRUCTURE":
		if !report.ManifestComplete || !r.StructureChecksComplete || !r.FormatChecksComplete || len(r.Reasons) != 0 || len(r.ConfirmedRejections) != 0 || len(r.Manifest) == 0 || len(r.Manifest) != r.ArchiveEntryCount+1 || r.ExtractedFileCount != avCount-1 || extracted != r.ExtractedBytes {
			return report, "", failure("REPORT_VALIDATION_FAILED", 409)
		}
	case "BLOCK":
		if report.ManifestComplete || r.StructureChecksComplete || r.FormatChecksComplete || len(r.Reasons) != 1 || len(r.ConfirmedRejections) != 1 {
			return report, "", failure("REPORT_VALIDATION_FAILED", 409)
		}
		e := r.ConfirmedRejections[0]
		o, exists := objects[e.ObjectID]
		if !exists || o.Kind != "container" || e.ReasonCode != r.Reasons[0] || (e.ReasonCode != "UNSAFE_ARCHIVE_PATH" && e.ReasonCode != "ARCHIVE_NAME_COLLISION" && e.ReasonCode != "ARCHIVE_PATH_TYPE_CONFLICT") {
			return report, "", failure("REPORT_VALIDATION_FAILED", 409)
		}
	case "HOLD":
		allowed := map[string]bool{"UNSUPPORTED_FORMAT": true, "UNEXPECTED_ARTIFACT_TYPE": true, "LIMIT_EXCEEDED": true, "WORKSPACE_IO_ERROR": true, "SCAN_TIMEOUT": true, "ARCHIVE_CORRUPT": true, "ARCHIVE_ENTRY_TYPE_CONFLICT": true, "ARCHIVE_PROFILE_UNSUPPORTED": true, "ENCRYPTED_ARCHIVE": true, "DOCX_FIELD_REQUIRES_REVIEW": true, "XLSX_FORMULA_OR_CONNECTION": true, "ACTIVE_CONTENT_REQUIRES_REVIEW": true}
		if report.ManifestComplete || r.StructureChecksComplete || r.FormatChecksComplete || len(r.ConfirmedRejections) != 0 || len(r.Reasons) != 1 || !allowed[r.Reasons[0]] {
			return report, "", failure("REPORT_VALIDATION_FAILED", 409)
		}
	default:
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	if validateAVFields(fields["av"]) != nil {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	report.avValidation, err = validateAVReport(r, report.AV, expected)
	if err != nil {
		return report, "", failure("REPORT_VALIDATION_FAILED", 409)
	}
	digest := sha256.Sum256(body)
	return report, hex.EncodeToString(digest[:]), nil
}

func readPrivate(path string, limit int64) ([]byte, error) {
	f, err := openPrivate(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > limit || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("invalid private file")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(body)) > limit || int64(len(body)) != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("invalid private file")
	}
	return body, nil
}

func requiredFields(body []byte, names ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != len(names) {
		return nil, errors.New("invalid JSON fields")
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(value, []byte("null")) {
			return nil, errors.New("missing JSON field")
		}
	}
	return fields, nil
}

func strictJSON(body []byte, value any) error {
	return strictJSONKeys(body, value, 128)
}

func strictJSONKeys(body []byte, value any, keyLimit int) error {
	if !utf8.Valid(body) {
		return errors.New("invalid JSON")
	}
	probe := json.NewDecoder(bytes.NewReader(body))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON depth")
		}
		token, err := probe.Token()
		if err != nil {
			return err
		}
		if text, ok := token.(string); ok && len(text) > 4096 {
			return errors.New("JSON string")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for probe.More() {
					key, err := probe.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok || len(name) > keyLimit || seen[name] {
						return errors.New("JSON key")
					}
					seen[name] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for probe.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("JSON delimiter")
			}
			_, err = probe.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := probe.Token(); err != io.EOF {
		return errors.New("JSON trailing")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	return d.Decode(value)
}
