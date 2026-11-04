package broker

import "fmt"

const (
	MaxInputBytes  int64 = 250 << 20
	OriginalBudget int64 = 5 << 30
	SafetyMargin   int64 = 2 << 30
	Stage0Passed         = true
)

type Config struct {
	DataDir             string
	InputRoots          map[string]string
	ReleaseDestinations map[string]string
	ShareNames          bool
	VM                  *VMConfig
	Update              *UpdateConfig
}

type VMConfig struct {
	RunnerPath string
	Workspace  string
	Proof      string
}

type Coverage struct {
	ProfileID              string   `json:"profile_id"`
	RequiredChecksComplete bool     `json:"required_checks_complete"`
	AVProcessStatus        string   `json:"av_process_status"`
	AVResult               string   `json:"av_result"`
	AVCoverageAssurance    string   `json:"av_coverage_assurance"`
	RequiredAVInputCount   int      `json:"required_av_input_count"`
	AVNormalResultCount    int      `json:"av_normal_result_count"`
	KnownLimitations       []string `json:"known_limitations"`
}

type RejectionEvidence struct {
	EvidenceID string `json:"evidence_id"`
	ObjectID   string `json:"object_id"`
	ReasonCode string `json:"reason_code"`
}

type Request struct {
	URL               string  `json:"url,omitempty"`
	IdempotencyKey    string  `json:"idempotency_key"`
	SourceKind        string  `json:"source_kind"`
	RootID            string  `json:"root_id,omitempty"`
	Source            string  `json:"source,omitempty"`
	DisplayName       *string `json:"display_name,omitempty"`
	DeclaredMediaType *string `json:"declared_media_type,omitempty"`
	ExpectedType      *string `json:"expected_type,omitempty"`
	ExpectedSHA256    *string `json:"expected_sha256,omitempty"`
}

type InputReceipt struct {
	ObjectID         string `json:"object_id"`
	SHA256           string `json:"sha256"`
	ByteSize         int64  `json:"byte_size"`
	ContentAvailable bool   `json:"content_available"`
}

type ReleaseEligibility struct {
	Eligible    bool     `json:"eligible"`
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

type JobPage struct {
	SchemaVersion string `json:"schema_version"`
	Jobs          []Job  `json:"jobs"`
	NextCursor    string `json:"next_cursor,omitempty"`
}

type Job struct {
	SchemaVersion          string              `json:"schema_version"`
	JobID                  string              `json:"job_id"`
	DisplayName            string              `json:"display_name,omitempty"`
	AttemptID              string              `json:"attempt_id,omitempty"`
	UpdateID               string              `json:"update_id,omitempty"`
	WaitReason             string              `json:"wait_reason,omitempty"`
	NextAllowedAt          *string             `json:"next_allowed_at"`
	Phase                  string              `json:"phase"`
	Verdict                string              `json:"verdict"`
	IntakeStatus           string              `json:"intake_status"`
	ReasonCodes            []string            `json:"reason_codes"`
	ExecutionErrors        []string            `json:"execution_errors"`
	InputReceipt           *InputReceipt       `json:"input_receipt"`
	Release                ReleaseEligibility  `json:"release"`
	CreatedAt              string              `json:"created_at"`
	FinishedAt             string              `json:"finished_at,omitempty"`
	Coverage               Coverage            `json:"coverage"`
	ScanDetails            *ScanDetails        `json:"scan_details,omitempty"`
	Progress               *ScanProgress       `json:"progress,omitempty"`
	ConfirmedRejections    []RejectionEvidence `json:"confirmed_rejections"`
	RuntimeCleanupComplete bool                `json:"runtime_cleanup_complete"`
}

func pendingCoverage() Coverage {
	return Coverage{ProfileID: "filegate-standard-av-v1-unadopted", AVProcessStatus: "not_started", AVResult: "pending", AVCoverageAssurance: "standard_engine_best_effort", KnownLimitations: []string{"AV_INTERNAL_LIMITS_NOT_FULLY_OBSERVABLE"}}
}

type Receipt struct {
	SchemaVersion       string        `json:"schema_version"`
	JobID               string        `json:"job_id"`
	IntakeStatus        string        `json:"intake_status"`
	Replayed            bool          `json:"replayed"`
	CurrentInputChecked bool          `json:"current_input_checked"`
	BodyConsumed        bool          `json:"body_consumed"`
	InputReceipt        *InputReceipt `json:"input_receipt"`
	Job                 Job           `json:"job"`
	HTTPStatus          int           `json:"-"`
}

type PruneResult struct {
	SchemaVersion          string `json:"schema_version"`
	ObjectsRemoved         int    `json:"objects_removed"`
	JobsRemoved            int    `json:"jobs_removed"`
	DefinitionsRemoved     int    `json:"definitions_removed"`
	UpdateRuntimesRemoved  int    `json:"update_runtimes_removed"`
	UpdateHistoriesRemoved int    `json:"update_histories_removed"`
	UpdateCleanupPending   int    `json:"update_cleanup_pending"`
}

type Error struct {
	Code           string          `json:"code"`
	Status         int             `json:"-"`
	Receipt        *Receipt        `json:"receipt,omitempty"`
	ReleaseReceipt *ReleaseReceipt `json:"release_receipt,omitempty"`
}

func (e *Error) Error() string              { return e.Code }
func failure(code string, status int) error { return &Error{Code: code, Status: status} }
func storageError() error                   { return failure("STORE_UNAVAILABLE", 503) }
func (j Job) Terminal() bool {
	return j.Phase == "FINISHED" || j.Phase == "FAILED" || j.Phase == "CANCELLED"
}
func receiptFor(j Job, replayed bool) Receipt {
	status := 202
	if replayed && j.IntakeStatus == "COMMITTED" {
		status = 200
	}
	return Receipt{SchemaVersion: "4", JobID: j.JobID, IntakeStatus: j.IntakeStatus, Replayed: replayed, InputReceipt: j.InputReceipt, Job: j, HTTPStatus: status}
}

func newID(prefix string) string { return fmt.Sprintf("%s_%s", prefix, randomID()) }
