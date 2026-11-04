package broker

import (
	"context"
)

const releaseSchema = `
CREATE TABLE IF NOT EXISTS release_destinations (id TEXT PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS releases (id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL, job_id TEXT NOT NULL REFERENCES jobs(id), state TEXT NOT NULL, finalized_at INTEGER NOT NULL DEFAULT 0, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS release_publication_attempts (release_id TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE, sequence INTEGER NOT NULL, state TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY(release_id,sequence));
CREATE TABLE IF NOT EXISTS release_authorizations (release_id TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE, sequence INTEGER NOT NULL, attempt_id TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY(release_id,sequence));
CREATE TABLE IF NOT EXISTS release_reservations (release_id TEXT PRIMARY KEY REFERENCES releases(id), device TEXT NOT NULL, reserved INTEGER NOT NULL, written INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS release_tombstones (key_hash TEXT PRIMARY KEY, release_id TEXT NOT NULL UNIQUE, job_id TEXT NOT NULL, state TEXT NOT NULL);
`

type ReleaseReceipt struct {
	SchemaVersion          string   `json:"schema_version"`
	ReleaseID              string   `json:"release_id"`
	JobID                  string   `json:"job_id"`
	DestinationID          string   `json:"destination_id"`
	OutputName             string   `json:"output_name"`
	State                  string   `json:"state"`
	Replayed               bool     `json:"replayed"`
	AbortRequested         bool     `json:"abort_requested"`
	AbortOutcome           *string  `json:"abort_outcome"`
	PublicationStatus      string   `json:"publication_status"`
	PublicationConfirmed   bool     `json:"publication_confirmed"`
	ResourcesFinalized     bool     `json:"resources_finalized"`
	Success                bool     `json:"success"`
	FinalValidation        string   `json:"final_validation"`
	OutputState            string   `json:"output_state"`
	CurrentOutputState     string   `json:"current_output_state"`
	OutputSyncConfirmation string   `json:"output_sync_confirmation"`
	ReasonCodes            []string `json:"reason_codes"`
	CreatedAt              string   `json:"created_at"`
	FinalizedAt            string   `json:"finalized_at,omitempty"`
	HTTPStatus             int      `json:"-"`
}

type releaseIdentity struct {
	Device string `json:"device"`
	Inode  uint64 `json:"inode"`
	Birth  string `json:"birth"`
}

type ReleaseDestination struct {
	ID      string `json:"destination_id"`
	Enabled bool   `json:"enabled"`
}

type releaseDestinationRecord struct {
	ID       string           `json:"id"`
	Path     string           `json:"path"`
	Disabled bool             `json:"disabled"`
	Identity *releaseIdentity `json:"identity"`
	Staging  *releaseIdentity `json:"staging"`
}

type releaseBinding struct {
	AttemptID          string `json:"attempt_id"`
	PolicySHA256       string `json:"policy_sha256"`
	WorkerSHA256       string `json:"worker_sha256"`
	EngineSHA256       string `json:"engine_sha256"`
	BuildSHA256        string `json:"build_sha256"`
	ConfigSHA256       string `json:"config_sha256"`
	DefinitionsSHA256  string `json:"definitions_sha256"`
	FormatsSHA256      string `json:"formats_sha256"`
	ObservationsSHA256 string `json:"observations_sha256"`
	ReportSHA256       string `json:"report_sha256"`
	AuthorizedAt       string `json:"authorized_at"`
	ExpiresAt          string `json:"expires_at"`
	Format             string `json:"format"`
}

type releaseRecord struct {
	Receipt            ReleaseReceipt           `json:"receipt"`
	ObjectID           string                   `json:"object_id"`
	SHA256             string                   `json:"sha256"`
	ByteSize           int64                    `json:"byte_size"`
	Destination        releaseDestinationRecord `json:"destination"`
	TempName           string                   `json:"temp_name"`
	TempIdentity       *releaseIdentity         `json:"temp_identity"`
	AbortRequestedAt   string                   `json:"abort_requested_at,omitempty"`
	NoPublicationAt    string                   `json:"no_publication_at,omitempty"`
	CleanupConfirmedAt string                   `json:"cleanup_confirmed_at,omitempty"`
	Authorization      releaseBinding           `json:"authorization"`
	Generation         int                      `json:"generation"`
}

type releasePublicationAttempt struct {
	ReleaseID   string          `json:"release_id"`
	Sequence    int             `json:"sequence"`
	Generation  int             `json:"generation"`
	Temp        releaseIdentity `json:"temp_identity"`
	Destination releaseIdentity `json:"destination_identity"`
	OutputName  string          `json:"output_name"`
	Boot        string          `json:"boot"`
	State       string          `json:"state"`
	RecordedAt  string          `json:"recorded_at"`
	ResolvedAt  string          `json:"resolved_at,omitempty"`
	Evidence    string          `json:"evidence,omitempty"`
}

type releaseRun struct {
	id        string
	cancel    context.CancelFunc
	stopCause context.CancelCauseFunc
	done      chan struct{}
}

func (r releaseRecord) terminal() bool {
	return r.Receipt.State == "COMMITTED" || r.Receipt.State == "ABORTED" || r.Receipt.State == "PUBLISHED_UNVERIFIED"
}

func releaseFailure(code string, status int, receipt ReleaseReceipt) error {
	return &Error{Code: code, Status: status, ReleaseReceipt: &receipt}
}
