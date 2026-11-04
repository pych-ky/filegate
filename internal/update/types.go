package update

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
)

const (
	Engine                     = "1.4.6"
	Adapter                    = "filegate-freshclam-1.4.6-v1"
	Scope                      = "official-definitions-installation"
	MaxUTC               int64 = 253402300799
	DeadlineSeconds      int64 = 600
	MinimumInterval      int64 = 3600
	FreshnessSeconds     int64 = 86400
	WorkspaceReservation int64 = 6 << 30
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	Invalid        Error = "UPDATE_CONTROL_INVALID"
	Unknown        Error = "UPDATE_STATE_UNKNOWN"
	ClockUncertain Error = "UPDATE_CLOCK_UNCERTAIN"
	Cooldown       Error = "UPDATE_COOLDOWN"
	Timeout        Error = "UPDATE_TIMEOUT"
	Busy           Error = "RESOURCE_BUSY"
	StaleReport    Error = "STALE_REPORT_REJECTED"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Clock struct {
	Boot         string `json:"boot"`
	UTC          int64  `json:"utc"`
	ContinuousNS uint64 `json:"continuous_ns"`
}

func (c Clock) Valid() bool { return bootPattern.MatchString(c.Boot) && c.UTC > 0 && c.UTC <= MaxUTC }

type Snapshot struct {
	SchemaVersion    int    `json:"schema_version"`
	Engine           string `json:"engine"`
	Adapter          string `json:"adapter"`
	UUID             string `json:"uuid"`
	RetryAfterUTC    int64  `json:"retry_after_utc"`
	MaxRetryAfterUTC int64  `json:"max_retry_after_utc"`
	LastRay          string `json:"last_ray"`
}

type Binding struct {
	LibrarySHA256 string `json:"library_sha256"`
	FixtureOnly   bool   `json:"fixture_only"`
}

type Control struct {
	Generation                 int64          `json:"generation"`
	State                      string         `json:"state"`
	ActiveUpdateID             string         `json:"active_update_id,omitempty"`
	LastUpdateID               string         `json:"last_update_id,omitempty"`
	Binding                    Binding        `json:"binding"`
	Snapshot                   Snapshot       `json:"snapshot"`
	SnapshotSHA256             string         `json:"snapshot_sha256"`
	Clock                      Clock          `json:"clock"`
	NextAllowedUTC             int64          `json:"next_allowed_utc"`
	RemainingSeconds           int64          `json:"remaining_seconds"`
	ContinuousRemainingSeconds int64          `json:"continuous_remaining_seconds"`
	WaitFractionNS             uint64         `json:"wait_fraction_ns"`
	Reason                     string         `json:"reason,omitempty"`
	Definition                 *DefinitionSet `json:"definition,omitempty"`
}

type DefinitionSet struct {
	ImageManifestSHA256 string `json:"image_manifest_sha256,omitempty"`
	UpdateID            string `json:"update_id"`
	Generation          int64  `json:"generation"`
	Confirmed           Clock  `json:"confirmed"`
	ManifestSHA256      string `json:"manifest_sha256"`
}

type Attempt struct {
	ID                   string `json:"update_id"`
	BaseGeneration       int64  `json:"base_generation"`
	State                string `json:"state"`
	Started              Clock  `json:"started"`
	DeadlineContinuousNS uint64 `json:"deadline_continuous_ns"`
	Reason               string `json:"reason,omitempty"`
	ControlCommitted     bool   `json:"control_committed"`
	FinalSHA256          string `json:"final_sha256,omitempty"`
	FinalReceived        *Clock `json:"final_received,omitempty"`
	OriginConfirmed      bool   `json:"origin_confirmed"`
	StopConfirmed        bool   `json:"stop_confirmed"`
	CleanupConfirmed     bool   `json:"cleanup_confirmed"`
	ReservedBytes        int64  `json:"reserved_bytes"`
	AdoptionApproved     bool   `json:"adoption_approved"`
	FinishedUTC          int64  `json:"finished_utc,omitempty"`
}

type RestoreRequest struct {
	SchemaVersion  int      `json:"schema_version"`
	UpdateID       string   `json:"update_id"`
	BaseGeneration int64    `json:"base_generation"`
	Snapshot       Snapshot `json:"control_snapshot"`
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
