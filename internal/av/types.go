// Package av runs the fixed scanner profile inside the isolated inspection VM.
package av

const (
	ProfileID           = "filegate-standard-av-1.4.6-limited-v2"
	ProfilePath         = "/av/product-profile.json"
	ManifestPath        = "/av/scan-manifest.json"
	ConfigurationSHA256 = "08eaa97d240dde9866c14e709bbf937dbff04c068e28676e690146b150ae7477"
	BinarySHA256        = "a174fa3c75b6f544f852cdc8205f61a3198355091ad07679bed1c0f591c31917"
)

type Definition struct {
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	ByteSize int64  `json:"byte_size"`
}

// Profile is installed by the trusted image builder, never supplied by an input.
type Profile struct {
	SchemaVersion          int          `json:"schema_version"`
	ProfileID              string       `json:"profile_id"`
	ScannerManifestSHA256  string       `json:"scanner_manifest_sha256"`
	ConfigurationSHA256    string       `json:"configuration_sha256"`
	DefinitionSetSHA256    string       `json:"definition_set_sha256"`
	ObservationSHA256      string       `json:"observation_sha256"`
	FixtureDefinitionsOnly bool         `json:"fixture_definitions_only"`
	Definitions            []Definition `json:"definitions"`
}

type Binding struct {
	ProfileSHA256          string `json:"profile_sha256"`
	ScannerManifestSHA256  string `json:"scanner_manifest_sha256"`
	BinarySHA256           string `json:"binary_sha256"`
	ConfigurationSHA256    string `json:"configuration_sha256"`
	DefinitionSetSHA256    string `json:"definition_set_sha256"`
	ObservationSHA256      string `json:"observation_sha256"`
	FixtureDefinitionsOnly bool   `json:"fixture_definitions_only"`
}

type ObjectResult struct {
	ObjectID            string `json:"object_id"`
	SHA256              string `json:"sha256"`
	ByteSize            int64  `json:"byte_size"`
	Status              string `json:"status"`
	ReasonCode          string `json:"reason_code"`
	SignatureSHA256     string `json:"signature_sha256"`
	InputVerified       bool   `json:"input_verified"`
	NormalResultPresent bool   `json:"normal_result_present"`
	verificationFailure string
}

type Detection struct {
	ObjectID        string `json:"object_id"`
	SHA256          string `json:"sha256"`
	ByteSize        int64  `json:"byte_size"`
	ReasonCode      string `json:"reason_code"`
	SignatureSHA256 string `json:"signature_sha256"`
}

type Result struct {
	SchemaVersion       int            `json:"schema_version"`
	ProfileID           string         `json:"profile_id"`
	ProcessStatus       string         `json:"process_status"`
	AVResult            string         `json:"av_result"`
	ResultsComplete     bool           `json:"results_complete"`
	BindingVerified     bool           `json:"binding_verified"`
	Binding             *Binding       `json:"binding"`
	RequiredInputCount  int            `json:"required_input_count"`
	NormalResultCount   int            `json:"normal_result_count"`
	ExitCode            *int           `json:"exit_code"`
	StdoutBytes         int64          `json:"stdout_bytes"`
	StdoutSHA256        string         `json:"stdout_sha256"`
	StderrBytes         int64          `json:"stderr_bytes"`
	StderrSHA256        string         `json:"stderr_sha256"`
	ReasonCodes         []string       `json:"reason_codes"`
	Objects             []ObjectResult `json:"objects"`
	ConfirmedDetections []Detection    `json:"confirmed_detections"`
}

func NotStarted(reason string) Result {
	return Result{SchemaVersion: 1, ProfileID: ProfileID, ProcessStatus: "not_started", AVResult: "inconclusive",
		ReasonCodes: []string{reason}, Objects: []ObjectResult{}, ConfirmedDetections: []Detection{}}
}

func (r *Result) reason(code string) {
	for _, old := range r.ReasonCodes {
		if code == old {
			return
		}
	}
	r.ReasonCodes = append(r.ReasonCodes, code)
}
