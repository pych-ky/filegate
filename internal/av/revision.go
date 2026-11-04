package av

// Revision binds the exact scanner and observation contract of a definition image.
type Revision struct {
	ProfileID             string `json:"profile_id"`
	ScannerManifestSHA256 string `json:"scanner_manifest_sha256"`
	BinarySHA256          string `json:"binary_sha256"`
	ConfigurationSHA256   string `json:"configuration_sha256"`
	ObservationSHA256     string `json:"observation_sha256"`
}

const ObservationSHA256 = "9911ded74d6240baf219dab9bb9b9cb185c913274dd63d42993d69df04dbcbca"

func CurrentRevision() Revision {
	return Revision{ProfileID, scannerManifestSHA256, BinarySHA256, ConfigurationSHA256, ObservationSHA256}
}

// Historical tuples are retained verbatim; a stored image is never relabelled.
func KnownRevision(r Revision) bool {
	return r == CurrentRevision() || r == (Revision{
		"filegate-standard-av-1.4.6-candidate-v1",
		"47be9f07e65948d76d6cf46b38d2baf73cddcccd7562a7a3011e19af9d982b8c",
		"a174fa3c75b6f544f852cdc8205f61a3198355091ad07679bed1c0f591c31917",
		"08eaa97d240dde9866c14e709bbf937dbff04c068e28676e690146b150ae7477",
		"2820f79fce99925c4bbf2301c2bae1c1276e8940439ce61926aadb473be7dd2e",
	})
}

// Observation-contract migration keeps the same scanner, binary and configuration.
func CompatibleRevision(previous, next Revision) bool {
	return next == CurrentRevision() && KnownRevision(previous) &&
		previous.ScannerManifestSHA256 == next.ScannerManifestSHA256 &&
		previous.BinarySHA256 == next.BinarySHA256 && previous.ConfigurationSHA256 == next.ConfigurationSHA256
}
