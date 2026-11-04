package freshclamadapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strconv"
)

const AdapterID = "filegate-freshclam-1.4.6-v1"
const SourceID = "1.4.6:5853e1396777bae4d909cd3dd44f58352e7cf9b3:filegate-v1"
const MaxTime int64 = 253402300799
const Limit = 1 << 20

var invalid = errors.New("UPDATE_STATE_UNKNOWN")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var fixturePath = regexp.MustCompile(`^/probe[0-2]\.ndb$`)

type Snapshot struct {
	SchemaVersion    int    `json:"schema_version"`
	Engine           string `json:"engine"`
	Adapter          string `json:"adapter"`
	UUID             string `json:"uuid"`
	RetryAfterUTC    int64  `json:"retry_after_utc"`
	MaxRetryAfterUTC int64  `json:"max_retry_after_utc"`
	LastRay          string `json:"last_ray"`
}

type Request struct {
	SchemaVersion   int      `json:"schema_version"`
	UpdateID        string   `json:"update_id"`
	BaseGeneration  int64    `json:"base_generation"`
	ControlSnapshot Snapshot `json:"control_snapshot"`
	FixtureURLs     []string `json:"fixture_urls,omitempty"`
}

func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, invalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, invalid
	}
	switch t {
	case json.Delim('{'):
		v := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, invalid
			}
			if _, exists := v[name]; exists {
				return nil, invalid
			}
			if v[name], err = readValue(d, depth+1); err != nil {
				return nil, err
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return nil, invalid
		}
		return v, nil
	case json.Delim('['):
		v := []any{}
		for d.More() {
			x, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			v = append(v, x)
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return nil, invalid
		}
		return v, nil
	default:
		if _, bad := t.(json.Delim); bad {
			return nil, invalid
		}
		return t, nil
	}
}

func document(data []byte) (map[string]any, error) {
	if len(data) > Limit {
		return nil, invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := readValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, invalid
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, invalid
	}
	return m, nil
}

func exact(m map[string]any, fields ...string) bool {
	if len(m) != len(fields) {
		return false
	}
	for _, field := range fields {
		if m[field] == nil {
			return false
		}
	}
	return true
}

func printable(s string, maximum int) bool {
	if len(s) > maximum {
		return false
	}
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func ParseRequest(data []byte, fixture bool) (Request, error) {
	var request Request
	m, err := document(data)
	fields := []string{"schema_version", "update_id", "base_generation", "control_snapshot"}
	if fixture {
		fields = append(fields, "fixture_urls")
	}
	if err != nil || !exact(m, fields...) {
		return request, invalid
	}
	snapshot, ok := m["control_snapshot"].(map[string]any)
	if !ok || !exact(snapshot, "schema_version", "engine", "adapter", "uuid", "retry_after_utc", "max_retry_after_utc", "last_ray") {
		return request, invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || request.SchemaVersion != 1 || !identifier.MatchString(request.UpdateID) || request.BaseGeneration < 0 || request.BaseGeneration == 1<<63-1 {
		return request, invalid
	}
	s := request.ControlSnapshot
	if s.SchemaVersion != 1 || s.Engine != "1.4.6" || s.Adapter != AdapterID || !uuid.MatchString(s.UUID) || s.RetryAfterUTC < 0 || s.RetryAfterUTC > MaxTime || s.MaxRetryAfterUTC < 0 || s.MaxRetryAfterUTC > MaxTime || !printable(s.LastRay, 20) {
		return request, invalid
	}
	if fixture {
		if len(request.FixtureURLs) < 1 || len(request.FixtureURLs) > 3 {
			return request, invalid
		}
		for _, raw := range request.FixtureURLs {
			u, err := url.Parse(raw)
			if err != nil {
				return request, invalid
			}
			port, portErr := strconv.Atoi(u.Port())
			if portErr != nil || port < 1 || port > 65535 || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !fixturePath.MatchString(u.EscapedPath()) {
				return request, invalid
			}
		}
	}
	return request, nil
}

func canonical(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}

func snapshotObject(s Snapshot) map[string]any {
	return map[string]any{"schema_version": s.SchemaVersion, "engine": s.Engine, "adapter": s.Adapter, "uuid": s.UUID, "retry_after_utc": s.RetryAfterUTC, "max_retry_after_utc": s.MaxRetryAfterUTC, "last_ray": s.LastRay}
}
