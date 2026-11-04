package freshclamadapter

import (
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type Options struct {
	Library, DatabaseDirectory, TemporaryDirectory string
	Fixture                                        bool
}

func Unknown(request *Request) map[string]any {
	report := map[string]any{"schema_version": 1, "final": false, "control_complete": false, "control_snapshot": nil, "reason_code": "UPDATE_STATE_UNKNOWN"}
	if request != nil {
		report["update_id"], report["base_generation"] = request.UpdateID, request.BaseGeneration
		report["engine"], report["adapter"] = "1.4.6", AdapterID
	}
	return report
}

// Library diagnostics never share the adapter's JSON report descriptors.
func discardOutput() (func() error, error) {
	saved := [2]int{-1, -1}
	for n, fd := range []int{1, 2} {
		copy, err := unix.Dup(fd)
		if err != nil {
			for _, prior := range saved {
				if prior >= 0 {
					unix.Close(prior)
				}
			}
			return nil, invalid
		}
		unix.CloseOnExec(copy)
		saved[n] = copy
	}
	null, err := unix.Open("/dev/null", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		for _, fd := range saved {
			unix.Close(fd)
		}
		return nil, invalid
	}
	restore := func() error {
		flushLibraryOutput()
		var result error
		for n, fd := range []int{1, 2} {
			if unix.Dup2(saved[n], fd) != nil {
				result = invalid
			}
			unix.Close(saved[n])
		}
		return result
	}
	for _, fd := range []int{1, 2} {
		if unix.Dup2(null, fd) != nil {
			unix.Close(null)
			restore()
			return nil, invalid
		}
	}
	unix.Close(null)
	return restore, nil
}

func Run(request Request, options Options) (report map[string]any, err error) {
	body, err := canonical(request)
	if err != nil {
		return nil, invalid
	}
	if _, err = ParseRequest(body, options.Fixture); err != nil {
		return nil, err
	}
	restore, err := discardOutput()
	if err != nil {
		return nil, err
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil {
			report = nil
			err = restoreErr
		}
	}()
	return execute(request, options)
}

func execute(request Request, options Options) (map[string]any, error) {
	l, librarySHA, err := loadRuntime(options.Library)
	if err != nil {
		return nil, err
	}
	defer l.close()
	if l.restore(request.ControlSnapshot) != nil {
		return nil, invalid
	}
	database, err := filepath.EvalSymlinks(options.DatabaseDirectory)
	temporary, tempErr := filepath.EvalSymlinks(options.TemporaryDirectory)
	if err != nil || tempErr != nil {
		return nil, invalid
	}
	if l.initialize(database, temporary) != nil {
		return nil, invalid
	}
	defer l.cleanup()
	if _, err = l.current(); err != nil {
		return nil, err
	}
	definitions := []string{"main", "daily", "bytecode"}
	if options.Fixture {
		definitions = request.FixtureURLs
	}
	rows := []map[string]any{}
	allOrigins, allArtifacts := true, true
	for index, name := range definitions {
		s, err := l.current()
		if err != nil {
			return nil, err
		}
		label := name
		if options.Fixture {
			label = "fixture_" + strconv.Itoa(index)
		}
		if s.Invalid || s.Blocked || s.RetryAfter > time.Now().Unix() {
			rows = append(rows, map[string]any{"definition": label, "status": "not_requested_cooldown_or_invalid", "origin_confirmed": false, "artifact_verified": false})
			allOrigins, allArtifacts = false, false
			continue
		}
		before := s.RequestCount
		status, err := l.update(name, options.Fixture)
		if err != nil {
			return nil, err
		}
		s, err = l.current()
		if err != nil {
			return nil, err
		}
		origin := (status == 0 || status == 1) && s.RequestCount > before && !s.Invalid && !s.Blocked && (s.HTTPStatus == 200 || s.HTTPStatus == 206 || s.HTTPStatus == 304)
		verified := false
		var artifact any
		if origin {
			candidates := []string{filepath.Join(database, name+".cvd"), filepath.Join(database, name+".cld")}
			if options.Fixture {
				parsed, _ := url.Parse(name)
				candidates = []string{filepath.Join(database, filepath.Base(parsed.Path))}
			}
			present := []string{}
			for _, path := range candidates {
				if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
					present = append(present, path)
				}
			}
			if len(present) == 1 && l.verify(present[0]) {
				h, size, err := FileDigest(present[0])
				if err != nil {
					return nil, err
				}
				verified = true
				artifact = map[string]any{"sha256": h, "bytes": size}
			}
		}
		rows = append(rows, map[string]any{"definition": label, "status": status, "origin_confirmed": origin, "artifact_verified": verified, "artifact": artifact, "http_status": s.HTTPStatus})
		allOrigins = allOrigins && origin
		allArtifacts = allArtifacts && verified
	}
	l.finish()
	s, err := l.current()
	if err != nil {
		return nil, err
	}
	complete := s.Initialized && s.Final && !s.Invalid && !(s.Blocked && s.RequestCount != 0 && s.ResponseUTC == 0)
	snapshot := snapshotObject(Snapshot{SchemaVersion: 1, Engine: "1.4.6", Adapter: AdapterID, UUID: s.UUID, RetryAfterUTC: s.RetryAfter, MaxRetryAfterUTC: s.MaxRetryAfter, LastRay: s.LastRay})
	encoded, err := canonical(snapshot)
	if err != nil || len(encoded) > 4096 {
		complete = false
	}
	var control, snapshotSHA, reason any
	if complete {
		control = snapshot
		snapshotSHA = digest(encoded)
	}
	if s.Invalid {
		reason = "UPDATE_CONTROL_INVALID"
	} else if !complete {
		reason = "UPDATE_STATE_UNKNOWN"
	} else if s.Blocked {
		reason = "UPDATE_COOLDOWN"
	}
	kind := "fallback"
	if s.RetryRaw != "" {
		kind = "delta_seconds"
		if strings.IndexFunc(s.RetryRaw, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			kind = "http_date"
		}
	}
	return map[string]any{"schema_version": 1, "update_id": request.UpdateID, "base_generation": request.BaseGeneration, "engine": "1.4.6", "adapter": AdapterID,
		"final": s.Final, "all_network_requests_finished": s.Final, "control_complete": complete, "control_snapshot": control, "reason_code": reason, "snapshot_sha256": snapshotSHA,
		"request_count": s.RequestCount, "response_count": s.ResponseCount, "response": map[string]any{"http_status": s.HTTPStatus, "guest_utc": s.ResponseUTC, "retry_after_kind": kind, "retry_after_raw": s.RetryRaw, "date_raw": s.DateRaw, "wait_seconds": s.WaitSeconds},
		"dat_save_attempts": s.DatSaveAttempts, "dat_save_failures": s.DatSaveFailures, "definitions": rows, "all_required_origin_confirmations": allOrigins, "all_required_artifacts_verified": allArtifacts,
		"fixture_only": options.Fixture, "host_deadline_and_adoption_not_evaluated": true, "adapter_library_sha256": librarySHA}, nil
}

func WriteReport(writer io.Writer, report map[string]any) error {
	body, err := canonical(report)
	if err != nil || len(body) > Limit {
		body = []byte(`{"schema_version":1,"final":false,"control_complete":false,"reason_code":"UPDATE_CONTROL_INVALID"}`)
	}
	_, err = writer.Write(append(body, '\n'))
	return err
}
