package fixtures

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"filegate.local/filegate/internal/freshclamadapter"
	control "filegate.local/filegate/internal/update"
)

type freshclamCase struct {
	id       string
	status   int
	retry    string
	datFail  bool
	requests int
}

var freshclamCases = []freshclamCase{
	{"429-delta", 429, "3600", false, 1}, {"429-fallback", 429, "", false, 1},
	{"403-fallback", 403, "", false, 1}, {"403-long", 403, "864000", false, 1},
	{"429-long", 429, "864000", false, 1}, {"429-http-date", 429, "date", false, 1},
	{"429-dat-save-failure", 429, "3600", true, 1}, {"success-then-429", 429, "3600", false, 2},
	{"success-then-429-truncated", 429, "3600", false, 2},
}

func hostExchange(reader *bufio.Reader, output io.Writer, value any) (map[string]any, error) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > 1<<20 {
		return nil, invalid
	}
	if _, err = output.Write(append(body, '\n')); err != nil {
		return nil, err
	}
	answer, err := reader.ReadSlice('\n')
	var result map[string]any
	if err != nil || len(answer) > 8192 || decode(answer, &result) != nil {
		return nil, invalid
	}
	return result, nil
}

func adapter(library, database, temporary string, request map[string]any) (map[string]any, error) {
	body, err := json.Marshal(request)
	if err != nil || len(body) > 4096 {
		return nil, invalid
	}
	arguments := []string{"/filegate-freshclam", "--library", library, "--database-dir", database, "--temp-dir", temporary, "--fixture"}
	stdout, _, _, err := command(arguments, body, 1<<20, []string{"PATH=/bin:/usr/bin", "LC_ALL=C"})
	var result map[string]any
	if err != nil || decode(stdout, &result) != nil {
		return nil, invalid
	}
	return result, nil
}

func snapshot(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func Freshclam(library, work, output, mode string, input io.Reader, channel io.Writer) error {
	if !guest() || mode != "" && mode != "first" && mode != "restore" {
		return invalid
	}
	canonical, err := filepath.EvalSymlinks(library)
	if err != nil || !strings.HasPrefix(canonical, freshclamadapter.Prefix+"/lib/") {
		return invalid
	}
	library = canonical
	librarySHA, err := fileDigest(library)
	if err != nil || os.Mkdir(work, 0700) != nil {
		return invalid
	}
	reader := bufio.NewReaderSize(input, 8193)
	var results []map[string]any
	allPassed := true
	for index, c := range freshclamCases {
		directory := filepath.Join(work, c.id)
		database, temporary := filepath.Join(directory, "db"), filepath.Join(directory, "tmp")
		if os.Mkdir(directory, 0700) != nil || os.Mkdir(database, 0700) != nil || os.Mkdir(temporary, 0700) != nil {
			return invalid
		}
		if c.datFail {
			if os.Mkdir(filepath.Join(database, "freshclam.dat"), 0700) != nil {
				return invalid
			}
		} else if os.WriteFile(filepath.Join(database, "freshclam.dat"), []byte("stale synthetic dat must not replace host snapshot"), 0600) != nil {
			return invalid
		}
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		var mutex sync.Mutex
		var requests []string
		count := func() int { mutex.Lock(); defer mutex.Unlock(); return len(requests) }
		server := &http.Server{ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mutex.Lock()
			requests = append(requests, r.URL.RequestURI())
			sequence := len(requests)
			mutex.Unlock()
			status := c.status
			if strings.HasPrefix(c.id, "success-then-429") && sequence == 1 {
				status = http.StatusOK
			}
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			if c.retry != "" {
				retry := c.retry
				if retry == "date" {
					retry = time.Now().Add(7200 * time.Second).UTC().Format(http.TimeFormat)
				}
				w.Header().Set("Retry-After", retry)
			}
			body := []byte{}
			if status == http.StatusOK {
				body = []byte("FileGate.Harmless.Marker:0:*:46696c6547617465206861726d6c657373\n")
			}
			length := len(body)
			if strings.HasSuffix(c.id, "-truncated") && status == 429 {
				length = 100
			}
			w.Header().Set("Content-Length", strconv.Itoa(length))
			w.Header().Set("Connection", "close")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
		served := make(chan error, 1)
		go func() { served <- server.Serve(listener) }()
		initial := map[string]any{"schema_version": 1, "engine": control.Engine, "adapter": control.Adapter,
			"uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "retry_after_utc": 0, "max_retry_after_utc": 0, "last_ray": ""}
		urls := []string{}
		for n := 0; n < 3; n++ {
			urls = append(urls, "http://"+listener.Addr().String()+"/probe"+strconv.Itoa(n)+".ndb")
		}
		request := map[string]any{"schema_version": 1, "update_id": "update_fixture_" + strconv.Itoa(index), "base_generation": index,
			"control_snapshot": initial, "fixture_urls": urls}
		if mode != "" {
			reply, exchangeErr := hostExchange(reader, channel, map[string]any{"event": "freshclam_control_ready", "id": c.id, "library_sha256": librarySHA})
			if exchangeErr != nil {
				server.Close()
				<-served
				return exchangeErr
			}
			if reply["event"] == "freshclam_control_skip" && reply["id"] == c.id && reply["reason"] == "UPDATE_STATE_UNKNOWN" && mode == "restore" {
				results = append(results, map[string]any{"id": c.id, "expectation_met": true, "skipped_unknown": true, "actual_requests": count()})
				server.Close()
				<-served
				continue
			}
			provided, ok := reply["request"].(map[string]any)
			if len(reply) != 3 || reply["event"] != "freshclam_control_request" || reply["id"] != c.id || !ok {
				server.Close()
				<-served
				return invalid
			}
			request = provided
			request["fixture_urls"] = urls
			initial = snapshot(request["control_snapshot"])
		}
		initialBody, err := json.Marshal(request)
		var initialRequest map[string]any
		if err != nil || decode(initialBody, &initialRequest) != nil {
			server.Close()
			<-served
			return invalid
		}
		started := time.Now().Unix()
		first, callErr := adapter(library, database, temporary, request)
		requestsFirst := count()
		var replay map[string]any
		if callErr == nil && mode != "" {
			reply, exchangeErr := hostExchange(reader, channel, map[string]any{"event": "freshclam_control_final", "id": c.id, "report": first})
			state := "UNKNOWN"
			if first["control_complete"] == true {
				state = "COOLDOWN"
			}
			if exchangeErr != nil || !same(reply, map[string]any{"event": "freshclam_control_committed", "id": c.id, "state": state}) {
				callErr = invalid
			}
		}
		if callErr == nil && first["control_complete"] == true && mode == "" {
			updateID, ok := request["update_id"].(string)
			if !ok {
				server.Close()
				<-served
				return invalid
			}
			request["update_id"] = updateID + "_restored"
			request["base_generation"] = number(request["base_generation"]) + 1
			request["control_snapshot"] = first["control_snapshot"]
			replay, callErr = adapter(library, database, temporary, request)
		}
		duration, _ := strconv.ParseInt(c.retry, 10, 64)
		if c.status == 403 {
			duration = max(duration, 86400)
		} else if c.retry == "date" {
			duration = 7200
		} else if c.retry == "" {
			duration = 14400
		}
		controlSnapshot := snapshot(first["control_snapshot"])
		meets := callErr == nil && first["control_complete"] == true && first["final"] == true && first["all_network_requests_finished"] == true &&
			requestsFirst == c.requests && count() == requestsFirst && number(first["request_count"]) == int64(c.requests) && first["all_required_origin_confirmations"] == false &&
			controlSnapshot["uuid"] == initial["uuid"] && number(controlSnapshot["max_retry_after_utc"]) >= started+duration-2
		if mode != "first" {
			meets = meets && replay != nil && replay["control_complete"] == true && number(replay["request_count"]) == 0 &&
				number(snapshot(replay["control_snapshot"])["max_retry_after_utc"]) >= number(controlSnapshot["max_retry_after_utc"])
		}
		if c.datFail {
			meets = meets && number(first["dat_save_failures"]) > 0
		}
		if c.status == 429 {
			rows, _ := first["definitions"].([]any)
			requested := []map[string]any{}
			for _, row := range rows {
				value, ok := row.(map[string]any)
				if ok && number(value["status"]) >= 0 {
					requested = append(requested, value)
				}
			}
			meets = meets && len(requested) != 0 && number(requested[len(requested)-1]["status"]) == 0 && requested[len(requested)-1]["origin_confirmed"] == false
		}
		if c.retry == "date" {
			meets = meets && snapshot(first["response"])["retry_after_kind"] == "http_date"
		}
		if strings.HasSuffix(c.id, "-truncated") {
			meets = callErr == nil && first["control_complete"] == false && first["control_snapshot"] == nil && first["reason_code"] == "UPDATE_STATE_UNKNOWN" && count() == c.requests && number(first["request_count"]) == int64(c.requests) && replay == nil
		}
		if mode == "restore" {
			meets = callErr == nil && first["control_complete"] == true && first["final"] == true && requestsFirst == 0 && count() == 0 && number(first["request_count"]) == 0 &&
				controlSnapshot["uuid"] == initial["uuid"] && same(controlSnapshot["max_retry_after_utc"], initial["max_retry_after_utc"])
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		server.Shutdown(ctx)
		cancel()
		server.Close()
		<-served
		expectedRequests := c.requests
		if mode == "restore" {
			expectedRequests = 0
		}
		results = append(results, map[string]any{"id": c.id, "expected_requests": expectedRequests, "actual_requests": count(), "host_control_mode": mode,
			"dat_save_failure_injected": c.datFail, "expectation_met": meets, "initial_request": initialRequest, "first_report": first, "restored_report": replay})
		allPassed = allPassed && meets
	}
	result := map[string]any{"schema_version": 1, "evidence_kind": "target_guest_measurement", "fixture_only": true,
		"cases": results, "all_expectations_met": allPassed, "remaining_required_evidence": []string{"host clock normalization and persistent generation", "600 second deadline and process stop", "real official database differential/full acquisition", "all update crash points"}}
	if err = write(output, result); err != nil {
		return err
	}
	if !allPassed {
		return invalid
	}
	return nil
}
