package verification

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"filegate.local/filegate/internal/hostvm"
	updatecontrol "filegate.local/filegate/internal/update"
)

// release-replay sends two concurrent ordinary-API releases with one new key for an already genuine PASS job, then the
// same key for another destination; it reuses the reviewed release-boundary plan for every broker and runtime binding.
func init() { Register("release-replay", runReleaseReplay) }

type releaseReplayDestination struct {
	ID   string `json:"destination_id"`
	Path string `json:"path"`
}

type releaseReplayPlan struct {
	Schema               int    `json:"schema"`
	Kind                 string `json:"kind"`
	BoundaryPlanSHA256   string `json:"boundary_plan_sha256"`
	JobID                string `json:"job_id"`
	AttemptID            string `json:"attempt_id"`
	InputSHA256          string `json:"input_sha256"`
	InputByteSize        int64  `json:"input_byte_size"`
	DefinitionUpdateID   string `json:"definition_update_id"`
	DefinitionGeneration int64  `json:"definition_generation"`
	BoundaryRelease      struct {
		ReleaseID  string `json:"release_id"`
		OutputPath string `json:"output_path"`
	} `json:"boundary_release"`
	ReleaseKey            string                   `json:"release_key"`
	ConcurrentDestination releaseReplayDestination `json:"concurrent_destination"`
	ConflictDestination   releaseReplayDestination `json:"conflict_destination"`
}

type releaseReplayResult struct {
	Status                  int
	Body                    []byte
	Error                   string
	Started, Sent, Received time.Time
}

// releaseReplayRequest is one ordinary-API release on its own connection; it never touches shared harness records.
func releaseReplayRequest(socket, jobID, destination, key string) (r releaseReplayResult) {
	r.Started = time.Now()
	body, err := json.Marshal(map[string]string{"destination_id": destination})
	if err != nil {
		r.Error = err.Error()
		return
	}
	c, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		r.Error = err.Error()
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	req, err := http.NewRequest("POST", "http://filegate/v1/jobs/"+jobID+"/release", bytes.NewReader(body))
	if err != nil {
		r.Error = err.Error()
		return
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	if err = req.Write(c); err != nil {
		r.Error = err.Error()
		return
	}
	r.Sent = time.Now()
	response, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		r.Error = err.Error()
		return
	}
	defer response.Body.Close()
	r.Body, err = io.ReadAll(response.Body)
	r.Received = time.Now()
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.Status = response.StatusCode
	return
}

func releaseReplayDirectory(h *Harness, label, path string) Object {
	entries := releaseBoundaryEntries(path)
	files := Object{}
	for _, name := range entries {
		full := filepath.Join(path, name)
		identity := releaseBoundaryIdentity(full)
		if info, err := os.Lstat(full); err == nil && info.Mode().IsRegular() {
			identity["sha256"] = FileDigest(full)
		}
		files[name] = identity
	}
	return Object{"label": label, "identity": releaseBoundaryIdentity(path), "entries": entries, "files": files}
}

func runReleaseReplay(h *Harness) {
	Must(os.Unsetenv(releaseBoundaryMarker))
	h.Record["kind"] = "filegate-release-replay"
	h.Record["scope"] = "two ordinary-API scenarios on the isolated stage-0-accepted verification state: two concurrent same-key releases of an existing genuine PASS job to one new private destination, then the same key for another valid private destination; no VM, AV, update, rescan or fault injection"
	h.Record["publication_attempted"] = false
	h.Record["formal_state_used"] = false
	boundary, receipt := releaseBoundaryPlanChecks(h)
	h.Check("replay_plan_supplied", h.Inputs != "")
	body := deliveryRead(h.Inputs, 65536)
	var plan releaseReplayPlan
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	Must(decoder.Decode(&plan))
	if decoder.Decode(new(any)) != io.EOF {
		panic(Failure{"RELEASE_REPLAY_PLAN_TRAILING_DATA"})
	}
	h.Record["replay_plan_sha256"] = Digest(body)
	identifier := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	state := filepath.Dir(boundary.DataDirectory)
	destinations := []releaseReplayDestination{plan.ConcurrentDestination, plan.ConflictDestination}
	placed := plan.ConcurrentDestination.ID != plan.ConflictDestination.ID && plan.ConcurrentDestination.Path != plan.ConflictDestination.Path
	for _, d := range destinations {
		placed = placed && identifier.MatchString(d.ID) && d.ID != boundary.Destination.ID && deliverySafePath(d.Path) && filepath.Dir(d.Path) == state && d.Path != boundary.Destination.Path && !releaseBoundaryFormal(h, d.Path)
	}
	h.Check("replay_plan_scope", plan.Schema == 1 && plan.Kind == "filegate-release-replay-plan" && plan.BoundaryPlanSHA256 == Str(h.Record, "plan_sha256") && deliveryJobID.MatchString(plan.JobID) && regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(plan.AttemptID) && plan.InputSHA256 == boundary.Input.SHA256 && plan.InputByteSize == boundary.Input.ByteSize && plan.ReleaseKey != "" && plan.ReleaseKey != boundary.ReleaseKey && placed)
	h.Check("boundary_output_in_boundary_destination", filepath.Dir(plan.BoundaryRelease.OutputPath) == boundary.Destination.Path && strings.HasPrefix(filepath.Base(plan.BoundaryRelease.OutputPath), plan.BoundaryRelease.ReleaseID+"."))

	health := h.Start()
	h.Stop(false)
	gates := Map(receipt, "gates")
	h.Record["gate_probe_health"] = health
	h.Check("broker_health_matches_receipt_gates", health["stage0_passed"] == gates["stage0_passed"] && health["customer_operation_enabled"] == (Bool(gates, "stage0_passed") && Bool(gates, "stage3_completed")))
	h.Check("stage0_accepted_isolated_build", Bool(gates, "stage0_passed") && gates["stage3_completed"] == false && Bool(health, "stage0_passed") && Bool(health, "release_enabled") && health["customer_operation_enabled"] == false)

	runtime, err := hostvm.New(boundary.Scan.Workspace)
	Must(err)
	h.StopTimeout = releaseBoundaryStopTimeout
	pid := 0
	defer func() {
		if failure := recover(); failure != nil {
			h.Record["failure_state"] = releaseBoundaryFailureState(h, releaseBoundaryPlan{DataDirectory: boundary.DataDirectory}, runtime.State, pid)
			panic(failure)
		}
	}()
	h.Check("shared_runtime_slot_initially_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["data_identity"] = deliveryPrivate(h, "dedicated_state", boundary.DataDirectory)
	deliveryPrivate(h, "dedicated_input_root", boundary.InputRoot)
	h.Data, h.InputDirectory = boundary.DataDirectory, boundary.InputRoot
	h.Socket = filepath.Join(h.Data, "filegate.sock")
	roots := h.Query("SELECT CAST(value AS TEXT) FROM config WHERE name='input_roots'")
	recorded := ""
	if len(roots) == 1 {
		recorded, _ = roots[0][0].(string)
	}
	h.Check("recorded_input_roots", recorded != "" && Equal(Decode([]byte(recorded)), Object{"alias": boundary.InputRoot, "fixture": boundary.InputRoot}))
	control := Map(SnapshotUpdate(filepath.Join(h.Data, "state.sqlite"), true, false), "control")
	h.Check("no_active_update", Str(control, "active_update_id") == "")
	definition := deliveryAdoption(h, control, Decode(deliveryRead(boundary.Registration.Path, 1<<20)))
	now, err := updatecontrol.ReadClock()
	Must(err)
	confirmed := Map(definition, "confirmed")
	h.Check("fresh_same_definition_no_update", Str(definition, "update_id") == plan.DefinitionUpdateID && Int(definition, "generation") == plan.DefinitionGeneration && now.Boot == Str(confirmed, "boot") && now.UTC >= Int(confirmed, "utc") && now.UTC-Int(confirmed, "utc") <= 85800 && now.ContinuousNS >= uint64(Int(confirmed, "continuous_ns")) && now.ContinuousNS-uint64(Int(confirmed, "continuous_ns")) <= 85800000000000)
	for _, d := range destinations {
		if !Exists(d.Path) {
			Must(os.Mkdir(d.Path, 0700))
		}
		h.Check("empty_private_destination_"+d.ID, len(releaseBoundaryEntries(d.Path)) == 0)
		deliveryPrivate(h, "private_destination_"+d.ID, d.Path)
	}
	boundaryBefore := releaseReplayDirectory(h, "boundary", boundary.Destination.Path)
	h.Check("boundary_output_present", FileDigest(plan.BoundaryRelease.OutputPath) == boundary.Input.SHA256)

	serve := []string{"--vm-runner", boundary.Scan.Runner.Path, "--vm-workspace", boundary.Scan.Workspace, "--vm-proof", boundary.Scan.Proof.Path, "--update-library-sha256", boundary.LibrarySHA256, "--release-destination", boundary.Destination.ID + "=" + boundary.Destination.Path, "--release-destination", plan.ConcurrentDestination.ID + "=" + plan.ConcurrentDestination.Path, "--release-destination", plan.ConflictDestination.ID + "=" + plan.ConflictDestination.Path}
	health = h.Start(serve...)
	pid = h.Process.Process.Pid
	h.Check("replay_broker_gate_open", Bool(health, "stage0_passed") && Bool(health, "release_enabled") && health["customer_operation_enabled"] == false)
	status, job := h.Request("GET", "/v1/jobs/"+plan.JobID, nil, nil, nil)
	h.Record["job_before"] = job
	versions := Map(job, "scan_details", "versions")
	h.Check("existing_genuine_PASS_still_eligible", status == 200 && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "PASS" && Bool(job, "release", "eligible") && Bool(job, "coverage", "required_checks_complete") && Str(job, "coverage", "av_result") == "clean" && Str(job, "attempt_id") == plan.AttemptID && Str(job, "input_receipt", "sha256") == plan.InputSHA256 && Int(job, "input_receipt", "byte_size") == plan.InputByteSize && Str(versions, "definition_update_id") == plan.DefinitionUpdateID && Int(versions, "definition_generation") == plan.DefinitionGeneration && Str(versions, "host_sha256") == boundary.Broker.SHA256)
	openReleases := "SELECT count(*) FROM releases WHERE state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED')"
	releasesBefore, openBefore := releaseBoundaryCount(h, "SELECT count(*) FROM releases"), releaseBoundaryCount(h, openReleases)
	rowsBefore := deliveryRowSnapshot(h)
	WriteJSON(filepath.Join(h.Out, "rows-before.json"), rowsBefore)
	h.Check("baseline_no_held_release_resources", Int(rowsBefore, "resource_pins", "count") == 0 && Int(rowsBefore, "release_reservations", "count") == 0 && Int(rowsBefore, "reservations", "count") == 0 && Int(rowsBefore, "scan_queue", "count") == 0)

	// Scenario 1: both requests wait on one start signal; each goroutine fills only its own slot.
	h.Record["publication_attempted"] = true
	results := make([]releaseReplayResult, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = releaseReplayRequest(h.Socket, plan.JobID, plan.ConcurrentDestination.ID, plan.ReleaseKey)
		}(i)
	}
	close(start)
	wg.Wait()
	requests := []Object{}
	values := []Object{}
	for i, r := range results {
		h.Responses = append(h.Responses, r.Body)
		row := Object{"request": i, "status": r.Status, "error": r.Error, "started": r.Started.UTC().Format(time.RFC3339Nano), "sent": r.Sent.UTC().Format(time.RFC3339Nano), "received": r.Received.UTC().Format(time.RFC3339Nano), "body_sha256": Digest(r.Body)}
		requests = append(requests, row)
		h.Check("concurrent_request_completed_"+string(rune('a'+i)), r.Error == "" && (r.Status == 200 || r.Status == 202))
		values = append(values, Decode(r.Body))
	}
	latestSent, earliestReceived := results[0].Sent, results[0].Received
	for _, r := range results[1:] {
		if r.Sent.After(latestSent) {
			latestSent = r.Sent
		}
		if r.Received.Before(earliestReceived) {
			earliestReceived = r.Received
		}
	}
	h.Record["concurrent_requests"] = requests
	h.Record["concurrent_overlap_ns"] = earliestReceived.Sub(latestSent).Nanoseconds()
	h.Check("both_requests_in_flight_together", latestSent.Before(earliestReceived))
	release, output := Str(values[0], "release_id"), Str(values[0], "output_name")
	fresh := 0
	for _, v := range values {
		if v["replayed"] == false {
			fresh++
		}
	}
	h.Check("concurrent_same_release_and_name", release != "" && output != "" && Str(values[1], "release_id") == release && Str(values[1], "output_name") == output && fresh == 1 && (Bool(values[0], "replayed") || Bool(values[1], "replayed")))
	var final Object
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		code, value := h.Request("GET", "/v1/releases/"+release, nil, nil, nil)
		h.Check("release_status_available", code == 200)
		if s := Str(value, "state"); s == "COMMITTED" || s == "ABORTED" || s == "PUBLISHED_UNVERIFIED" || s == "REVALIDATION_REQUIRED" || s == "RECOVERY_REQUIRED" {
			final = value
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.Record["release_after_concurrency"] = final
	h.Check("concurrent_release_committed", Str(final, "state") == "COMMITTED" && Str(final, "release_id") == release && Str(final, "output_name") == output && Bool(final, "success") && Str(final, "final_validation") == "verified" && Str(final, "output_state") == "MATCH" && Str(final, "publication_status") == "PUBLISHED" && Bool(final, "resources_finalized"))
	records := QueryObjects(h, "SELECT data FROM releases WHERE id=?", release)
	attempts := QueryObjects(h, "SELECT data FROM release_publication_attempts WHERE release_id=? ORDER BY sequence", release)
	h.Check("one_release_row_and_one_publication", releaseBoundaryCount(h, "SELECT count(*) FROM releases") == releasesBefore+1 && len(records) == 1 && Int(records[0], "generation") == 1 && Str(records[0], "destination", "path") == plan.ConcurrentDestination.Path && len(attempts) == 1 && Str(attempts[0], "state") == "PUBLISHED" && Str(attempts[0], "evidence") == "exclusive_rename_returned_success")
	finalPath := filepath.Join(plan.ConcurrentDestination.Path, output)
	concurrent := releaseReplayDirectory(h, "concurrent", plan.ConcurrentDestination.Path)
	h.Check("single_output_matches_input", Equal(concurrent["entries"], []string{".filegate-staging", output}) && len(releaseBoundaryEntries(filepath.Join(plan.ConcurrentDestination.Path, ".filegate-staging"))) == 0 && FileDigest(finalPath) == plan.InputSHA256 && Int(releaseBoundaryIdentity(finalPath), "size") == plan.InputByteSize)
	ledger := releaseBoundaryLedger(h, release)
	h.Record["ledger_after_concurrency"] = ledger
	h.Check("resources_back_to_baseline", Int(ledger, "release_pins") == 0 && Int(ledger, "release_reservations") == 0 && Int(ledger, "open_releases") == openBefore)
	h.Check("boundary_output_unchanged_after_concurrency", Equal(releaseReplayDirectory(h, "boundary", boundary.Destination.Path), boundaryBefore))
	rowsAfter := deliveryRowSnapshot(h)
	WriteJSON(filepath.Join(h.Out, "rows-after-concurrency.json"), rowsAfter)

	// Scenario 3: the same key for another valid destination must be refused without touching rows or files.
	conflictBefore := releaseReplayDirectory(h, "conflict", plan.ConflictDestination.Path)
	status, conflict := h.Request("POST", "/v1/jobs/"+plan.JobID+"/release", Object{"destination_id": plan.ConflictDestination.ID}, map[string]string{"Idempotency-Key": plan.ReleaseKey}, nil)
	h.Record["same_key_other_destination"] = Object{"status": status, "response": conflict}
	h.Check("same_key_other_destination_idempotency_conflict", status == 409 && ErrorCode(conflict) == "IDEMPOTENCY_CONFLICT")
	rowsConflict := deliveryRowSnapshot(h)
	WriteJSON(filepath.Join(h.Out, "rows-after-conflict.json"), rowsConflict)
	h.Check("conflict_changes_no_rows", Equal(rowsConflict, rowsAfter))
	h.Check("conflict_changes_no_files", Equal(releaseReplayDirectory(h, "concurrent", plan.ConcurrentDestination.Path), concurrent) && Equal(releaseReplayDirectory(h, "conflict", plan.ConflictDestination.Path), conflictBefore) && Equal(releaseReplayDirectory(h, "boundary", boundary.Destination.Path), boundaryBefore))
	h.Record["directories"] = Object{"boundary": boundaryBefore, "concurrent": concurrent, "conflict_before": conflictBefore}
	h.Stop(false)
	h.Check("shared_runtime_slot_finally_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["release_id"] = release
}
