package verification

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"filegate.local/filegate/internal/hostvm"
	updatecontrol "filegate.local/filegate/internal/update"
)

// release-prepublish stops a separately built verification broker after the INTENT commit and the final authorization
// and capacity checks, just before the exclusive rename; a same-boot restart must prove no publication, then the same
// key re-authorizes and publishes the unchanged temp.
func init() { Register("release-prepublish", runReleasePrepublish) }

const releasePrepublishMarker = "FILEGATE_RELEASE_PREPUBLISH_MARKER"

var releasePrepublishSpec = releaseStopSpec{"filegate-release-prepublish-plan", "intent_synced_before_rename", releasePrepublishMarker, "internal/broker/release_prepublish_stop.go"}

type releasePrepublishExtra struct {
	Schema                int                        `json:"schema"`
	Kind                  string                     `json:"kind"`
	MainPlanSHA256        string                     `json:"main_plan_sha256"`
	DefinitionUpdateID    string                     `json:"definition_update_id"`
	DefinitionGeneration  int64                      `json:"definition_generation"`
	PreviousJobs          []string                   `json:"previous_jobs"`
	PreservedReleases     []string                   `json:"preserved_releases"`
	PreservedDestinations []releaseReplayDestination `json:"preserved_destinations"`
}

func releasePrepublishPreserved(h *Harness, extra releasePrepublishExtra) Object {
	jobs, releases, directories := Object{}, Object{}, Object{}
	for _, id := range extra.PreviousJobs {
		jobs[id] = Digest(Encoded(h.Query("SELECT * FROM jobs WHERE id=?", id)))
	}
	for _, id := range extra.PreservedReleases {
		releases[id] = Digest(Encoded([]any{h.Query("SELECT * FROM releases WHERE id=?", id), h.Query("SELECT * FROM release_publication_attempts WHERE release_id=? ORDER BY sequence", id), h.Query("SELECT * FROM release_authorizations WHERE release_id=? ORDER BY sequence", id)}))
	}
	for _, d := range extra.PreservedDestinations {
		directories[d.ID] = releaseReplayDirectory(h, d.ID, d.Path)
	}
	return Object{"jobs": jobs, "releases": releases, "directories": directories}
}

func runReleasePrepublish(h *Harness) {
	Must(os.Unsetenv(releaseBoundaryMarker))
	Must(os.Unsetenv(releasePrepublishMarker))
	h.Record["kind"] = "filegate-release-prepublish"
	h.Record["scope"] = "one Chapter 13 stop point: verification-overlay broker killed after the synchronized INTENT and the final authorization and capacity checks, before the exclusive rename; same-boot restart proves no publication, then the same key re-authorizes and publishes the unchanged temp; new job on a real VM/ClamAV PASS, dedicated state and private destination"
	h.Record["stop_point"] = releasePrepublishSpec.StopPoint
	h.Record["intake_attempted"] = false
	h.Record["publication_attempted"] = false
	h.Record["formal_state_used"] = false
	plan, receipt := releaseStopPlanChecks(h, releasePrepublishSpec)
	h.Check("prepublish_extra_plan_supplied", h.Inputs != "")
	body := deliveryRead(h.Inputs, 65536)
	var extra releasePrepublishExtra
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	Must(decoder.Decode(&extra))
	if decoder.Decode(new(any)) != io.EOF {
		panic(Failure{"RELEASE_PREPUBLISH_PLAN_TRAILING_DATA"})
	}
	h.Record["extra_plan_sha256"] = Digest(body)
	state := filepath.Dir(plan.DataDirectory)
	scoped := extra.Schema == 1 && extra.Kind == "filegate-release-prepublish-extra" && extra.MainPlanSHA256 == Str(h.Record, "plan_sha256") && len(extra.PreviousJobs) > 0 && len(extra.PreservedReleases) > 0 && len(extra.PreservedDestinations) > 0 && filepath.Dir(plan.Destination.Path) == state
	for _, id := range extra.PreviousJobs {
		scoped = scoped && deliveryJobID.MatchString(id)
	}
	for _, id := range extra.PreservedReleases {
		scoped = scoped && regexp.MustCompile(`^release_[0-9a-f]{32}$`).MatchString(id)
	}
	for _, d := range extra.PreservedDestinations {
		scoped = scoped && d.ID != plan.Destination.ID && d.Path != plan.Destination.Path && deliverySafePath(d.Path) && filepath.Dir(d.Path) == state && !releaseBoundaryFormal(h, d.Path)
	}
	h.Check("prepublish_extra_plan_scope", scoped)

	health := h.Start()
	h.Stop(false)
	gates := Map(receipt, "gates")
	h.Record["gate_probe_health"] = health
	h.Check("broker_health_matches_receipt_gates", health["stage0_passed"] == gates["stage0_passed"] && health["customer_operation_enabled"] == (Bool(gates, "stage0_passed") && Bool(gates, "stage3_completed")))
	h.Check("stage0_accepted_isolated_build", Bool(gates, "stage0_passed") && gates["stage3_completed"] == false && Bool(health, "stage0_passed") && Bool(health, "pass_enabled") && Bool(health, "release_enabled") && health["customer_operation_enabled"] == false)

	runtime, err := hostvm.New(plan.Scan.Workspace)
	Must(err)
	h.StopTimeout = releaseBoundaryStopTimeout
	pid := 0
	defer func() {
		if failure := recover(); failure != nil {
			h.Record["failure_state"] = releaseBoundaryFailureState(h, plan, runtime.State, pid)
			panic(failure)
		}
	}()
	h.Check("shared_runtime_slot_initially_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["data_identity"] = deliveryPrivate(h, "dedicated_state", plan.DataDirectory)
	deliveryPrivate(h, "dedicated_input_root", plan.InputRoot)
	h.Data, h.InputDirectory = plan.DataDirectory, plan.InputRoot
	h.Socket = filepath.Join(h.Data, "filegate.sock")
	h.Check("dedicated_state_registration", Exists(filepath.Join(h.Data, "state.sqlite")) && plan.Registration.Path == filepath.Join(h.Data, "update-runtime.json"))
	roots := h.Query("SELECT CAST(value AS TEXT) FROM config WHERE name='input_roots'")
	recorded := ""
	if len(roots) == 1 {
		recorded, _ = roots[0][0].(string)
	}
	h.Check("recorded_input_roots", recorded != "" && Equal(Decode([]byte(recorded)), Object{"alias": plan.InputRoot, "fixture": plan.InputRoot}))
	before := deliveryRowSnapshot(h)
	h.Check("dedicated_state_has_no_inflight_work", Int(before, "reservations", "count") == 0 && Int(before, "scan_queue", "count") == 0 && Int(before, "resource_pins", "count") == 0 && Int(before, "release_reservations", "count") == 0)
	control := Map(SnapshotUpdate(filepath.Join(h.Data, "state.sqlite"), true, false), "control")
	h.Check("no_active_update", Str(control, "active_update_id") == "")
	definition := deliveryAdoption(h, control, Decode(deliveryRead(plan.Registration.Path, 1<<20)))
	now, err := updatecontrol.ReadClock()
	Must(err)
	confirmed := Map(definition, "confirmed")
	h.Check("fresh_same_definition_no_update", Str(definition, "update_id") == extra.DefinitionUpdateID && Int(definition, "generation") == extra.DefinitionGeneration && now.Boot == Str(confirmed, "boot") && now.UTC >= Int(confirmed, "utc") && now.UTC-Int(confirmed, "utc") <= 85800 && now.ContinuousNS >= uint64(Int(confirmed, "continuous_ns")) && now.ContinuousNS-uint64(Int(confirmed, "continuous_ns")) <= 85800000000000)
	if !Exists(plan.Destination.Path) {
		Must(os.Mkdir(plan.Destination.Path, 0700))
	}
	h.Check("empty_dedicated_destination", len(releaseBoundaryEntries(plan.Destination.Path)) == 0)
	deliveryPrivate(h, "dedicated_destination", plan.Destination.Path)
	preserved := releasePrepublishPreserved(h, extra)
	h.Record["preserved_before"] = preserved

	serve := []string{"--vm-runner", plan.Scan.Runner.Path, "--vm-workspace", plan.Scan.Workspace, "--vm-proof", plan.Scan.Proof.Path, "--update-library-sha256", plan.LibrarySHA256, "--release-destination", plan.Destination.ID + "=" + plan.Destination.Path}
	for _, d := range extra.PreservedDestinations {
		serve = append(serve, "--release-destination", d.ID+"="+d.Path)
	}
	marker := filepath.Join(h.Out, "stop-marker.json")
	Must(os.Setenv(releasePrepublishMarker, marker))
	health = h.Start(serve...)
	Must(os.Unsetenv(releasePrepublishMarker))
	pid = h.Process.Process.Pid
	h.Check("prepublish_broker_gate_open", Bool(health, "stage0_passed") && Bool(health, "release_enabled") && health["customer_operation_enabled"] == false)

	h.Record["intake_attempted"] = true
	code, submitted := h.Submit("file", plan.Input.Path, Object{"idempotency_key": plan.Input.IdempotencyKey, "expected_type": plan.Input.ExpectedType, "expected_sha256": plan.Input.SHA256}, nil)
	jobID := Str(submitted, "job_id")
	isNew := deliveryJobID.MatchString(jobID)
	for _, id := range extra.PreviousJobs {
		isNew = isNew && jobID != id
	}
	h.Check("new_job_committed", code == 0 && isNew && Str(submitted, "input_receipt", "sha256") == plan.Input.SHA256 && Int(submitted, "input_receipt", "byte_size") == plan.Input.ByteSize)
	code, job := vmWaitCLI(h, jobID)
	h.Record["job_before_release"] = job
	versions := Map(job, "scan_details", "versions")
	h.Check("genuine_PASS_on_new_broker", code == 0 && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "PASS" && Bool(job, "coverage", "required_checks_complete") && Str(job, "coverage", "av_result") == "clean" && Bool(job, "runtime_cleanup_complete") && Bool(job, "release", "eligible") && Str(versions, "host_sha256") == plan.Broker.SHA256 && Str(versions, "definition_update_id") == extra.DefinitionUpdateID && Int(versions, "definition_generation") == extra.DefinitionGeneration)
	openReleases := "SELECT count(*) FROM releases WHERE state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED')"
	openBefore := releaseBoundaryCount(h, openReleases)

	h.Record["publication_attempted"] = true
	requested := Execute(h.Root, []string{h.Binary, "--data-dir", h.Data, "release", jobID, "--destination", plan.Destination.ID, "--idempotency-key", plan.ReleaseKey}, nil, 10*time.Second)
	h.Commands = append(h.Commands, Object{"operation": "release", "exit_code": requested.ExitCode})
	h.Responses = append(h.Responses, requested.Stdout, requested.Stderr)
	deadline := time.Now().Add(120 * time.Second)
	for h.ServiceAlive() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	h.Check("broker_stopped_before_rename", !h.ServiceAlive())
	h.Stop(true)
	stop := Decode(deliveryRead(marker, 4096))
	release, output, tempName := Str(stop, "release_id"), Str(stop, "output_name"), Str(stop, "temp_name")
	h.Record["stop_marker"] = stop
	h.Check("stop_marker_from_same_broker", Str(stop, "stop_point") == releasePrepublishSpec.StopPoint && Int(stop, "pid") == int64(pid) && release != "" && output != "" && tempName == release+".1.partial")
	if requested.ExitCode == 0 {
		first := Decode(requested.Stdout)
		h.Check("first_request_same_release", Str(first, "release_id") == release && Get(first, "replayed") == false)
	}

	// At the stop only INTENT is durable and the synchronized temp is still unconsumed: no final exists.
	final := filepath.Join(plan.Destination.Path, output)
	temp := filepath.Join(plan.Destination.Path, ".filegate-staging", tempName)
	records := QueryObjects(h, "SELECT data FROM releases WHERE id=?", release)
	h.Check("stop_release_ready_unknown", len(records) == 1 && Str(records[0], "receipt", "state") == "READY" && Str(records[0], "receipt", "publication_status") == "UNKNOWN" && Get(records[0], "receipt", "publication_confirmed") == false && Int(records[0], "generation") == 1 && Str(records[0], "temp_name") == tempName)
	stopped := releaseBoundaryLedger(h, release)
	h.Record["ledger_at_stop"] = stopped
	attempts := List(stopped, "attempts")
	h.Check("stop_single_intent_attempt", len(attempts) == 1 && Str(attempts[0], "state") == "INTENT")
	h.Check("stop_no_final_and_synchronized_temp_kept", !Exists(final) && Exists(temp) && FileDigest(temp) == plan.Input.SHA256 && Int(releaseBoundaryIdentity(temp), "size") == plan.Input.ByteSize && Int(releaseBoundaryIdentity(temp), "inode") == Int(records[0], "temp_identity", "inode"))
	tempIdentity := releaseBoundaryIdentity(temp)
	h.Check("stop_resources_held", Int(stopped, "release_pins") == 1 && Int(stopped, "release_reservations") == 1 && Int(stopped, "open_releases") == openBefore+1 && releaseBoundaryCount(h, "SELECT count(*) FROM release_authorizations WHERE release_id=?", release) == 1)

	// The same verification binary runs normally: the marker variable is unset, so the hook returns.
	h.Record["restart_mode"] = "same verification overlay binary with the stop marker variable unset"
	h.Start(serve...)
	code, proven := h.CLI("release-status", release)
	h.Record["release_after_same_boot_recovery"] = proven
	h.Check("same_boot_recovery_revalidation_required", code == 0 && Str(proven, "release_id") == release && Str(proven, "output_name") == output && Str(proven, "state") == "REVALIDATION_REQUIRED" && Str(proven, "publication_status") == "NOT_PUBLISHED" && Get(proven, "abort_requested") == false)
	recovered := releaseBoundaryLedger(h, release)
	h.Record["ledger_after_same_boot_recovery"] = recovered
	attempts = List(recovered, "attempts")
	h.Check("no_publication_proven_same_boot", len(attempts) == 1 && Str(attempts[0], "state") == "NO_PUBLICATION_PROVEN" && Str(attempts[0], "evidence") == "same_boot_unchanged_unconsumed_exclusive_temp")
	h.Check("temp_unchanged_and_resources_still_held", !Exists(final) && Exists(temp) && Equal(releaseBoundaryIdentity(temp), tempIdentity) && FileDigest(temp) == plan.Input.SHA256 && Int(recovered, "release_pins") == 1 && Int(recovered, "release_reservations") == 1 && Int(recovered, "open_releases") == openBefore+1)
	h.Record["temp_identity_before_resend"] = tempIdentity

	code, resent := h.CLI("release", jobID, "--destination", plan.Destination.ID, "--idempotency-key", plan.ReleaseKey)
	h.Record["same_key_resend"] = resent
	h.Check("same_key_resend_reauthorizes_and_commits", code == 0 && Bool(resent, "replayed") && Str(resent, "release_id") == release && Str(resent, "output_name") == output && Str(resent, "state") == "COMMITTED")
	code, committed := h.CLI("release-status", release)
	h.Record["release_after_resend"] = committed
	h.Check("release_committed_after_resume", code == 0 && Str(committed, "state") == "COMMITTED" && Bool(committed, "success") && Str(committed, "final_validation") == "verified" && Str(committed, "output_state") == "MATCH" && Str(committed, "publication_status") == "PUBLISHED" && Bool(committed, "resources_finalized"))
	records = QueryObjects(h, "SELECT data FROM releases WHERE id=?", release)
	resumed := releaseBoundaryLedger(h, release)
	h.Record["ledger_after_resend"] = resumed
	attempts = List(resumed, "attempts")
	h.Check("history_no_publication_then_published", len(records) == 1 && Int(records[0], "generation") == 1 && Str(records[0], "temp_name") == tempName && len(attempts) == 2 && Str(attempts[0], "state") == "NO_PUBLICATION_PROVEN" && Str(attempts[0], "evidence") == "same_boot_unchanged_unconsumed_exclusive_temp" && Str(attempts[1], "state") == "PUBLISHED" && Str(attempts[1], "evidence") == "exclusive_rename_returned_success" && releaseBoundaryCount(h, "SELECT count(*) FROM release_authorizations WHERE release_id=?", release) == 2)
	h.Check("final_is_the_stopped_temp", Exists(final) && !Exists(temp) && Equal(releaseBoundaryIdentity(final), tempIdentity) && FileDigest(final) == plan.Input.SHA256 && Equal(releaseBoundaryEntries(plan.Destination.Path), []string{".filegate-staging", output}) && len(releaseBoundaryEntries(filepath.Join(plan.Destination.Path, ".filegate-staging"))) == 0)
	h.Check("resources_settled_once", Int(resumed, "release_pins") == 0 && Int(resumed, "release_reservations") == 0 && Int(resumed, "open_releases") == openBefore)

	settled := deliveryRowSnapshot(h)
	destination := releaseReplayDirectory(h, plan.Destination.ID, plan.Destination.Path)
	code, again := h.CLI("release", jobID, "--destination", plan.Destination.ID, "--idempotency-key", plan.ReleaseKey)
	h.Check("sequential_resend_changes_nothing", code == 0 && Bool(again, "replayed") && Str(again, "release_id") == release && Str(again, "state") == "COMMITTED" && Equal(deliveryRowSnapshot(h), settled) && Equal(releaseReplayDirectory(h, plan.Destination.ID, plan.Destination.Path), destination))
	h.Check("previous_jobs_releases_and_destinations_unchanged", Equal(releasePrepublishPreserved(h, extra), preserved))
	h.Stop(false)
	h.Check("shared_runtime_slot_finally_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["release_id"] = release
	h.Record["job_id"] = jobID
}
