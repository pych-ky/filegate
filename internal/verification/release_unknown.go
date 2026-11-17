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

// release-unknown stops the reviewed prepublish verification broker before the rename, moves only that release's temp to
// a private holding directory, and checks that a restart cannot prove publication; cleanup restores the same temp, lets
// the broker prove no publication, and aborts through the ordinary API.
func init() { Register("release-unknown", runReleaseUnknown) }

type releaseUnknownPlan struct {
	Schema                int                        `json:"schema"`
	Kind                  string                     `json:"kind"`
	MainPlanSHA256        string                     `json:"main_plan_sha256"`
	JobID                 string                     `json:"job_id"`
	AttemptID             string                     `json:"attempt_id"`
	DefinitionUpdateID    string                     `json:"definition_update_id"`
	DefinitionGeneration  int64                      `json:"definition_generation"`
	ReleaseKey            string                     `json:"release_key"`
	Destination           releaseReplayDestination   `json:"destination"`
	HoldingPath           string                     `json:"holding_path"`
	PreviousJobs          []string                   `json:"previous_jobs"`
	PreservedReleases     []string                   `json:"preserved_releases"`
	PreservedDestinations []releaseReplayDestination `json:"preserved_destinations"`
}

func releaseUnknownIdentity(h *Harness, label, path string) Object {
	identity, err := releaseUnknownStat(path)
	Must(err)
	identity["sha256"] = FileDigest(path)
	h.Record[label] = identity
	return identity
}

type releaseUnknownCaseSpec struct{ Kind, Scope, PlanKind string }

// releaseUnknownRun is the unknown state reached by the shared driver, handed to the suite-specific continuation.
type releaseUnknownRun struct {
	extra                                         releaseUnknownPlan
	serve                                         []string
	release, final, temp, held, staging, tempName string
	tempIdentity, unknownRows                     Object
	openBefore                                    int64
}

func runReleaseUnknown(h *Harness) {
	releaseUnknownCase(h, releaseUnknownCaseSpec{"filegate-release-unknown", "unresolved INTENT with neither final nor temp: the reviewed prepublish broker stops before the rename, the release temp is moved to a private holding directory, and a same-boot restart and same-key resend must not publish, copy again or settle; cleanup restores the same temp and aborts through the ordinary API; existing genuine PASS job, dedicated state and private destination", "filegate-release-unknown-plan"}, releaseUnknownResendAndAbort)
}

func releaseUnknownCase(h *Harness, spec releaseUnknownCaseSpec, settle func(*Harness, *releaseUnknownRun)) {
	Must(os.Unsetenv(releaseBoundaryMarker))
	Must(os.Unsetenv(releasePrepublishMarker))
	h.Record["kind"] = spec.Kind
	h.Record["scope"] = spec.Scope
	h.Record["publication_attempted"] = false
	h.Record["formal_state_used"] = false
	h.Record["temp_in_holding"] = false
	plan, receipt := releaseStopPlanChecks(h, releasePrepublishSpec)
	h.Check("unknown_plan_supplied", h.Inputs != "")
	body := deliveryRead(h.Inputs, 65536)
	var extra releaseUnknownPlan
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	Must(decoder.Decode(&extra))
	if decoder.Decode(new(any)) != io.EOF {
		panic(Failure{"RELEASE_UNKNOWN_PLAN_TRAILING_DATA"})
	}
	h.Record["unknown_plan_sha256"] = Digest(body)
	state := filepath.Dir(plan.DataDirectory)
	identifier := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	scoped := extra.Schema == 1 && extra.Kind == spec.PlanKind && extra.MainPlanSHA256 == Str(h.Record, "plan_sha256") && deliveryJobID.MatchString(extra.JobID) && regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(extra.AttemptID) && extra.ReleaseKey != "" && extra.ReleaseKey != plan.ReleaseKey && identifier.MatchString(extra.Destination.ID) && deliverySafePath(extra.Destination.Path) && filepath.Dir(extra.Destination.Path) == state && deliverySafePath(extra.HoldingPath) && filepath.Dir(extra.HoldingPath) == state && extra.HoldingPath != extra.Destination.Path && !releaseBoundaryFormal(h, extra.Destination.Path) && !releaseBoundaryFormal(h, extra.HoldingPath) && len(extra.PreservedDestinations) > 0
	for _, id := range extra.PreviousJobs {
		scoped = scoped && deliveryJobID.MatchString(id)
	}
	for _, id := range extra.PreservedReleases {
		scoped = scoped && regexp.MustCompile(`^release_[0-9a-f]{32}$`).MatchString(id)
	}
	for _, d := range extra.PreservedDestinations {
		scoped = scoped && d.ID != extra.Destination.ID && d.Path != extra.Destination.Path && d.Path != extra.HoldingPath && deliverySafePath(d.Path) && filepath.Dir(d.Path) == state
	}
	h.Check("unknown_plan_scope", scoped)

	health := h.Start()
	h.Stop(false)
	gates := Map(receipt, "gates")
	h.Record["gate_probe_health"] = health
	h.Check("broker_health_matches_receipt_gates", health["stage0_passed"] == gates["stage0_passed"] && health["customer_operation_enabled"] == (Bool(gates, "stage0_passed") && Bool(gates, "stage3_completed")))
	h.Check("stage0_accepted_isolated_build", Bool(gates, "stage0_passed") && gates["stage3_completed"] == false && Bool(health, "stage0_passed") && Bool(health, "release_enabled") && health["customer_operation_enabled"] == false)

	runtime, err := hostvm.New(plan.Scan.Workspace)
	Must(err)
	h.StopTimeout = releaseBoundaryStopTimeout
	pid := 0
	staging := filepath.Join(extra.Destination.Path, ".filegate-staging")
	defer func() {
		if failure := recover(); failure != nil {
			h.Record["failure_state"] = releaseBoundaryFailureState(h, plan, runtime.State, pid)
			func() {
				defer func() { _ = recover() }()
				h.Record["failure_files"] = Object{"holding": releaseReplayDirectory(h, "holding", extra.HoldingPath), "staging": releaseReplayDirectory(h, "staging", staging)}
			}()
			panic(failure)
		}
	}()
	h.Check("shared_runtime_slot_initially_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["data_identity"] = deliveryPrivate(h, "dedicated_state", plan.DataDirectory)
	deliveryPrivate(h, "dedicated_input_root", plan.InputRoot)
	h.Data, h.InputDirectory = plan.DataDirectory, plan.InputRoot
	h.Socket = filepath.Join(h.Data, "filegate.sock")
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
	for _, path := range []string{extra.Destination.Path, extra.HoldingPath} {
		if !Exists(path) {
			Must(os.Mkdir(path, 0700))
		}
		h.Check("empty_private_directory_"+filepath.Base(path), len(releaseBoundaryEntries(path)) == 0)
		deliveryPrivate(h, "private_directory_"+filepath.Base(path), path)
	}
	preservedSet := releasePrepublishExtra{PreviousJobs: extra.PreviousJobs, PreservedReleases: extra.PreservedReleases, PreservedDestinations: extra.PreservedDestinations}
	preserved := releasePrepublishPreserved(h, preservedSet)
	h.Record["preserved_before"] = preserved

	serve := []string{"--vm-runner", plan.Scan.Runner.Path, "--vm-workspace", plan.Scan.Workspace, "--vm-proof", plan.Scan.Proof.Path, "--update-library-sha256", plan.LibrarySHA256, "--release-destination", extra.Destination.ID + "=" + extra.Destination.Path}
	for _, d := range extra.PreservedDestinations {
		serve = append(serve, "--release-destination", d.ID+"="+d.Path)
	}
	marker := filepath.Join(h.Out, "stop-marker.json")
	Must(os.Setenv(releasePrepublishMarker, marker))
	health = h.Start(serve...)
	Must(os.Unsetenv(releasePrepublishMarker))
	pid = h.Process.Process.Pid
	h.Check("unknown_broker_gate_open", Bool(health, "stage0_passed") && Bool(health, "release_enabled") && health["customer_operation_enabled"] == false)
	status, job := h.Request("GET", "/v1/jobs/"+extra.JobID, nil, nil, nil)
	h.Record["job_before"] = job
	versions := Map(job, "scan_details", "versions")
	h.Check("existing_genuine_PASS_still_eligible", status == 200 && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "PASS" && Bool(job, "release", "eligible") && Bool(job, "coverage", "required_checks_complete") && Str(job, "coverage", "av_result") == "clean" && Str(job, "attempt_id") == extra.AttemptID && Str(job, "input_receipt", "sha256") == plan.Input.SHA256 && Int(job, "input_receipt", "byte_size") == plan.Input.ByteSize && Str(versions, "host_sha256") == plan.Broker.SHA256 && Str(versions, "definition_update_id") == extra.DefinitionUpdateID && Int(versions, "definition_generation") == extra.DefinitionGeneration)
	openReleases := "SELECT count(*) FROM releases WHERE state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED')"
	openBefore := releaseBoundaryCount(h, openReleases)

	// Scenario 1: the reviewed hook stops only this broker after the synchronized INTENT, before the rename.
	h.Record["publication_attempted"] = true
	requested := Execute(h.Root, []string{h.Binary, "--data-dir", h.Data, "release", extra.JobID, "--destination", extra.Destination.ID, "--idempotency-key", extra.ReleaseKey}, nil, 10*time.Second)
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
	final := filepath.Join(extra.Destination.Path, output)
	temp := filepath.Join(staging, tempName)
	held := filepath.Join(extra.HoldingPath, tempName)
	records := QueryObjects(h, "SELECT data FROM releases WHERE id=?", release)
	h.Check("stop_release_ready_unknown", len(records) == 1 && Str(records[0], "receipt", "state") == "READY" && Str(records[0], "receipt", "publication_status") == "UNKNOWN" && Get(records[0], "receipt", "publication_confirmed") == false && Int(records[0], "generation") == 1 && Str(records[0], "temp_name") == tempName)
	stopped := releaseBoundaryLedger(h, release)
	h.Record["ledger_at_stop"] = stopped
	attempts := List(stopped, "attempts")
	tempIdentity := releaseUnknownIdentity(h, "temp_identity_at_stop", temp)
	recordedTemp := Map(records[0], "temp_identity")
	h.Check("stop_single_intent_no_final_real_temp", len(attempts) == 1 && Str(attempts[0], "state") == "INTENT" && !Exists(final) && Str(tempIdentity, "device") == Str(recordedTemp, "device") && Int(tempIdentity, "inode") == Int(recordedTemp, "inode") && Str(tempIdentity, "birth") == Str(recordedTemp, "birth") && Str(tempIdentity, "sha256") == plan.Input.SHA256 && Int(tempIdentity, "size") == plan.Input.ByteSize && Bool(tempIdentity, "regular") && Int(tempIdentity, "nlink") == 1 && Int(tempIdentity, "uid") == int64(os.Geteuid()) && Int(tempIdentity, "mode")&0077 == 0)
	h.Check("stop_resources_held", Int(stopped, "release_pins") == 1 && Int(stopped, "release_reservations") == 1 && Int(stopped, "open_releases") == openBefore+1 && releaseBoundaryCount(h, "SELECT count(*) FROM release_authorizations WHERE release_id=?", release) == 1)

	// Scenario 2: with the broker stopped, move only this temp, exclusively, to the private holding directory.
	h.Check("holding_target_absent", !Exists(held) && len(releaseBoundaryEntries(extra.HoldingPath)) == 0)
	Must(releaseUnknownMove(staging, tempName, extra.HoldingPath, tempName))
	h.Record["temp_in_holding"] = true
	heldIdentity := releaseUnknownIdentity(h, "held_identity_after_move", held)
	h.Check("temp_moved_with_same_identity_and_content", !Exists(temp) && Equal(heldIdentity, tempIdentity))

	// Scenario 3: a same-boot restart cannot prove publication or no publication; nothing is published or settled.
	h.Record["restart_mode"] = "same verification overlay binary with the stop marker variable unset"
	h.Start(serve...)
	status, unknown := h.Request("GET", "/v1/releases/"+release, nil, nil, nil)
	unknownLedger := releaseBoundaryLedger(h, release)
	unknownRows := deliveryRowSnapshot(h)
	WriteJSON(filepath.Join(h.Out, "unknown-state.json"), Object{"http_status": status, "receipt": unknown, "ledger": unknownLedger, "release_rows": QueryObjects(h, "SELECT data FROM releases WHERE id=?", release), "rows": unknownRows})
	attempts = List(unknownLedger, "attempts")
	h.Check("restart_recovery_required_publication_unknown", status == 200 && Str(unknown, "release_id") == release && Str(unknown, "state") == "RECOVERY_REQUIRED" && Contains(unknown["reason_codes"], "PUBLICATION_UNKNOWN") && Str(unknown, "publication_status") == "UNKNOWN" && Get(unknown, "success") == false && Get(unknown, "resources_finalized") == false)
	h.Check("unknown_intent_unresolved_resources_held", len(attempts) == 1 && Str(attempts[0], "state") == "INTENT" && releaseBoundaryCount(h, "SELECT count(*) FROM release_authorizations WHERE release_id=?", release) == 1 && Int(unknownLedger, "release_pins") == 1 && Int(unknownLedger, "release_reservations") == 1 && Int(unknownLedger, "open_releases") == openBefore+1)
	h.Check("unknown_no_final_no_temp_holding_unchanged", !Exists(final) && !Exists(temp) && Equal(releaseUnknownIdentity(h, "held_identity_at_unknown", held), tempIdentity) && Equal(releaseBoundaryEntries(extra.Destination.Path), []string{".filegate-staging"}))
	settle(h, &releaseUnknownRun{extra: extra, serve: serve, release: release, final: final, temp: temp, held: held, staging: staging, tempName: tempName, tempIdentity: tempIdentity, unknownRows: unknownRows, openBefore: openBefore})
	h.Check("previous_jobs_releases_and_destinations_unchanged", Equal(releasePrepublishPreserved(h, preservedSet), preserved))
	h.Stop(false)
	h.Check("shared_runtime_slot_finally_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["release_id"] = release
}

// releaseUnknownResendAndAbort resends the same key in the unknown state, then restores the temp and aborts.
func releaseUnknownResendAndAbort(h *Harness, u *releaseUnknownRun) {
	extra, serve, release, final, temp, held, staging, tempName, tempIdentity, openBefore := u.extra, u.serve, u.release, u.final, u.temp, u.held, u.staging, u.tempName, u.tempIdentity, u.openBefore
	status, resent := h.Request("POST", "/v1/jobs/"+extra.JobID+"/release", Object{"destination_id": extra.Destination.ID}, map[string]string{"Idempotency-Key": extra.ReleaseKey}, nil)
	resentReceipt := resent
	if ErrorCode(resent) != "" {
		resentReceipt = Map(resent, "error", "receipt")
	}
	resendRows := deliveryRowSnapshot(h)
	WriteJSON(filepath.Join(h.Out, "unknown-resend.json"), Object{"http_status": status, "response": resent, "ledger": releaseBoundaryLedger(h, release), "release_rows": QueryObjects(h, "SELECT data FROM releases WHERE id=?", release), "rows": resendRows})
	h.Check("resend_keeps_recovery_required", Str(resentReceipt, "release_id") == release && Str(resentReceipt, "state") == "RECOVERY_REQUIRED" && Str(resentReceipt, "publication_status") == "UNKNOWN" && Get(resentReceipt, "success") == false && Get(resentReceipt, "resources_finalized") == false)
	h.Check("resend_changes_no_rows_or_files", Equal(resendRows, u.unknownRows) && !Exists(final) && !Exists(temp) && Equal(releaseUnknownIdentity(h, "held_identity_after_resend", held), tempIdentity) && Equal(releaseBoundaryEntries(extra.Destination.Path), []string{".filegate-staging"}) && len(releaseBoundaryEntries(staging)) == 0)
	h.Stop(false)

	// Cleanup (recorded apart from the unknown-state result): restore the same temp and let the broker settle it.
	cleanup := Object{}
	h.Record["cleanup"] = cleanup
	h.Check("cleanup_restore_target_absent", !Exists(temp) && Equal(releaseUnknownIdentity(h, "held_identity_before_restore", held), tempIdentity))
	Must(releaseUnknownMove(extra.HoldingPath, tempName, staging, tempName))
	h.Record["temp_in_holding"] = false
	restored := releaseUnknownIdentity(h, "temp_identity_after_restore", temp)
	h.Check("cleanup_temp_restored_same_identity", Equal(restored, tempIdentity) && !Exists(held) && len(releaseBoundaryEntries(extra.HoldingPath)) == 0)
	h.Start(serve...)
	status, proven := h.Request("GET", "/v1/releases/"+release, nil, nil, nil)
	cleanup["after_restore_restart"] = proven
	provenLedger := releaseBoundaryLedger(h, release)
	attempts := List(provenLedger, "attempts")
	h.Check("cleanup_restart_proves_no_publication", status == 200 && Str(proven, "state") == "REVALIDATION_REQUIRED" && Str(proven, "publication_status") == "NOT_PUBLISHED" && len(attempts) == 1 && Str(attempts[0], "state") == "NO_PUBLICATION_PROVEN" && Str(attempts[0], "evidence") == "same_boot_unchanged_unconsumed_exclusive_temp" && Int(provenLedger, "release_pins") == 1 && Int(provenLedger, "release_reservations") == 1 && Equal(releaseUnknownIdentity(h, "temp_identity_before_abort", temp), tempIdentity) && !Exists(final))
	status, aborted := h.Request("POST", "/v1/releases/"+release+"/abort", nil, nil, nil)
	cleanup["abort"] = Object{"status": status, "response": aborted}
	abortLedger := releaseBoundaryLedger(h, release)
	cleanup["ledger_after_abort"] = abortLedger
	attempts = List(abortLedger, "attempts")
	h.Check("cleanup_abort_settles_once", status == 200 && Str(aborted, "state") == "ABORTED" && Str(aborted, "abort_outcome") == "ABORTED" && Bool(aborted, "resources_finalized") && Get(aborted, "success") == false && len(attempts) == 1 && Str(attempts[0], "state") == "NO_PUBLICATION_PROVEN" && releaseBoundaryCount(h, "SELECT count(*) FROM release_authorizations WHERE release_id=?", release) == 1 && Int(abortLedger, "release_pins") == 0 && Int(abortLedger, "release_reservations") == 0 && Int(abortLedger, "open_releases") == openBefore)
	h.Check("cleanup_temp_removed_final_never_created", !Exists(temp) && !Exists(final) && Equal(releaseBoundaryEntries(extra.Destination.Path), []string{".filegate-staging"}) && len(releaseBoundaryEntries(staging)) == 0 && len(releaseBoundaryEntries(extra.HoldingPath)) == 0)
}
