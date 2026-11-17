package verification

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"filegate.local/filegate/internal/hostvm"
	updatecontrol "filegate.local/filegate/internal/update"
	"golang.org/x/sys/unix"
)

// release-boundary stops a separately built verification broker after the exclusive rename succeeded and before any
// success record, then resends the same key; it refuses before intake or publication unless stage 0 is accepted.
func init() { Register("release-boundary", runReleaseBoundary) }

const releaseBoundaryStop = "published_rename_before_record"
const releaseBoundaryMarker = "FILEGATE_RELEASE_BOUNDARY_MARKER"

// Broker Close waits up to 10 s for a release, 40 s for a scan and 40 s for an update in sequence; 10 s is margin.
const releaseBoundaryStopTimeout = 100 * time.Second

// releaseStopSpec names one reviewed stop point: its plan kind, marker variable and the overlay file holding the hook.
type releaseStopSpec struct{ PlanKind, StopPoint, Marker, HookFile string }

var releaseBoundarySpec = releaseStopSpec{"filegate-release-boundary-plan", releaseBoundaryStop, releaseBoundaryMarker, "internal/broker/release_boundary_stop.go"}

type releaseBoundaryPlan struct {
	Schema        int         `json:"schema"`
	Kind          string      `json:"kind"`
	StopPoint     string      `json:"stop_point"`
	DataDirectory string      `json:"data_directory"`
	InputRoot     string      `json:"input_root"`
	Broker        deliveryRef `json:"broker"`
	BuildReceipt  deliveryRef `json:"build_receipt"`
	Scan          struct {
		Runner    deliveryRef `json:"runner"`
		Workspace string      `json:"workspace"`
		Receipt   deliveryRef `json:"receipt"`
		Proof     deliveryRef `json:"proof"`
	} `json:"scan"`
	Registration              deliveryRef `json:"registration"`
	LibrarySHA256             string      `json:"library_sha256"`
	ExpectedSourceDifferences []string    `json:"expected_source_differences"`
	Input                     struct {
		Path           string `json:"path"`
		SHA256         string `json:"sha256"`
		ByteSize       int64  `json:"byte_size"`
		ExpectedType   string `json:"expected_type"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"input"`
	Destination struct {
		ID   string `json:"destination_id"`
		Path string `json:"path"`
	} `json:"destination"`
	ReleaseKey string `json:"release_key"`
}

func releaseBoundaryFormal(h *Harness, path string) bool {
	home, err := os.UserHomeDir()
	Must(err)
	base := filepath.Join(home, "Library", "Application Support", "FileGate")
	for _, protected := range []string{filepath.Join(base, "fg-final"), filepath.Join(base, "application"), filepath.Join(base, "Outbox"), filepath.Join(home, "Downloads"), h.Root} {
		if path == protected || strings.HasPrefix(path, protected+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func releaseBoundaryIdentity(path string) Object {
	var info unix.Stat_t
	Must(unix.Lstat(path, &info))
	return Object{"device": uint64(info.Dev), "inode": info.Ino, "mode": uint32(info.Mode), "size": info.Size}
}

func releaseBoundaryEntries(path string) []string {
	entries, err := os.ReadDir(path)
	Must(err)
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func releaseBoundaryCount(h *Harness, query string, args ...any) int64 {
	rows := h.Query(query, args...)
	if len(rows) != 1 || len(rows[0]) != 1 {
		panic(Failure{"RELEASE_BOUNDARY_COUNT_INVALID"})
	}
	return Int(Object{"n": rows[0][0]}, "n")
}

func releaseBoundaryLedger(h *Harness, release string) Object {
	return Object{
		"release_pins":         releaseBoundaryCount(h, "SELECT count(*) FROM resource_pins WHERE owner_id=?", release),
		"release_reservations": releaseBoundaryCount(h, "SELECT count(*) FROM release_reservations WHERE release_id=?", release),
		"open_releases":        releaseBoundaryCount(h, "SELECT count(*) FROM releases WHERE state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED')"),
		"attempts":             QueryObjects(h, "SELECT data FROM release_publication_attempts WHERE release_id=? ORDER BY sequence", release),
	}
}

func releaseBoundaryPlanChecks(h *Harness) (releaseBoundaryPlan, Object) {
	return releaseStopPlanChecks(h, releaseBoundarySpec)
}

// releaseStopPlanChecks binds the reviewed plan, the overlay build and the scan runtime before any service starts.
func releaseStopPlanChecks(h *Harness, spec releaseStopSpec) (releaseBoundaryPlan, Object) {
	h.Check("reviewed_plan_and_external_broker_required", h.BinaryProof != "" && h.Binary != "")
	body := deliveryRead(h.BinaryProof, 65536)
	var plan releaseBoundaryPlan
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	Must(decoder.Decode(&plan))
	if decoder.Decode(new(any)) != io.EOF {
		panic(Failure{"RELEASE_BOUNDARY_PLAN_TRAILING_DATA"})
	}
	h.Record["plan_sha256"] = Digest(body)
	paths := []string{plan.DataDirectory, plan.InputRoot, plan.Broker.Path, plan.BuildReceipt.Path, plan.Scan.Runner.Path, plan.Scan.Workspace, plan.Scan.Receipt.Path, plan.Scan.Proof.Path, plan.Registration.Path, plan.Input.Path, plan.Destination.Path}
	safe := true
	for _, path := range paths {
		safe = safe && deliverySafePath(path)
	}
	digests := true
	for _, value := range []string{plan.Broker.SHA256, plan.BuildReceipt.SHA256, plan.Scan.Runner.SHA256, plan.Scan.Receipt.SHA256, plan.Scan.Proof.SHA256, plan.Registration.SHA256, plan.LibrarySHA256, plan.Input.SHA256} {
		digests = digests && deliveryDigest.MatchString(value)
	}
	identifier := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	h.Check("plan_scope", plan.Schema == 1 && plan.Kind == spec.PlanKind && plan.StopPoint == spec.StopPoint && safe && digests && identifier.MatchString(plan.Destination.ID) && plan.ReleaseKey != "" && plan.Input.IdempotencyKey != "" && plan.Input.ByteSize > 0 && (plan.Input.ExpectedType == "zip" || plan.Input.ExpectedType == "txt"))
	h.Check("plan_state_input_and_destination_outside_formal_and_repository", !releaseBoundaryFormal(h, plan.DataDirectory) && !releaseBoundaryFormal(h, plan.InputRoot) && !releaseBoundaryFormal(h, plan.Destination.Path) && strings.HasPrefix(plan.Input.Path, plan.InputRoot+string(os.PathSeparator)))
	h.Check("broker_matches_plan", h.Binary == plan.Broker.Path && FileDigest(h.Binary) == plan.Broker.SHA256)

	receiptBody := deliveryRead(plan.BuildReceipt.Path, 4<<20)
	h.Check("build_receipt_matches_plan", Digest(receiptBody) == plan.BuildReceipt.SHA256)
	receipt := Decode(receiptBody)
	targets := []string{}
	overlayFixed := true
	for _, entry := range List(receipt, "overlay") {
		targets = append(targets, Str(entry, "target"))
		replacement := Str(entry, "replacement", "path")
		overlayFixed = overlayFixed && deliverySafePath(replacement) && FileDigest(replacement) == Str(entry, "replacement", "sha256")
	}
	sort.Strings(targets)
	deps := Map(receipt, "dependency_sources_sha256")
	var publishBase string
	for _, entry := range List(receipt, "overlay") {
		if Str(entry, "target") == "internal/broker/release_publish.go" {
			publishBase = Str(entry, "base_sha256")
		}
	}
	diff := Str(receipt, "overlay_diff", "path")
	overlay := []string{spec.HookFile, "internal/broker/release_publish.go"}
	sort.Strings(overlay)
	h.Check("overlay_recorded_and_unchanged", Equal(targets, overlay) && overlayFixed && deliverySafePath(diff) && FileDigest(diff) == Str(receipt, "overlay_diff", "sha256"))
	h.Check("build_receipt_binds_broker_and_overlay_base", Str(receipt, "kind") == "filegate-release-boundary-broker-build" && Str(receipt, "stop_point") == spec.StopPoint && Str(receipt, "binary", "sha256") == plan.Broker.SHA256 && publishBase != "" && Str(deps, "internal/broker/release_publish.go") == publishBase && deps[spec.HookFile] == nil)
	gates := Map(receipt, "gates")
	h.Record["build_receipt"] = Object{"sha256": plan.BuildReceipt.SHA256, "gates": gates, "overlay_targets": targets, "overlay_diff_sha256": Str(receipt, "overlay_diff", "sha256"), "dependency_files": len(deps)}

	h.Check("scan_runner_fixed_workspace_path", plan.Scan.Runner.Path == filepath.Join(plan.Scan.Workspace, ".build/filegate-vm") && plan.Scan.Receipt.Path == filepath.Join(plan.Scan.Workspace, "experiments/vm/evidence/build.json"))
	h.Check("scan_runtime_matches_plan", FileDigest(plan.Scan.Runner.Path) == plan.Scan.Runner.SHA256 && FileDigest(plan.Scan.Receipt.Path) == plan.Scan.Receipt.SHA256 && FileDigest(plan.Scan.Proof.Path) == plan.Scan.Proof.SHA256)
	registration := Decode(deliveryRead(plan.Registration.Path, 1<<20))
	h.Check("registration_matches_plan", FileDigest(plan.Registration.Path) == plan.Registration.SHA256 && Str(registration, "library_sha256") == plan.LibrarySHA256)
	scanReceipt := ReadJSON(plan.Scan.Receipt.Path)
	scanPins := Map(scanReceipt, "product_sources_sha256")
	h.Check("broker_go_toolchain_and_modules_match_scan_receipt", Str(receipt, "go") != "" && Str(receipt, "go") == Str(scanReceipt, "go") && Str(receipt, "go_mod_sha256") == Str(scanPins, "go.mod") && Str(receipt, "go_sum_sha256") == Str(scanPins, "go.sum"))
	differences := []string{}
	for name, digest := range deps {
		if pinned, ok := scanPins[name]; !ok {
			differences = append(differences, "unpinned:"+name)
		} else if pinned != digest {
			differences = append(differences, name)
		}
	}
	sort.Strings(differences)
	expected := append([]string{}, plan.ExpectedSourceDifferences...)
	sort.Strings(expected)
	h.Record["source_differences_from_scan_receipt"] = differences
	h.Check("broker_sources_match_scan_receipt_except_reviewed_differences", Equal(differences, expected))
	info, err := os.Lstat(plan.Input.Path)
	Must(err)
	h.Check("synthetic_input_matches_plan", info.Mode().IsRegular() && info.Size() == plan.Input.ByteSize && FileDigest(plan.Input.Path) == plan.Input.SHA256)
	return plan, receipt
}

// releaseBoundaryFailureState stops only this suite's broker within the broker's own budget and records what is still held.
func releaseBoundaryFailureState(h *Harness, plan releaseBoundaryPlan, slotState string, pid int) Object {
	state := Object{"broker_pid": pid, "stop_timeout_seconds": int64(h.StopTimeout / time.Second), "slot_and_ownership_files_left_untouched": true}
	step := func(name string, run func()) {
		defer func() {
			if failure := recover(); failure != nil {
				state[name+"_failure"] = failureRecord(failure)
			}
		}()
		run()
	}
	step("stop", func() {
		state["broker_running_before_stop"] = h.ServiceAlive()
		h.Stop(false)
	})
	state["broker_stopped"] = h.Process == nil
	step("slot", func() {
		path := filepath.Join(slotState, "active-vm.json")
		slot := Object{"present": Exists(path)}
		if Exists(path) {
			body := Read(path)
			output := Str(Decode(body), "output_directory")
			slot["sha256"], slot["output_directory"] = Digest(body), output
			slot["owned_by_dedicated_state"] = strings.HasPrefix(output, plan.DataDirectory+string(os.PathSeparator))
		}
		state["shared_vm_slot"] = slot
	})
	step("database", func() {
		if h.Data != plan.DataDirectory || !Exists(filepath.Join(h.Data, "state.sqlite")) {
			return
		}
		held := Object{}
		for name, query := range map[string]string{"reservations": "SELECT count(*) FROM reservations", "scan_queue": "SELECT count(*) FROM scan_queue", "resource_pins": "SELECT count(*) FROM resource_pins", "release_reservations": "SELECT count(*) FROM release_reservations", "open_runtime_runs": "SELECT count(*) FROM runtime_runs WHERE state NOT IN ('FINISHED','PRUNING','REPORT_PRUNING')", "open_releases": "SELECT count(*) FROM releases WHERE state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED')"} {
			held[name] = releaseBoundaryCount(h, query)
		}
		state["held"] = held
	})
	state["state_retained"] = plan.DataDirectory
	return state
}

func runReleaseBoundary(h *Harness) {
	Must(os.Unsetenv(releaseBoundaryMarker))
	h.Record["kind"] = "filegate-release-boundary"
	h.Record["scope"] = "one Chapter 13 stop point: verification-overlay broker killed after exclusive rename success and before the PUBLISHED record, then same-key resend; dedicated state, synthetic input, real VM/ClamAV PASS only on a stage-0-accepted build"
	h.Record["stop_point"] = releaseBoundaryStop
	h.Record["intake_attempted"] = false
	h.Record["publication_attempted"] = false
	h.Record["formal_state_used"] = false
	plan, receipt := releaseBoundaryPlanChecks(h)

	// Gate probe: a throwaway state under the harness temporary directory, no VM, no intake.
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
	// A failure after this point keeps its own record; the stop and holdings are recorded beside it, never instead of it.
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
	openBefore := releaseBoundaryCount(h, "SELECT count(*) FROM releases WHERE state NOT IN ('COMMITTED','ABORTED','PUBLISHED_UNVERIFIED')")
	before := deliveryRowSnapshot(h)
	h.Check("dedicated_state_has_no_inflight_work", Int(before, "reservations", "count") == 0 && Int(before, "scan_queue", "count") == 0 && Int(before, "resource_pins", "count") == 0 && Int(before, "release_reservations", "count") == 0)
	control := Map(SnapshotUpdate(filepath.Join(h.Data, "state.sqlite"), true, false), "control")
	h.Check("no_active_update", Str(control, "active_update_id") == "")
	definition := deliveryAdoption(h, control, Decode(deliveryRead(plan.Registration.Path, 1<<20)))
	now, err := updatecontrol.ReadClock()
	Must(err)
	confirmed := Map(definition, "confirmed")
	h.Check("fresh_existing_definition_no_update", now.Boot == Str(confirmed, "boot") && now.UTC >= Int(confirmed, "utc") && now.UTC-Int(confirmed, "utc") <= 85800 && now.ContinuousNS >= uint64(Int(confirmed, "continuous_ns")) && now.ContinuousNS-uint64(Int(confirmed, "continuous_ns")) <= 85800000000000)
	if !Exists(plan.Destination.Path) {
		Must(os.Mkdir(plan.Destination.Path, 0700))
	}
	h.Check("empty_dedicated_destination", len(releaseBoundaryEntries(plan.Destination.Path)) == 0)
	deliveryPrivate(h, "dedicated_destination", plan.Destination.Path)

	serve := []string{"--vm-runner", plan.Scan.Runner.Path, "--vm-workspace", plan.Scan.Workspace, "--vm-proof", plan.Scan.Proof.Path, "--update-library-sha256", plan.LibrarySHA256, "--release-destination", plan.Destination.ID + "=" + plan.Destination.Path}
	marker := filepath.Join(h.Out, "stop-marker.json")
	Must(os.Setenv(releaseBoundaryMarker, marker))
	health = h.Start(serve...)
	Must(os.Unsetenv(releaseBoundaryMarker))
	pid = h.Process.Process.Pid
	h.Check("boundary_broker_gate_open", Bool(health, "stage0_passed") && Bool(health, "release_enabled") && health["customer_operation_enabled"] == false)

	h.Record["intake_attempted"] = true
	code, submitted := h.Submit("file", plan.Input.Path, Object{"idempotency_key": plan.Input.IdempotencyKey, "expected_type": plan.Input.ExpectedType, "expected_sha256": plan.Input.SHA256}, nil)
	jobID := Str(submitted, "job_id")
	h.Check("synthetic_input_committed", code == 0 && deliveryJobID.MatchString(jobID) && Str(submitted, "input_receipt", "sha256") == plan.Input.SHA256 && Int(submitted, "input_receipt", "byte_size") == plan.Input.ByteSize)
	code, job := vmWaitCLI(h, jobID)
	h.Record["job_before_release"] = job
	h.Check("genuine_PASS_before_release", code == 0 && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "PASS" && Bool(job, "coverage", "required_checks_complete") && Bool(job, "runtime_cleanup_complete") && Bool(job, "release", "eligible"))

	h.Record["publication_attempted"] = true
	requested := Execute(h.Root, []string{h.Binary, "--data-dir", h.Data, "release", jobID, "--destination", plan.Destination.ID, "--idempotency-key", plan.ReleaseKey}, nil, 10*time.Second)
	h.Commands = append(h.Commands, Object{"operation": "release", "exit_code": requested.ExitCode})
	h.Responses = append(h.Responses, requested.Stdout, requested.Stderr)
	deadline := time.Now().Add(120 * time.Second)
	for h.ServiceAlive() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	h.Check("broker_stopped_at_boundary", !h.ServiceAlive())
	h.Stop(true)
	stop := Decode(deliveryRead(marker, 4096))
	release, output := Str(stop, "release_id"), Str(stop, "output_name")
	h.Record["stop_marker"] = stop
	h.Check("stop_marker_from_same_broker", Str(stop, "stop_point") == releaseBoundaryStop && Int(stop, "pid") == int64(pid) && release != "" && output != "" && !strings.Contains(output, "/"))
	if requested.ExitCode == 0 {
		first := Decode(requested.Stdout)
		h.Check("first_request_same_release", Str(first, "release_id") == release && Get(first, "replayed") == false)
	}

	// At the boundary the file is published but only INTENT is durable: recovery must prove publication itself.
	records := QueryObjects(h, "SELECT data FROM releases WHERE id=?", release)
	h.Check("boundary_release_not_committed", len(records) == 1 && Str(records[0], "receipt", "state") == "READY" && Str(records[0], "receipt", "publication_status") == "UNKNOWN" && Get(records[0], "receipt", "publication_confirmed") == false && Str(records[0], "receipt", "output_name") == output)
	boundary := releaseBoundaryLedger(h, release)
	h.Record["ledger_at_boundary"] = boundary
	attempts := List(boundary, "attempts")
	h.Check("boundary_single_intent_attempt", len(attempts) == 1 && Str(attempts[0], "state") == "INTENT")
	final := filepath.Join(plan.Destination.Path, output)
	temp := filepath.Join(plan.Destination.Path, ".filegate-staging", Str(stop, "temp_name"))
	h.Check("boundary_final_present_temp_consumed", Exists(final) && !Exists(temp) && FileDigest(final) == plan.Input.SHA256 && Int(releaseBoundaryIdentity(final), "size") == plan.Input.ByteSize)
	identity := releaseBoundaryIdentity(final)
	h.Check("boundary_resources_still_held", Int(boundary, "release_pins") >= 1 && Int(boundary, "release_reservations") == 1 && Int(boundary, "open_releases") == openBefore+1)

	// The same verification binary runs normally: the marker variable is unset, so the hook returns.
	h.Record["restart_mode"] = "same verification overlay binary with the stop marker variable unset"
	h.Start(serve...)
	code, status := h.CLI("release-status", release)
	h.Record["release_after_recovery"] = status
	h.Check("recovery_converges_committed", code == 0 && Str(status, "release_id") == release && Str(status, "state") == "COMMITTED" && Str(status, "output_name") == output && Str(status, "publication_status") == "PUBLISHED" && Bool(status, "success") && Str(status, "final_validation") == "verified" && Str(status, "output_state") == "MATCH" && Bool(status, "resources_finalized"))
	recovered := releaseBoundaryLedger(h, release)
	attempts = List(recovered, "attempts")
	h.Check("publication_proven_by_recovery_not_by_success_record", len(attempts) == 1 && Str(attempts[0], "state") == "PUBLISHED" && Str(attempts[0], "evidence") == "matching_final_original_temp_consumed")
	h.Check("recovery_settled_resources", Int(recovered, "release_pins") == 0 && Int(recovered, "release_reservations") == 0 && Int(recovered, "open_releases") == openBefore)
	beforeResend := deliveryRowSnapshot(h)
	code, replay := h.CLI("release", jobID, "--destination", plan.Destination.ID, "--idempotency-key", plan.ReleaseKey)
	h.Record["same_key_resend"] = replay
	h.Check("same_key_resend_same_release_and_name", code == 0 && Bool(replay, "replayed") && Str(replay, "release_id") == release && Str(replay, "output_name") == output && Str(replay, "state") == "COMMITTED")
	h.Check("no_recopy_or_duplicate_publication", Equal(releaseBoundaryEntries(plan.Destination.Path), []string{".filegate-staging", output}) && len(releaseBoundaryEntries(filepath.Join(plan.Destination.Path, ".filegate-staging"))) == 0 && Equal(releaseBoundaryIdentity(final), identity) && FileDigest(final) == plan.Input.SHA256)
	resent := releaseBoundaryLedger(h, release)
	h.Record["ledger_after_first_resend"] = resent
	h.Check("resources_settled_once", Int(resent, "release_pins") == 0 && Int(resent, "release_reservations") == 0 && Int(resent, "open_releases") == openBefore && Equal(resent["attempts"], recovered["attempts"]))
	h.Check("first_resend_changes_no_rows", Equal(deliveryRowSnapshot(h), beforeResend))
	h.Stop(false)

	h.Start(serve...)
	code, again := h.CLI("release", jobID, "--destination", plan.Destination.ID, "--idempotency-key", plan.ReleaseKey)
	h.Check("second_restart_no_second_settlement", code == 0 && Str(again, "release_id") == release && Str(again, "state") == "COMMITTED" && Equal(deliveryRowSnapshot(h), beforeResend) && Equal(releaseBoundaryIdentity(final), identity))
	h.Stop(false)
	h.Check("shared_runtime_slot_finally_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["release_id"] = release
	h.Record["job_id"] = jobID
}
