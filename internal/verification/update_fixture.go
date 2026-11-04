package verification

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func init() { Register("update-fixture", runUpdateFixture) }
func selectedCase(h *Harness, fallback string) string {
	if len(h.Cases) == 0 {
		return fallback
	}
	h.Check("single_selected_case", len(h.Cases) == 1)
	return h.Cases[0]
}
func SnapshotUpdate(path string, normal, stopped bool) Object {
	immutable := stopped && !Exists(path+"-wal") && !Exists(path+"-shm")
	before := ""
	dsn := "file:" + path + "?mode=ro"
	if immutable {
		before = FileDigest(path)
		dsn += "&immutable=1"
	}
	db, err := sql.Open("sqlite3", dsn)
	Must(err)
	defer db.Close()
	result := Object{}
	var body []byte
	Must(db.QueryRow("SELECT data FROM update_control").Scan(&body))
	result["control"] = Decode(body)
	jsonRows := func(query string) []any {
		rows, err := db.Query(query)
		Must(err)
		defer rows.Close()
		values := []any{}
		for rows.Next() {
			var body []byte
			Must(rows.Scan(&body))
			values = append(values, Decode(body))
		}
		Must(rows.Err())
		return values
	}
	result["attempts"] = jsonRows("SELECT data FROM update_attempts ORDER BY rowid")
	var reserved int64
	var integrity string
	Must(db.QueryRow("SELECT coalesce(sum(reserved_bytes),0) FROM update_attempts").Scan(&reserved))
	Must(db.QueryRow("PRAGMA integrity_check").Scan(&integrity))
	result["reserved_bytes"] = reserved
	result["integrity"] = integrity
	if normal {
		rows, err := db.Query("SELECT update_id,directory,manifest_sha256,state FROM update_runtime ORDER BY rowid")
		Must(err)
		runtime := []any{}
		for rows.Next() {
			var id, directory, manifest, state string
			Must(rows.Scan(&id, &directory, &manifest, &state))
			runtime = append(runtime, Object{"update_id": id, "directory": directory, "manifest_sha256": manifest, "state": state})
		}
		Must(rows.Err())
		Must(rows.Close())
		result["runtime"] = runtime
		rows, err = db.Query("SELECT job_id,attempt_id,update_id FROM update_waiters ORDER BY rowid")
		Must(err)
		waiters := []any{}
		for rows.Next() {
			var job, attempt, id string
			Must(rows.Scan(&job, &attempt, &id))
			waiters = append(waiters, []string{job, attempt, id})
		}
		Must(rows.Err())
		Must(rows.Close())
		result["waiters"] = waiters
		var pins int64
		Must(db.QueryRow("SELECT count(*) FROM resource_pins").Scan(&pins))
		result["pins"] = pins
	}
	Must(db.Close())
	if immutable && (FileDigest(path) != before || Exists(path+"-wal") || Exists(path+"-shm")) {
		panic(Failure{"UPDATE_DATABASE_CHANGED_AFTER_STOP"})
	}
	return result
}
func FixtureRegistration(h *Harness) Object {
	workspace := h.Paths["vm-workspace"]
	if workspace == "" {
		workspace = h.Workspace
	}
	h.Check("fixture_workspace_supplied", workspace != "")
	workspace, err := filepath.EvalSymlinks(workspace)
	Must(err)
	proof := h.Proof
	if proof == "" {
		proof = h.Paths["vm-proof"]
	}
	h.Check("fixture_proof_supplied", proof != "")
	proof, err = filepath.EvalSymlinks(proof)
	Must(err)
	library := h.Paths["library-sha256"]
	h.Check("fixture_library_digest", len(library) == 64 && strings.Trim(library, "0123456789abcdef") == "")
	vm := filepath.Join(workspace, "experiments/vm")
	receiptPath := filepath.Join(vm, "evidence/build.json")
	receipt := ReadJSON(receiptPath)
	pins := Object{receiptPath: FileDigest(receiptPath), proof: FileDigest(proof)}
	for _, group := range []struct{ name, base string }{{"artifacts", vm}, {"sources_sha256", vm}, {"external_sources_sha256", filepath.Join(workspace, "experiments")}, {"product_sources_sha256", workspace}} {
		for name, want := range Map(receipt, group.name) {
			path := filepath.Join(group.base, name)
			h.Check("fixture_source_"+name, FileDigest(path) == want)
			pins[path] = want
		}
	}
	runner, helper := filepath.Join(workspace, ".build/filegate-update"), filepath.Join(workspace, ".build/filegate-fixture-bridge")
	h.Check("fixture_runner_receipt", Str(receipt, "host_update_runner", "path") == runner && FileDigest(runner) == Str(receipt, "host_update_runner", "sha256"))
	h.Check("fixture_helper_receipt", FileDigest(helper) == Str(receipt, "artifacts", ".build/filegate-fixture-bridge"))
	pins[runner] = FileDigest(runner)
	pins[helper] = FileDigest(helper)
	h.Check("fixture_pin_bounds", len(pins) >= 12 && len(pins) <= 512)
	return Object{"schema": 2, "profile": "filegate-update-fixture-v1", "fixture_only": true, "library_sha256": library, "workspace": workspace, "runner": runner, "helper": helper, "proof": proof, "sha256": pins}
}
func fixtureHelperOverlay(h *Harness, manifest Object, mode string) {
	workspace := Str(manifest, "workspace")
	source := filepath.Join(workspace, "internal/fixturebridge/exchange.go")
	body := string(Read(source))
	marker := `if _, err = hostvm.WriteNew(filepath.Join(out, "final.json"), report); err != nil {`
	injection := ""
	if mode == "deadline" {
		injection = "for {\n" +
			"deadlineRecord, deadlineErr := receive()\n" +
			"if deadlineErr != nil { return deadlineErr }\n" +
			"deadlineWorkspace, deadlineErr := vmbridge.NormalizeWorkspace(deadlineRecord)\n" +
			"if deadlineErr != nil || deadlineWorkspace[\"reason\"] != nil || relay(deadlineWorkspace) != nil { return invalid }\n" +
			"}\n"
	} else {
		injection = `report["all_network_requests_finished"] = false` + "\n"
	}
	body = ReplaceOnce(body, marker, injection+marker)
	target := filepath.Join(h.Out, "fixture-exchange.go")
	Write(target, []byte(body))
	overlay := filepath.Join(h.Out, "fixture-overlay.json")
	WriteJSON(overlay, Object{"Replace": Object{source: target}})
	helper := filepath.Join(h.Out, "fixture-helper")
	result := Execute(workspace, []string{"go", "build", "-trimpath", "-buildvcs=false", "-overlay", overlay, "-o", helper, "./cmd/filegate-fixture-bridge"}, nil, 3*time.Minute)
	Write(filepath.Join(h.Out, "fixture-helper-build.log"), append(result.Stdout, result.Stderr...))
	h.Check("fixture_helper_overlay_build", result.ExitCode == 0)
	Must(os.Chmod(helper, 0500))
	pins := Map(manifest, "sha256")
	delete(pins, Str(manifest, "helper"))
	pins[helper] = FileDigest(helper)
	manifest["helper"] = helper
	h.Record["fixture_overlay"] = Object{"mode": mode, "source_sha256": FileDigest(source), "replacement_sha256": FileDigest(target), "helper_sha256": FileDigest(helper), "real_adapter_used": true, "deadline_shortened": false, "live_guest_workspace_relay_maintained": mode == "deadline", "synthetic_heartbeat_or_resources": false}
}
func runUpdateFixture(h *Harness) {
	name := selectedCase(h, "bridge")
	h.Check("fixture_case", name == "bridge" || name == "preparation-cancel" || name == "driver-death" || name == "deadline" || name == "invalid-final")
	h.Record["case"] = name
	h.Record["kind"] = "go-update-nic-free-fixed-bridge"
	h.Record["fixture_only"] = true
	h.Record["product_adoption_enabled"] = false
	h.Record["external_network_enabled"] = false
	h.Record["not_demonstrated"] = []string{"product broker waiting jobs", "official definition acquisition or adoption", "OS reboot or sleep", "customer material or PASS/release"}
	manifest := FixtureRegistration(h)
	if name == "deadline" || name == "invalid-final" {
		fixtureHelperOverlay(h, manifest, name)
	}
	path := filepath.Join(h.Out, "build/update-runtime.json")
	WriteJSON(path, manifest)
	h.Record["manifest_sha256"] = FileDigest(path)
	driver := h.Driver
	if driver == "" {
		driver = filepath.Join(h.Out, "update-driver")
		result := Execute(h.Root, []string{"go", "build", "-trimpath", "-buildvcs=false", "-o", driver, "./experiments/productupdate/driver"}, nil, 90*time.Second)
		Write(filepath.Join(h.Out, "build-driver.log"), append(result.Stdout, result.Stderr...))
		h.Check("driver_build", result.ExitCode == 0)
	}
	h.Record["driver_sha256"] = FileDigest(driver)
	if h.PrepareOnly {
		h.Record["scope"] = "Go fixture registration and helper build only; no runtime execution"
		h.Record["runtime_executed"] = false
		return
	}
	h.Record["runtime_executed"] = true
	var identity [16]byte
	_, err := rand.Read(identity[:])
	Must(err)
	id := fmt.Sprintf("update_%x", identity[:])
	state := filepath.Join(h.Out, "state")
	runtime := filepath.Join(state, "runtime-"+id)
	arguments := []string{driver, "--state", state, "--manifest", path, "--update-id", id}
	stdout, err := os.OpenFile(filepath.Join(h.Out, "driver.stdout"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	Must(err)
	defer stdout.Close()
	stderr, err := os.OpenFile(filepath.Join(h.Out, "driver.stderr"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	Must(err)
	defer stderr.Close()
	cmd := exec.Command(arguments[0], arguments[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	Must(cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := false
	observations := Object{"driver_pid": cmd.Process.Pid}
	defer func() {
		if !exited {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
				exited = true
			case <-time.After(45 * time.Second):
				observations["driver_still_active"] = true
			}
		}
		if exited && Exists(filepath.Join(state, "fixture.sqlite")) {
			recovery := Execute(h.Root, append(append([]string{}, arguments...), "--recover"), nil, 45*time.Second)
			observations["final_recovery_exit"] = recovery.ExitCode
			Write(filepath.Join(h.Out, "final-recovery.stdout"), recovery.Stdout)
			Write(filepath.Join(h.Out, "final-recovery.stderr"), recovery.Stderr)
		}
		WriteJSON(filepath.Join(h.Out, "observations.json"), observations)
	}()
	started := time.Now()
	signaled := false
	for !exited && time.Since(started) < 650*time.Second {
		select {
		case <-done:
			exited = true
		default:
		}
		if Exists(filepath.Join(runtime, "request.json")) && observations["pending"] == nil {
			observations["pending"] = SnapshotUpdate(filepath.Join(state, "fixture.sqlite"), false, false)
		}
		if !signaled {
			if name == "preparation-cancel" && Exists(filepath.Join(runtime, "output/preparation-owner.json")) {
				Must(cmd.Process.Signal(syscall.SIGTERM))
				observations["signal"] = "SIGTERM after durable preparation owner"
				signaled = true
			}
			if name == "driver-death" && Exists(filepath.Join(runtime, "output/vm-started.json")) {
				Must(cmd.Process.Kill())
				observations["signal"] = "SIGKILL after durable native MONITOR_READY identities"
				signaled = true
			}
		}
		if !exited {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !exited {
		Must(cmd.Process.Signal(syscall.SIGTERM))
		select {
		case <-done:
			exited = true
		case <-time.After(45 * time.Second):
			panic(Failure{"driver_total_deadline"})
		}
	}
	observations["driver_exit"] = cmd.ProcessState.ExitCode()
	observations["elapsed_seconds"] = time.Since(started).Seconds()
	if name == "preparation-cancel" || name == "driver-death" {
		h.Check("requested_interruption_boundary_observed", signaled)
	}
	pending := Map(observations, "pending")
	h.Check("reservation_observed", Int(pending, "reserved_bytes") == 6<<30)
	h.Check("single_active_attempt", len(List(pending, "attempts")) == 1)
	attempt := Map(List(pending, "attempts")[0])
	h.Check("deadline_starts_at_reservation", Int(attempt, "deadline_continuous_ns")-Int(attempt, "started", "continuous_ns") == 600000000000)
	recovery := Execute(h.Root, append(append([]string{}, arguments...), "--recover"), nil, 45*time.Second)
	Write(filepath.Join(h.Out, "recover.stdout"), recovery.Stdout)
	Write(filepath.Join(h.Out, "recover.stderr"), recovery.Stderr)
	h.Check("recovery_process", recovery.ExitCode == 0)
	after := SnapshotUpdate(filepath.Join(state, "fixture.sqlite"), false, true)
	observations["after"] = after
	h.Check("sqlite_integrity", Str(after, "integrity") == "ok")
	h.Check("reservation_reclaimed", Int(after, "reserved_bytes") == 0)
	h.Check("single_update_identity", len(List(after, "attempts")) == 1 && Str(List(after, "attempts")[0], "update_id") == id)
	finished := Map(List(after, "attempts")[0])
	h.Check("processes_confirmed_stopped", Bool(finished, "stop_confirmed"))
	h.Check("cleanup_confirmed", Bool(finished, "cleanup_confirmed"))
	h.Check("vm_slot_released", Str(after, "control", "active_update_id") == "")
	h.Check("definitions_not_adopted", Get(after, "control", "definition") == nil)
	h.Check("adoption_never_approved", Get(finished, "adoption_approved") == false)
	if name == "bridge" {
		h.Check("normal_driver_exit", cmd.ProcessState.ExitCode() == 0)
		h.Check("normal_attempt_has_no_interruption", Str(finished, "reason") == "")
		report := ReadJSON(filepath.Join(runtime, "output/final.json"))
		observations["final"] = report
		h.Check("control_committed_before_stop", Bool(finished, "control_committed"))
		h.Check("fixture_binding_preserved", Bool(after, "control", "binding", "fixture_only"))
		h.Check("cooldown_preserved", Str(after, "control", "state") == "COOLDOWN")
		h.Check("no_second_case_request", Int(report, "request_count") == 1)
		h.Check("fixed_429_response", Int(report, "response", "http_status") == 429)
		h.Check("final_all_network_requests_finished", Bool(report, "all_network_requests_finished"))
		h.Check("official_origin_not_confirmed", Get(finished, "origin_confirmed") == false)
		h.Check("snapshot_digest_preserved", Str(after, "control", "snapshot_sha256") == Str(report, "snapshot_sha256"))
	} else {
		h.Check("missing_or_invalid_final_keeps_unknown", Str(after, "control", "state") == "UNKNOWN")
		if name == "invalid-final" {
			report := ReadJSON(filepath.Join(runtime, "output/final.json"))
			h.Check("invalid_real_final_refused", report["all_network_requests_finished"] == false && Get(finished, "control_committed") == false && cmd.ProcessState.ExitCode() != 0)
		}
		if name == "preparation-cancel" || name == "driver-death" {
			h.Check("interruption_recorded", Str(finished, "reason") == "INTERRUPTED")
		}
	}
	nativeExists := Exists(filepath.Join(runtime, "output/watchdog/config.json"))
	if name != "preparation-cancel" {
		h.Check("native_fixture_reached", nativeExists)
	}
	if nativeExists {
		config := ReadJSON(filepath.Join(runtime, "output/watchdog/config.json"))
		h.Check("native_update_profile", Str(config, "owner_kind") == "update")
		h.Check("native_deadline_not_reset", Equal(Get(config, "continuous_start_ns"), Get(attempt, "started", "continuous_ns")) && Equal(config["continuous_deadline_ns"], attempt["deadline_continuous_ns"]))
		argv := List(config, "vm_argv")
		nicNone := false
		for i, arg := range argv {
			if arg == "-nic" && i+1 < len(argv) {
				nicNone = argv[i+1] == "none"
			}
		}
		h.Check("native_nic_none", nicNone)
		native := ReadJSON(filepath.Join(runtime, "output/watchdog/results.json"))
		h.Check("guardian_stop_verified", Bool(native, "guardian_result_verified"))
		if name == "bridge" || name == "deadline" || name == "invalid-final" {
			transfer := false
			for _, event := range List(native, "broker_events") {
				transfer = transfer || Str(event, "event") == "TRANSFER_ALLOWED"
			}
			h.Check("guest_preflight_before_transfer", Bool(native, "qemu_started") && transfer)
		}
		if name == "deadline" {
			h.Check("real_600_seconds_elapsed", time.Since(started) >= 600*time.Second)
			h.Check("native_original_deadline_timeout", Str(native, "terminal", "reason") == "UPDATE_TIMEOUT" && !Exists(filepath.Join(runtime, "output/final.json")))
		}
	}
	intent := ReadJSON(filepath.Join(runtime, "output/cleanup-intent.json"))
	absent := true
	for _, row := range List(intent, "directories") {
		absent = absent && !Exists(Str(row, "path"))
	}
	h.Check("owned_external_directories_absent", absent)
	stable := Encoded(finished)
	recovery = Execute(h.Root, append(append([]string{}, arguments...), "--recover"), nil, 45*time.Second)
	h.Check("repeat_recovery_process", recovery.ExitCode == 0)
	h.Check("finished_attempt_not_rewritten", Equal(List(SnapshotUpdate(filepath.Join(state, "fixture.sqlite"), false, true), "attempts")[0], Decode(stable)))
}
