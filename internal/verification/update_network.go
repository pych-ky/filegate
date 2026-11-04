package verification

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

func init() {
	Register("update-network", runUpdateNetwork)
	Register("update-network-state", observeUpdateNetworkState)
}

func observeUpdateNetworkState(h *Harness) {
	directory := h.Paths["state-directory"]
	h.Check("existing_state_supplied", directory != "")
	path := filepath.Join(directory, "state.sqlite")
	if !Exists(path) {
		path = filepath.Join(directory, "data/state.sqlite")
	}
	h.Check("existing_private_state", Exists(path) && !external(h.Root, path))
	before := SnapshotUpdate(path, true, false)
	after := SnapshotUpdate(path, true, false)
	h.Record["scope"] = "read-only durable official update state; no update or retry dispatched"
	h.Record["observed_state"] = before
	h.Record["state_directory"] = filepath.Dir(path)
	h.Record["network_requests"] = 0
	h.Record["official_update_succeeded"] = false
	h.Record["automatic_retry"] = false
	h.Record["existing_uuid_preserved"] = Equal(before, after)
	h.Record["retry_after_utc"] = Get(before, "control", "snapshot", "retry_after_utc")
	h.Record["next_allowed_utc"] = Get(before, "control", "next_allowed_utc")
	h.Check("durable_uuid_snapshot_deadline_history_unchanged", Equal(before, after))
	h.Check("official_binding_retained", Get(before, "control", "binding", "fixture_only") == false)
	WriteJSON(filepath.Join(h.Out, "durable-state.json"), before)
}
func BackupDatabase(source, target string, stopped bool) Object {
	dsn := "file:" + source + "?mode=ro"
	immutable := stopped && !Exists(source+"-wal") && !Exists(source+"-shm")
	before := ""
	if immutable {
		dsn += "&immutable=1"
		before = FileDigest(source)
	}
	src, err := sql.Open("sqlite3", dsn)
	Must(err)
	defer src.Close()
	dst, err := sql.Open("sqlite3", target)
	Must(err)
	defer dst.Close()
	ctx := context.Background()
	sourceConn, err := src.Conn(ctx)
	Must(err)
	defer sourceConn.Close()
	targetConn, err := dst.Conn(ctx)
	Must(err)
	defer targetConn.Close()
	Must(targetConn.Raw(func(target any) error {
		return sourceConn.Raw(func(source any) error {
			backup, err := target.(*sqlite3.SQLiteConn).Backup("main", source.(*sqlite3.SQLiteConn), "main")
			if err != nil {
				return err
			}
			_, err = backup.Step(-1)
			finished := backup.Finish()
			if err != nil {
				return err
			}
			return finished
		})
	}))
	Must(sourceConn.Close())
	Must(targetConn.Close())
	var journal, integrity string
	Must(dst.QueryRow("PRAGMA journal_mode=DELETE").Scan(&journal))
	Must(dst.QueryRow("PRAGMA integrity_check").Scan(&integrity))
	if journal != "delete" || integrity != "ok" {
		panic(Failure{"UPDATE_DATABASE_BACKUP_INVALID"})
	}
	Must(dst.Close())
	Must(src.Close())
	if immutable && (FileDigest(source) != before || Exists(source+"-wal") || Exists(source+"-shm")) {
		panic(Failure{"UPDATE_DATABASE_CHANGED_AFTER_STOP"})
	}
	return Object{"sha256": FileDigest(target), "integrity": integrity, "journal_mode": journal}
}
func snapshotNetwork(h *Harness, stopped bool) Object {
	value := SnapshotUpdate(filepath.Join(h.Data, "state.sqlite"), true, stopped)
	value["adoptions"] = QueryObjects(h, "SELECT data FROM update_adoptions ORDER BY rowid")
	runtime := []any{}
	for _, row := range vmRows(h, "SELECT attempt_id,directory,state,raw_reserved,raw_written,report_sha256 FROM runtime_runs ORDER BY rowid") {
		runtime = append(runtime, row)
	}
	value["scan_runtime"] = runtime
	definitions := []any{}
	for _, row := range vmRows(h, "SELECT attempt_id,update_id,active,data FROM scan_definition_snapshots ORDER BY rowid") {
		row["definition"] = row["data"]
		delete(row, "data")
		definitions = append(definitions, row)
	}
	value["scan_definitions"] = definitions
	value["scan_queue"] = vmScalar(h, "SELECT count(*) FROM scan_queue")
	return value
}
func classifyUpdate(state, final Object) string {
	if len(List(state, "attempts")) == 0 {
		return "not_started"
	}
	if Get(state, "control", "definition") != nil {
		return "official_definitions_adopted"
	}
	status := Int(final, "response", "http_status")
	if status == 403 {
		return "official_http_403"
	}
	if status == 429 {
		return "official_http_429"
	}
	if final != nil && Bool(List(state, "attempts")[0], "control_committed") {
		return "control_saved_without_adoption"
	}
	return "update_state_unknown"
}
func updateScanEvidence(h *Harness, state, job Object) Object {
	h.Check("one_completed_schema3_scan", Str(job, "phase") == "FINISHED" && len(List(state, "scan_runtime")) == 1 && len(List(state, "scan_definitions")) == 1)
	runtime, snapshot := Map(List(state, "scan_runtime")[0]), Map(List(state, "scan_definitions")[0])
	directory := Str(runtime, "directory")
	h.Check("scan_runtime_identity_and_settlement", directory == filepath.Join(h.Data, "runtime", Str(job, "attempt_id")) && Str(runtime, "attempt_id") == Str(snapshot, "attempt_id") && Str(snapshot, "attempt_id") == Str(job, "attempt_id") && Str(runtime, "state") == "FINISHED" && Int(runtime, "raw_reserved") == 0 && Int(runtime, "raw_written") == 0 && Int(snapshot, "active") == 0)
	requested := ReadJSON(filepath.Join(directory, "request.json"))
	definition, current := Map(snapshot, "definition"), Map(state, "control", "definition")
	same := true
	for _, key := range []string{"generation", "confirmed", "manifest_sha256", "image_manifest_sha256"} {
		same = same && Equal(definition[key], current[key])
	}
	h.Check("schema3_definition_is_dispatch_snapshot", Int(requested, "schema_version") == 3 && Str(requested, "policy_digest") == "filegate-product-scan-v4" && Equal(requested["definition"], definition) && Str(requested, "job_id") == Str(job, "job_id") && Str(requested, "attempt_id") == Str(job, "attempt_id") && Str(requested, "expected_sha256") == Str(job, "input_receipt", "sha256") && Equal(requested["byte_size"], Get(job, "input_receipt", "byte_size")) && Str(snapshot, "update_id") == Str(definition, "update_id") && Str(definition, "update_id") == Str(current, "update_id") && same)
	adopted := filepath.Join(h.Data, "definitions", Str(definition, "update_id"))
	imageManifest := ReadJSON(filepath.Join(adopted, "definition-image.json"))
	image := Str(definition, "image_path")
	var stat unix.Stat_t
	Must(unix.Lstat(image, &stat))
	same = true
	for _, key := range []string{"image", "profile", "binding"} {
		same = same && Equal(imageManifest[key], definition[key])
	}
	h.Check("scan_uses_adopted_readonly_image", image == filepath.Join(adopted, "definitions.ext4") && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&07777 == 0400 && stat.Uid == uint32(os.Getuid()) && stat.Nlink == 1 && stat.Size == 1<<30 && Int(definition, "image", "bytes") == stat.Size && Int(definition, "image", "device") == int64(stat.Dev) && Int(definition, "image", "inode") == int64(stat.Ino) && Int(definition, "image", "modified_ns") == stat.Mtim.Sec*1e9+stat.Mtim.Nsec && Int(definition, "image", "changed_ns") == stat.Ctim.Sec*1e9+stat.Ctim.Nsec && FileDigest(image) == Str(definition, "image", "sha256") && FileDigest(filepath.Join(adopted, "definition-image.json")) == Str(definition, "image_manifest_sha256") && same && Get(definition, "binding", "fixture_definitions_only") == false && Get(definition, "profile", "fixture_definitions_only") == false)
	out := filepath.Join(directory, "output")
	summary, report, exchange := ReadJSON(filepath.Join(out, "results.json")), ReadJSON(filepath.Join(out, "report.json")), ReadJSON(filepath.Join(out, "exchange.json"))
	reportSHA := FileDigest(filepath.Join(out, "report.json"))
	h.Check("scan_report_accepted_and_clean", Bool(summary, "passed") && Bool(summary, "report_accepted") && Str(summary, "report_sha256") == reportSHA && Str(runtime, "report_sha256") == reportSHA && Str(exchange, "report_sha256") == reportSHA && Bool(exchange, "report_accepted") && Str(exchange, "outcome") == "verified" && Int(report, "schema_version") == 2 && Str(report, "job_id") == Str(job, "job_id") && Str(report, "attempt_id") == Str(job, "attempt_id") && Equal(report["policy_digest"], requested["policy_digest"]) && Equal(report["input"], Object{"sha256": requested["expected_sha256"], "byte_size": requested["byte_size"]}) && Str(report, "av_process_status") == "completed" && Str(report, "av", "process_status") == "completed" && Str(report, "av_result") == "clean" && Str(report, "av", "av_result") == "clean" && Bool(report, "av", "results_complete") && Bool(report, "av", "binding_verified") && Equal(Get(report, "av", "binding"), definition["binding"]) && Int(report, "av", "exit_code") == 0 && Int(report, "av", "required_input_count") == 1 && Int(report, "av", "normal_result_count") == 1 && Str(report, "result", "structure_status") == "ACCEPT_FORMAT_STRUCTURE" && Get(report, "result", "required_checks_complete") == false)
	complete, intent, proof := ReadJSON(filepath.Join(out, "cleanup-complete.json")), ReadJSON(filepath.Join(out, "cleanup-intent.json")), ReadJSON(filepath.Join(out, "stop-proof.json"))
	native := ReadJSON(filepath.Join(out, "watchdog/results.json"))
	bound := Object{"job_id": requested["job_id"], "attempt_id": requested["attempt_id"], "input_sha256": requested["expected_sha256"], "byte_size": requested["byte_size"]}
	same = true
	for _, value := range []Object{complete, intent, proof} {
		for key, want := range bound {
			same = same && Equal(value[key], want)
		}
	}
	proofSHA := FileDigest(filepath.Join(out, "stop-proof.json"))
	nativeEvidence := Object{"path": "watchdog/results.json", "sha256": FileDigest(filepath.Join(out, "watchdog/results.json"))}
	checks := true
	for _, value := range Map(proof, "checks") {
		checks = checks && value == true
	}
	h.Check("scan_stop_and_cleanup_hash_chain", same && Equal(summary["recovery_evidence"], Object{"path": "cleanup-complete.json", "sha256": FileDigest(filepath.Join(out, "cleanup-complete.json"))}) && Str(complete, "cleanup_intent_sha256") == FileDigest(filepath.Join(out, "cleanup-intent.json")) && Str(complete, "stop_proof_sha256") == proofSHA && Str(intent, "stop_proof_sha256") == proofSHA && Str(intent, "slot_owner_sha256") == FileDigest(filepath.Join(out, "slot-owner.json")) && Str(complete, "kind") == "native_guardian" && Str(intent, "kind") == "native_guardian" && Str(proof, "kind") == "native_guardian" && Equal(summary["native_evidence"], nativeEvidence) && Equal(proof["evidence"], nativeEvidence) && Bool(proof, "stopped") && checks)
	stopped := len(List(native, "cleanup_after")) > 0
	for _, row := range List(native, "cleanup_after") {
		stopped = stopped && Get(row, "same_identity_live") == false
	}
	absent := true
	for _, row := range List(intent, "directories") {
		absent = absent && !Exists(Str(row, "path"))
	}
	h.Check("scan_vm_stopped_and_raw_reclaimed", Bool(native, "qemu_started") && Str(native, "terminal", "reason") == "EXCHANGE_COMPLETE" && Bool(native, "terminal", "all_exited") && Bool(native, "terminal", "transfer_allowed") && Bool(native, "guardian_result_verified") && Bool(native, "cleanup_all_exited") && Bool(native, "temporary_service_absent") && Get(native, "emergency_owned_cleanup") != true && stopped && Bool(summary, "raw_reclaimed") && Bool(summary, "vm_slot_finalized") && Int(summary, "reservation_charge_bytes") == 0 && Bool(complete, "raw_reclaimed") && Bool(complete, "external_directories_reclaimed") && absent)
	nativeIntent := ReadJSON(filepath.Join(out, "native-intent.json"))
	config := ReadJSON(filepath.Join(out, "watchdog/config.json"))
	argv := List(config, "vm_argv")
	nicNone, imageUsed := false, false
	for i, value := range argv {
		if value == "-nic" && i+1 < len(argv) {
			nicNone = argv[i+1] == "none"
		}
		if value == "driver=file,node-name=definitions-file,filename="+image+",read-only=on,discard=ignore" {
			imageUsed = true
		}
	}
	h.Check("scan_native_deadline_and_network_isolation", Equal(config, nativeIntent["config"]) && Str(config, "owner_kind") == "scan" && Int(config, "continuous_deadline_ns")-Int(config, "continuous_start_ns") == 300000000000 && nicNone && imageUsed && Str(config, "helper_pins", image) == Str(definition, "image", "sha256"))
	resources := ReadJSON(filepath.Join(out, "resource-intent.json"))
	pending := Str(resources, "slot_pending")
	h.Check("scan_shared_slot_released_and_gates_closed", !Exists(filepath.Join(filepath.Dir(pending), "active-vm.json")) && !Exists(pending) && Get(summary, "product_enabled") == false && Get(summary, "stage0_gate_passed") == false && Str(job, "verdict") == "HOLD" && Get(job, "release", "eligible") == false)
	return Object{"request": requested, "snapshot": snapshot, "runtime": runtime, "report_sha256": reportSHA, "av": report["av"], "summary": summary, "cleanup_complete": complete, "stop_proof": proof, "native_deadline_seconds": 300, "live_global_process_inventory_performed": false}
}
func preserveUpdateState(h *Harness, out string, stopped bool) {
	h.Record["state_database_backup"] = BackupDatabase(filepath.Join(h.Data, "state.sqlite"), filepath.Join(out, "state.sqlite"), h.Process == nil)
	if !stopped {
		return
	}
	retained := Object{}
	for _, directory := range []string{"updates", "definitions", "runtime"} {
		base := filepath.Join(h.Data, directory)
		if !Exists(base) {
			continue
		}
		Must(filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			var stat unix.Stat_t
			if unix.Lstat(path, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
				return nil
			}
			if stat.Uid != uint32(os.Getuid()) {
				return Failure{"UPDATE_EVIDENCE_OWNER_CHANGED"}
			}
			relative, err := filepath.Rel(h.Data, path)
			if err != nil {
				return err
			}
			digest := FileDigest(path)
			retained[relative] = Object{"path": path, "bytes": stat.Size, "sha256": digest}
			extension := filepath.Ext(path)
			if extension != ".cvd" && extension != ".cld" && extension != ".pending" && stat.Size <= 64<<20 {
				target := filepath.Join(out, "evidence", relative)
				Write(target, Read(path))
				if FileDigest(target) != digest {
					return Failure{"UPDATE_EVIDENCE_COPY_CHANGED"}
				}
			}
			return nil
		}))
	}
	WriteJSON(filepath.Join(out, "retained-files.json"), retained)
}
func runUpdateNetwork(h *Harness) {
	candidate, stateDirectory := h.Paths["registration-candidate"], h.Paths["state-directory"]
	h.Check("unchanged_candidate_and_state_supplied", candidate != "" && stateDirectory != "")
	stateDirectory, err := filepath.Abs(stateDirectory)
	Must(err)
	parent, err := filepath.EvalSymlinks(filepath.Dir(stateDirectory))
	Must(err)
	h.Check("fresh_short_canonical_state", parent == filepath.Dir(stateDirectory) && !Exists(stateDirectory) && !external(h.Root, stateDirectory) && len(filepath.Join(stateDirectory, "data/filegate.sock")) <= 100)
	manifest := ReadJSON(candidate)
	h.Check("unchanged_official_registration", Int(manifest, "schema") == 2 && Str(manifest, "profile") == "filegate-official-update-v1" && Get(manifest, "fixture_only") == false && Str(manifest, "origin") == "https://database.clamav.net" && filepath.Base(Str(manifest, "build")) == "build.json" && Str(manifest, "helper") == filepath.Join(filepath.Dir(Str(manifest, "build")), "filegate-update-bridge") && Str(manifest, "runner") == filepath.Join(Str(manifest, "workspace"), ".build/filegate-update"))
	sourcePins, artifactPins := Object{}, Map(ReadJSON(Str(manifest, "build")), "artifacts_sha256")
	for name, want := range Map(manifest, "sha256") {
		h.Check("unchanged_registration_pin_"+filepath.Base(name), FileDigest(name) == want)
		sourcePins[name] = want
	}
	WriteJSON(filepath.Join(h.Out, "sources.json"), sourcePins)
	WriteJSON(filepath.Join(h.Out, "artifacts-before.json"), artifactPins)
	Must(os.Mkdir(stateDirectory, 0700))
	WriteJSON(filepath.Join(stateDirectory, "network-attempt.json"), Object{"schema": 1, "artifact": h.Out, "registration_sha256": FileDigest(candidate), "automatic_retry": false})
	WriteJSON(filepath.Join(h.Out, "state-location.json"), Object{"directory": stateDirectory, "data_dir": filepath.Join(stateDirectory, "data"), "retry_or_reinitialization_permitted": false})
	sub := normalHarness(h, stateDirectory, manifest)
	observations := Object{"state_directory": stateDirectory, "transitions": []any{}}
	var final Object
	outcome := "not_started"
	started := time.Time{}
	h.Record["network_scope"] = "fixed database.clamav.net:443 through unchanged registered runtime"
	h.Record["official_update_succeeded"] = false
	h.Record["automatic_retry"] = false
	h.Record["state_retained"] = stateDirectory
	h.Record["native_deadline_seconds"] = Object{"update": 600, "scan": 300}
	h.Record["observation_limit_seconds"] = Object{"update": 685, "scan_after_update_settled": 385}
	h.Record["broker_stop_grace_seconds"] = 85
	h.Record["fixture_overlay"] = nil
	h.Record["not_demonstrated"] = []string{"stopped AV research", "Stage 0 or Stage 3 acceptance", "OS reboot or power loss"}
	defer func() {
		failure := recover()
		defer func() {
			if failure != nil {
				panic(failure)
			}
		}()
		func() {
			defer func() {
				if failure := recover(); failure != nil {
					h.Record["cleanup_failure"] = failureRecord(failure)
				}
			}()
			sub.Stop(false)
		}()
		h.Checks = append(h.Checks, sub.Checks...)
		h.Logs = append(h.Logs, sub.Logs...)
		h.Commands = append(h.Commands, sub.Commands...)
		if !started.IsZero() {
			observations["execution_elapsed_seconds"] = time.Since(started).Seconds()
		}
		if sub.Process != nil {
			observations["broker_unresolved_pid"] = sub.Process.Process.Pid
		}
		if Exists(filepath.Join(sub.Data, "state.sqlite")) {
			last := snapshotNetwork(sub, sub.Process == nil)
			observations["last_database"] = last
			outcome = classifyUpdate(last, final)
			stopped := sub.Process == nil
			for _, a := range List(last, "attempts") {
				stopped = stopped && Bool(a, "stop_confirmed")
			}
			for _, row := range List(last, "scan_runtime") {
				stopped = stopped && Str(row, "state") == "FINISHED"
			}
			if sub.Process == nil {
				preserveUpdateState(sub, h.Out, stopped)
			}
			observations["file_snapshot_after_stop_confirmed"] = stopped
		}
		same := true
		for path, want := range sourcePins {
			same = same && FileDigest(path) == want
		}
		h.Check("sources_and_images_unchanged", same)
		h.Record["outcome"] = outcome
		h.Record["official_update_succeeded"] = outcome == "official_definitions_adopted" && failure == nil && h.Record["cleanup_failure"] == nil
		WriteJSON(filepath.Join(h.Out, "observations.json"), observations)
		WriteJSON(filepath.Join(h.Out, "commands.json"), sub.Commands)
		Write(filepath.Join(h.Out, "service.log"), bytesJoin(sub.Logs))
	}()
	health := normalStart(sub, manifest)
	sub.Check("acceptance_gates_closed", GatesClosed(health))
	initial := snapshotNetwork(sub, false)
	observations["initial"] = initial
	sub.Check("new_installation_no_prior_attempt", Str(initial, "control", "state") == "READY" && len(List(initial, "attempts")) == 0 && len(List(initial, "adoptions")) == 0 && Get(initial, "control", "definition") == nil)
	sub.Check("unmodified_runtime_registration", Equal(ReadJSON(filepath.Join(sub.Data, "update-runtime.json")), manifest))
	input := filepath.Join(sub.InputDirectory, "synthetic.txt")
	Write(input, InputA)
	Write(filepath.Join(h.Out, "synthetic.txt"), InputA)
	started = time.Now()
	code, receipt := sub.Submit("file", input, Object{"idempotency_key": "official-update-once", "expected_sha256": Digest(InputA)}, nil)
	observations["receipt"] = receipt
	sub.Check("synthetic_input_committed", code == 0 && Str(receipt, "input_receipt", "sha256") == Digest(InputA))
	previous := ""
	scanStarted := time.Time{}
	runtime := ""
	var job Object
	for {
		state := snapshotNetwork(sub, false)
		_, job = sub.Request("GET", "/v1/jobs/"+Str(receipt, "job_id"), nil, nil, nil)
		observations["latest"], observations["job"] = state, job
		sub.Check("one_update_at_most", len(List(state, "attempts")) <= 1)
		if rows := List(state, "runtime"); len(rows) > 0 {
			runtime = Str(rows[0], "directory")
			sub.Check("runtime_inside_private_update_directory", filepath.Dir(runtime) == filepath.Join(sub.Data, "updates"))
			finalPath := filepath.Join(runtime, "output/final.json")
			if final == nil && Exists(finalPath) {
				final = ReadJSON(finalPath)
				observations["final_first_observed"] = Object{"elapsed_seconds": time.Since(started).Seconds(), "sha256": FileDigest(finalPath), "report": final}
			}
		}
		transition := string(Encoded(Object{"control": Get(state, "control", "state"), "attempts": state["attempts"], "job_phase": job["phase"]}))
		if transition != previous {
			observations["transitions"] = append(observations["transitions"].([]any), Object{"elapsed_seconds": time.Since(started).Seconds(), "control": Get(state, "control", "state"), "attempts": state["attempts"], "job_phase": job["phase"]})
			WriteJSON(filepath.Join(h.Out, "observations.json"), observations)
			previous = transition
		}
		settled := len(List(state, "attempts")) == 1 && Str(state, "control", "active_update_id") == ""
		if settled {
			a := List(state, "attempts")[0]
			settled = Str(a, "state") == "FINISHED" && Bool(a, "stop_confirmed") && Bool(a, "cleanup_confirmed")
		}
		if settled && Get(state, "control", "definition") != nil && scanStarted.IsZero() {
			scanStarted = time.Now()
			observations["update_settled_elapsed_seconds"] = time.Since(started).Seconds()
		}
		phase := Str(job, "phase")
		if settled && (phase == "FINISHED" || phase == "FAILED" || phase == "CANCELLED") {
			break
		}
		if scanStarted.IsZero() && time.Since(started) >= 685*time.Second {
			panic(Failure{"update_observation_deadline_with_stop_grace"})
		}
		if !scanStarted.IsZero() && time.Since(scanStarted) >= 385*time.Second {
			panic(Failure{"scan_observation_deadline_with_stop_grace"})
		}
		if !sub.ServiceAlive() {
			panic(Failure{"broker_exited_during_update"})
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !scanStarted.IsZero() {
		observations["scan_observed_elapsed_seconds"] = time.Since(scanStarted).Seconds()
	}
	sub.Stop(false)
	settled := snapshotNetwork(sub, true)
	observations["settled"] = settled
	outcome = classifyUpdate(settled, final)
	sub.Check("one_update_only", len(List(settled, "attempts")) == 1 && len(List(settled, "runtime")) == 1)
	attempt := Map(List(settled, "attempts")[0])
	sub.Check("installation_uuid_preserved", Str(settled, "control", "snapshot", "uuid") == Str(initial, "control", "snapshot", "uuid"))
	sub.Check("original_preserved_hold", Str(job, "verdict") == "HOLD" && Get(job, "release", "eligible") == false && Equal(job["input_receipt"], receipt["input_receipt"]) && bytes.Equal(Read(filepath.Join(sub.Data, "objects", Str(receipt, "input_receipt", "object_id"))), InputA))
	reclaimed := Bool(attempt, "stop_confirmed") && Bool(attempt, "cleanup_confirmed") && Int(settled, "reserved_bytes") == 0 && Str(List(settled, "runtime")[0], "state") == "FINISHED" && len(List(settled, "waiters")) == 0 && Int(settled, "pins") == 0 && Int(settled, "scan_queue") == 0
	for _, row := range List(settled, "scan_runtime") {
		reclaimed = reclaimed && Str(row, "state") == "FINISHED" && Int(row, "raw_reserved") == 0
	}
	sub.Check("runtime_stopped_and_capacity_reclaimed", reclaimed)
	observations["cleanup_evidence"] = UpdateCleanupEvidence(sub, runtime)
	sub.Check("update_native_deadline_unchanged", Int(attempt, "deadline_continuous_ns")-Int(attempt, "started", "continuous_ns") == 600000000000)
	if Exists(filepath.Join(runtime, "output/native-intent.json")) {
		config := Map(ReadJSON(filepath.Join(runtime, "output/native-intent.json")), "config")
		sub.Check("update_native_deadline_matches_attempt", Str(config, "owner_kind") == "update" && Equal(config["continuous_start_ns"], Get(attempt, "started", "continuous_ns")) && Equal(config["continuous_deadline_ns"], attempt["deadline_continuous_ns"]))
	}
	if Bool(attempt, "control_committed") {
		sub.Check("final_committed_before_adoption", final != nil && Get(final, "fixture_only") == false && Str(attempt, "final_sha256") == FileDigest(filepath.Join(runtime, "output/final.json")) && Str(settled, "control", "state") == "COOLDOWN" && Equal(Get(settled, "control", "snapshot"), final["control_snapshot"]))
		closed := ReadJSON(filepath.Join(runtime, "output/network-closed.json"))
		sub.Check("host_network_closed", Str(closed, "update_id") == Str(attempt, "update_id") && Str(closed, "request_sha256") == FileDigest(filepath.Join(runtime, "request.json")))
	} else {
		sub.Check("unknown_prevents_adoption", Str(settled, "control", "state") == "UNKNOWN" && Get(settled, "control", "definition") == nil && len(List(settled, "adoptions")) == 0)
	}
	if outcome == "official_definitions_adopted" {
		definition := Map(settled, "control", "definition")
		adopted := filepath.Join(sub.Data, "definitions", Str(attempt, "update_id"))
		candidate := ReadJSON(filepath.Join(adopted, "manifest.json"))
		definitions := List(final, "definitions")
		names := map[string]bool{}
		confirmed := len(definitions) == 3
		for _, row := range definitions {
			names[Str(row, "definition")] = true
			confirmed = confirmed && Bool(row, "origin_confirmed") && Bool(row, "artifact_verified")
		}
		sub.Check("official_origin_and_signature_confirmations", Bool(final, "all_required_origin_confirmations") && Bool(final, "all_required_artifacts_verified") && Int(final, "response_count") > 0 && names["main"] && names["daily"] && names["bytecode"] && confirmed)
		sub.Check("adoption_bound_to_final_and_generation", Bool(attempt, "adoption_approved") && len(List(settled, "adoptions")) == 1 && Str(definition, "update_id") == Str(attempt, "update_id") && Int(definition, "generation") == Int(attempt, "base_generation")+1 && Str(definition, "manifest_sha256") == FileDigest(filepath.Join(adopted, "manifest.json")) && Equal(candidate["final_sha256"], attempt["final_sha256"]))
		approved := Map(List(settled, "adoptions")[0], "approved")
		sub.Check("adoption_within_original_deadline", Equal(approved["boot"], Get(attempt, "started", "boot")) && Int(attempt, "final_received", "continuous_ns") <= Int(approved, "continuous_ns") && Int(approved, "continuous_ns") < Int(attempt, "deadline_continuous_ns"))
		validNames, bytesMatch := len(List(candidate, "files")) == 3, true
		for _, row := range List(candidate, "files") {
			name := Str(row, "name")
			base, suffix := strings.TrimSuffix(strings.TrimSuffix(name, ".cvd"), ".cld"), filepath.Ext(name)
			validNames = validNames && (base == "main" || base == "daily" || base == "bytecode") && (suffix == ".cvd" || suffix == ".cld")
			path := filepath.Join(adopted, name)
			info, err := os.Stat(path)
			Must(err)
			bytesMatch = bytesMatch && info.Size() == Int(row, "bytes") && FileDigest(path) == Str(row, "sha256")
		}
		sub.Check("adopted_candidate_names", validNames)
		sub.Check("adopted_bytes_match_verified_candidates", len(List(candidate, "files")) == 3 && bytesMatch)
		observations["schema3_scan_evidence"] = updateScanEvidence(sub, settled, job)
	} else {
		sub.Check("failed_update_not_adopted", Get(attempt, "adoption_approved") == false && len(List(settled, "adoptions")) == 0 && Get(settled, "control", "definition") == nil && Str(job, "phase") == "FAILED" && Contains(Get(job, "reason_codes"), "DATABASE_STALE") && len(List(settled, "scan_runtime")) == 0 && len(List(settled, "scan_definitions")) == 0)
	}
}
