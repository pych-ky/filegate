package verification

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() { Register("update-normal", runUpdateNormal) }
func normalHarness(parent *Harness, directory string, manifest Object) *Harness {
	h := &Harness{Options: parent.Options, Data: filepath.Join(directory, "data"), InputDirectory: filepath.Join(directory, "inputs"), Socket: filepath.Join(directory, "data/filegate.sock"), Record: Object{}, StartTimeout: 30 * time.Second, StopTimeout: 85 * time.Second}
	Must(os.Mkdir(h.Data, 0700))
	Must(os.Mkdir(h.InputDirectory, 0700))
	WriteJSON(filepath.Join(h.Data, "update-runtime.json"), manifest)
	return h
}
func normalStart(h *Harness, manifest Object) Object {
	workspace, proof := h.Paths["scan-workspace"], h.Paths["scan-proof"]
	h.Check("scan_workspace_proof_supplied", workspace != "" && proof != "")
	return h.Start("--vm-runner", filepath.Join(workspace, ".build/filegate-vm"), "--vm-workspace", workspace, "--vm-proof", proof, "--update-library-sha256", Str(manifest, "library_sha256"))
}
func UpdateCleanupEvidence(h *Harness, runtime string) Object {
	out := filepath.Join(runtime, "output")
	requested := ReadJSON(filepath.Join(runtime, "request.json"))
	receipt := ReadJSON(filepath.Join(out, "update-complete.json"))
	h.Check("completion_request_binding", Str(receipt, "profile") == "filegate-official-update-v1" && Get(receipt, "fixture_only") == false && Str(receipt, "update_id") == Str(requested, "attempt_id") && Equal(receipt["base_generation"], Get(requested, "attempt", "base_generation")) && Str(receipt, "request_sha256") == FileDigest(filepath.Join(runtime, "request.json")) && Bool(receipt, "stop_confirmed") && Bool(receipt, "cleanup_confirmed"))
	complete, intent, proof := ReadJSON(filepath.Join(out, "cleanup-complete.json")), ReadJSON(filepath.Join(out, "cleanup-intent.json")), ReadJSON(filepath.Join(out, "stop-proof.json"))
	proofSHA := FileDigest(filepath.Join(out, "stop-proof.json"))
	h.Check("cleanup_hash_chain", Str(receipt, "cleanup_sha256") == FileDigest(filepath.Join(out, "cleanup-complete.json")) && Str(complete, "cleanup_intent_sha256") == FileDigest(filepath.Join(out, "cleanup-intent.json")) && Str(complete, "stop_proof_sha256") == proofSHA && Str(intent, "stop_proof_sha256") == proofSHA && Str(receipt, "stop_proof_sha256") == proofSHA && Str(intent, "slot_owner_sha256") == FileDigest(filepath.Join(out, "slot-owner.json")) && Str(complete, "kind") == Str(intent, "kind") && Str(intent, "kind") == Str(proof, "kind"))
	bound := Object{"job_id": requested["job_id"], "attempt_id": requested["attempt_id"], "input_sha256": requested["expected_sha256"], "byte_size": requested["byte_size"]}
	same := true
	for _, value := range []Object{complete, intent, proof} {
		for key, expected := range bound {
			same = same && Equal(value[key], expected)
		}
	}
	h.Check("proofs_bound_to_snapshot", same && Bool(proof, "stopped") && Bool(complete, "raw_reclaimed") && Bool(complete, "external_directories_reclaimed"))
	evidence := Str(proof, "evidence", "path")
	path := filepath.Join(out, evidence)
	relative, err := filepath.Rel(out, path)
	h.Check("stop_evidence_scope", err == nil && relative != ".." && !strings.HasPrefix(relative, "../") && !filepath.IsAbs(evidence))
	h.Check("stop_evidence_digest", FileDigest(path) == Str(proof, "evidence", "sha256"))
	absent := true
	for _, row := range List(intent, "directories") {
		absent = absent && !Exists(Str(row, "path"))
	}
	h.Check("owned_external_directories_absent", absent)
	resources := ReadJSON(filepath.Join(out, "resource-intent.json"))
	pending := Str(resources, "slot_pending")
	h.Check("shared_slot_released", !Exists(filepath.Join(filepath.Dir(pending), "active-vm.json")) && !Exists(pending))
	native := Object{}
	if Exists(filepath.Join(out, "watchdog/results.json")) {
		native = ReadJSON(filepath.Join(out, "watchdog/results.json"))
		stopped := true
		for _, row := range List(native, "cleanup_after") {
			stopped = stopped && Get(row, "same_identity_live") == false
		}
		h.Check("native_saved_stop_readback", Bool(native, "cleanup_all_exited") && Bool(native, "temporary_service_absent") && stopped)
	}
	return Object{"completion": receipt, "cleanup_complete": complete, "cleanup_intent": intent, "stop_proof": proof, "native_reached": len(native) > 0, "qemu_started": native["qemu_started"], "live_global_process_inventory_performed": false}
}
func guardedManifest(h *Harness, candidate string) Object {
	manifest := ReadJSON(candidate)
	workspace := Str(manifest, "workspace")
	originalHelper := Str(manifest, "helper")
	h.Check("UPDATE_GO_HELPER_BINDING_REQUIRED", filepath.Base(originalHelper) == "filegate-update-bridge" && FileDigest(originalHelper) == Str(manifest, "sha256", originalHelper))
	changes := Object{}
	originals := Object{}
	for _, name := range []string{"forward.go", "exchange.go"} {
		source := filepath.Join(workspace, "internal/updatebridge", name)
		body := string(Read(source))
		originals[source] = FileDigest(source)
		h.Check("UPDATE_GO_SOURCE_CHANGED_"+name, Get(manifest, "sha256", source) == originals[source])
		if name == "forward.go" {
			start, end := strings.Index(body, "func Forward("), strings.Index(body, "func relayNetwork(")
			h.Check("UPDATE_FORWARD_MARKER", start >= 0 && end > start)
			body = body[:start] + `func Forward(request, expected string) error { _,err:=writeControl(` + string(Encoded(filepath.Join(h.Out, "forward-forbidden.json"))) + `,object{"forward_attempted":true,"network_opened":false});if err!=nil{return err};return errInvalid }
` + body[end:]
			body = strings.Replace(body, "\t\"context\"\n", "", 1)
			body = strings.Replace(body, "\t\"sort\"\n", "", 1)
		} else {
			body = ReplaceOnce(body, "func Run(directory, requestPath, requestSHA string, input io.Reader, output io.Writer) error {", `func Run(directory, requestPath, requestSHA string, input io.Reader, output io.Writer) (resultErr error) {
defer func(){if resultErr!=nil{message:=[]byte(resultErr.Error());_,_=writeControl(`+string(Encoded(filepath.Join(h.Out, "helper-failure.json")))+`,object{"error_code":"UPDATE_HELPER_FAILED","message_sha256":digest(message),"message_bytes":len(message)})}}()`)
			body = ReplaceOnce(body, "ready, err := receive(connection, reader)", "ready, err := receive(connection, reader)\nfixturePreflight(ready,err)")
			marker := `reply = object{"event": "freshclam_control_request", "request": x.requested["restore"], "definition_cache": x.requested["definition_cache"]}`
			body = ReplaceOnce(body, marker, "if err=fixtureReadyHold(id,value[\"library_sha256\"]);err!=nil{return err}\n"+marker)
			body += `
func fixtureReadyHold(id string,library any)error{if _,err:=writeControl(` + string(Encoded(filepath.Join(h.Out, "fixture-ready.json"))) + `,object{"schema":1,"update_id":id,"library_sha256":library,"restore_sent":false});err!=nil{return err};for{time.Sleep(100*time.Millisecond)}}
func fixturePreflight(value object,failure error){
 if failure!=nil{text:=[]byte(failure.Error());_,_=writeControl(` + string(Encoded(filepath.Join(h.Out, "frame-failure.json"))) + `,object{"error_code":"UPDATE_FRAME_REJECTED","message_bytes":len(text),"message_sha256":digest(text)});return}
 detail,_:=encoded(value["detail"]);if text,ok:=value["detail"].(string);ok{detail=[]byte(text)};event:=value["event"];if !oneOf(event,"ready","boot_error","protocol_error"){event="other"};reason:=value["reason"];if !oneOf(reason,"WORKSPACE_CONFIGURATION_ERROR","WORKSPACE_IO_ERROR","RESOURCE_MONITOR_FAILED"){reason=nil}
 _,_=writeControl(` + string(Encoded(filepath.Join(h.Out, "preflight-observation.json"))) + `,object{"event":event,"reason":reason,"detail_code":nil,"detail_sha256":digest(detail),"detail_bytes":len(detail),"network_matches":same(value["net_devices"],[]string{"/sys/class/net/eth0","/sys/class/net/lo"}),"loopback_up":value["loopback_up"]==true,"blocks_match":same(value["blocks"],object{"vda":object{"sectors":"2097152","read_only":"1"},"vdb":object{"sectors":"32768","read_only":"1"},"vdc":object{"sectors":"8388608","read_only":"0"}})})
}
`
		}
		target := filepath.Join(h.Out, "guarded-"+name)
		Write(target, []byte(body))
		formatted := Execute(workspace, []string{"gofmt", "-w", target}, nil, 10*time.Second)
		h.Check("guarded_overlay_format_"+name, formatted.ExitCode == 0)
		changes[source] = target
	}
	overlay := filepath.Join(h.Out, "go-overlay.json")
	WriteJSON(overlay, Object{"Replace": changes})
	helper := filepath.Join(h.Out, "guarded-filegate-update-bridge")
	command := []string{"go", "build", "-trimpath", "-buildvcs=false", "-overlay", overlay, "-o", helper, "./cmd/filegate-update-bridge"}
	built := Execute(workspace, command, nil, 3*time.Minute)
	Write(filepath.Join(h.Out, "guarded-helper.build.stdout"), built.Stdout)
	Write(filepath.Join(h.Out, "guarded-helper.build.stderr"), built.Stderr)
	WriteJSON(filepath.Join(h.Out, "guarded-helper-build.json"), Object{"argv": command, "exit_code": built.ExitCode, "source_sha256": originals, "overlay_sha256": FileDigest(overlay)})
	h.Check("UPDATE_GO_GUARDED_BUILD_FAILED", built.ExitCode == 0)
	for name, want := range originals {
		h.Check("guard_source_unchanged_"+filepath.Base(name), FileDigest(name) == want)
	}
	Must(os.Chmod(helper, 0500))
	build := ReadJSON(Str(manifest, "build"))
	originalArtifacts := Map(build, "artifacts_sha256")
	artifacts := Object{helper: FileDigest(helper)}
	pins := Map(manifest, "sha256")
	for _, name := range []string{"base.ext4", "definitions.ext4", "kernel", "initramfs.cpio.gz"} {
		source := filepath.Join(filepath.Dir(Str(manifest, "build")), name)
		target := filepath.Join(h.Out, name)
		copyArtifact(source, target)
		h.Check("guarded_image_"+name, FileDigest(target) == originalArtifacts[source])
		artifacts[target] = originalArtifacts[source]
		pins[target] = originalArtifacts[source]
	}
	build["artifacts_sha256"] = artifacts
	guardedBuild := filepath.Join(h.Out, "guarded-build.json")
	WriteJSON(guardedBuild, build)
	delete(pins, Str(manifest, "build"))
	delete(pins, Str(manifest, "helper"))
	manifest["build"], manifest["helper"] = guardedBuild, helper
	pins[guardedBuild] = FileDigest(guardedBuild)
	pins[helper] = FileDigest(helper)
	WriteJSON(filepath.Join(h.Out, "overlay.json"), Object{"original_candidate_sha256": FileDigest(candidate), "original_helper": originalHelper, "original_helper_sha256": FileDigest(originalHelper), "guarded_helper_sha256": FileDigest(helper), "forward_disabled_before_DNS": true, "stop_point": "before normal restore is sent to adapter", "report_or_origin_substituted": false, "go_overlay_sha256": FileDigest(overlay), "images_copied_without_changing_baseline_inode": true})
	return manifest
}
func copyArtifact(source, target string) {
	input, err := os.Open(source)
	Must(err)
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	Must(err)
	_, err = io.Copy(output, input)
	if err != nil {
		_ = output.Close()
		panic(err)
	}
	Must(output.Sync())
	Must(output.Close())
}
func runUpdateNormal(h *Harness) {
	name := selectedCase(h, "")
	known := map[string]bool{"registration": true, "image-registration": true, "pin-change": true, "preparation-cancel": true, "broker-death": true, "ready-cancel": true}
	h.Check("normal_case", known[name])
	candidate := h.Paths["registration-candidate"]
	h.Check("registration_candidate_supplied", candidate != "")
	original := ReadJSON(candidate)
	baseline := Map(ReadJSON(Str(original, "build")), "artifacts_sha256")
	for path, want := range baseline {
		h.Check("baseline_artifact_"+filepath.Base(path), FileDigest(path) == want)
	}
	WriteJSON(filepath.Join(h.Out, "baseline-artifacts.json"), baseline)
	manifest := guardedManifest(h, candidate)
	h.Record["case"] = name
	h.Record["external_requests"] = 0
	h.Record["network_guard_in_helper"] = true
	h.Record["definition_adoption_exercised"] = false
	h.Record["state_retained"] = true
	h.Record["retain_state"] = true
	h.Record["not_demonstrated"] = []string{"official network acquisition", "successful Final or definition adoption", "600 seconds elapsed", "OS reboot or sleep"}
	observations := Object{}
	defer func() {
		WriteJSON(filepath.Join(h.Out, "observations.json"), observations)
		for path, want := range baseline {
			h.Check("baseline_unchanged_"+filepath.Base(path), FileDigest(path) == want)
		}
	}()
	newState := func(label string, m Object) *Harness {
		directory := filepath.Join(h.Temporary, label)
		Must(os.Mkdir(directory, 0700))
		return normalHarness(h, directory, m)
	}
	collect := func(sub *Harness) {
		defer func() {
			if failure := recover(); failure != nil {
				h.Record["cleanup_failure"] = failureRecord(failure)
			}
			h.Checks = append(h.Checks, sub.Checks...)
			h.Logs = append(h.Logs, sub.Logs...)
			h.Commands = append(h.Commands, sub.Commands...)
			if sub.Process != nil {
				h.Record["broker_unresolved_pid"] = sub.Process.Process.Pid
			}
		}()
		sub.Stop(false)
	}
	if name == "registration" || name == "image-registration" {
		rejections := []string{"fixture-only", "changed-pin"}
		if name == "image-registration" {
			rejections = []string{"image-profile", "missing-image-tool-pin", "image-tool-binding"}
		}
		for _, label := range rejections {
			wrong := Decode(Encoded(manifest))
			switch label {
			case "fixture-only":
				wrong["fixture_only"] = true
			case "changed-pin":
				Map(wrong, "sha256")[Str(wrong, "helper")] = strings.Repeat("0", 64)
			case "image-profile":
				Map(wrong, "image_profile")["observation_sha256"] = strings.Repeat("0", 64)
			case "missing-image-tool-pin":
				delete(Map(wrong, "sha256"), Str(wrong, "image_tools", "debugfs"))
			case "image-tool-binding":
				Map(wrong, "image_tools")["debugfs"] = wrong["runner"]
			}
			sub := newState(label, wrong)
			command := []string{sub.Binary, "--data-dir", sub.Data, "serve", "--input-root", "fixture=" + sub.InputDirectory, "--vm-runner", filepath.Join(h.Paths["scan-workspace"], ".build/filegate-vm"), "--vm-workspace", h.Paths["scan-workspace"], "--vm-proof", h.Paths["scan-proof"], "--update-library-sha256", Str(wrong, "library_sha256")}
			r := Execute(h.Root, command, nil, 30*time.Second)
			rejected := Decode(r.Stdout)
			h.Check(label+"_rejected", r.ExitCode == 2 && ErrorCode(rejected) == "INVALID_UPDATE_CONFIGURATION")
			observations[label] = Object{"exit_code": r.ExitCode, "response": rejected}
		}
		sub := newState("valid", manifest)
		defer collect(sub)
		health := normalStart(sub, manifest)
		sub.Check("valid_registration_gate_closed", GatesClosed(health))
		state := SnapshotUpdate(filepath.Join(sub.Data, "state.sqlite"), true, false)
		observations["valid"] = state
		sub.Check("registration_has_no_attempt_or_definition", len(List(state, "attempts")) == 0 && Get(state, "control", "definition") == nil)
		return
	}
	sub := newState(name, manifest)
	defer collect(sub)
	normalStart(sub, manifest)
	if name == "pin-change" {
		helper := Str(manifest, "helper")
		originalBody := Read(helper)
		defer func() {
			Must(os.Chmod(helper, 0700))
			Write(helper, originalBody)
			Must(os.Chmod(helper, 0500))
			h.Check("guarded_helper_restored", FileDigest(helper) == Digest(originalBody))
		}()
		Must(os.Chmod(helper, 0700))
		file, err := os.OpenFile(helper, os.O_APPEND|os.O_WRONLY, 0700)
		Must(err)
		_, err = file.Write([]byte("\nPIN_CHANGED_AFTER_REGISTRATION\n"))
		Must(err)
		Must(file.Sync())
		Must(file.Close())
		Must(os.Chmod(helper, 0500))
		input := filepath.Join(sub.InputDirectory, "synthetic.txt")
		Write(input, InputA)
		code, receipt := sub.Submit("file", input, Object{"idempotency_key": "normal-update-pin-change", "expected_sha256": Digest(InputA)}, nil)
		sub.Check("input_committed", code == 0 && Str(receipt, "input_receipt", "sha256") == Digest(InputA))
		job := sub.WaitJob(Str(receipt, "job_id"), true)
		state := SnapshotUpdate(filepath.Join(sub.Data, "state.sqlite"), true, false)
		observations["job"], observations["after"] = job, state
		sub.Check("changed_runtime_pin_rejected", Str(job, "phase") == "FAILED" && Str(job, "verdict") == "HOLD" && Contains(Get(job, "reason_codes"), "UPDATE_CONTROL_INVALID") && Get(job, "release", "eligible") == false)
		sub.Check("changed_pin_has_no_update_or_reservation", len(List(state, "attempts")) == 0 && len(List(state, "runtime")) == 0 && len(List(state, "waiters")) == 0 && Int(state, "pins") == 0 && Int(state, "reserved_bytes") == 0 && Get(state, "control", "definition") == nil)
		sub.Check("original_preserved_without_network", bytes.Equal(Read(filepath.Join(sub.Data, "objects", Str(receipt, "input_receipt", "object_id"))), InputA) && !Exists(filepath.Join(h.Out, "forward-forbidden.json")))
		return
	}
	input := filepath.Join(sub.InputDirectory, "synthetic.txt")
	Write(input, InputA)
	code, receipt := sub.Submit("file", input, Object{"idempotency_key": "normal-update-startup", "expected_sha256": Digest(InputA)}, nil)
	observations["receipt"] = receipt
	sub.Check("input_committed", code == 0 && Str(receipt, "input_receipt", "sha256") == Digest(InputA))
	deadline := time.Now().Add(100 * time.Second)
	runtime := ""
	var pending Object
	for time.Now().Before(deadline) {
		if Exists(filepath.Join(h.Out, "helper-failure.json")) {
			observations["helper_failure"] = ReadJSON(filepath.Join(h.Out, "helper-failure.json"))
			panic(Failure{"normal_helper_failed_before_stop_point"})
		}
		state := SnapshotUpdate(filepath.Join(sub.Data, "state.sqlite"), true, false)
		if rows := List(state, "runtime"); len(rows) > 0 {
			runtime = Str(rows[0], "directory")
			marker := filepath.Join(runtime, "output/preparation-owner.json")
			if name == "ready-cancel" || name == "broker-death" {
				marker = filepath.Join(h.Out, "fixture-ready.json")
			}
			if Exists(marker) {
				pending = state
				observations["stop_marker"] = ReadJSON(marker)
				observations["stop_marker_path"] = marker
				break
			}
		}
		if !sub.ServiceAlive() {
			panic(Failure{"service_exited_before_stop_point"})
		}
		time.Sleep(30 * time.Millisecond)
	}
	sub.Check("normal_stop_point_not_observed", pending != nil)
	observations["pending"] = pending
	sub.Check("six_gib_reserved", Int(pending, "reserved_bytes") == 6<<30)
	sub.Check("one_attempt_waiter_pinned", len(List(pending, "attempts")) == 1 && len(List(pending, "waiters")) == 1 && Int(pending, "pins") == 1)
	_, waiting := sub.Request("GET", "/v1/jobs/"+Str(receipt, "job_id"), nil, nil, nil)
	observations["waiting_job"] = waiting
	sub.Check("waiting_phase_contract", Str(waiting, "phase") == "QUEUED_FOR_SCAN" && Str(waiting, "wait_reason") == "DEFINITION_UPDATE" && Str(waiting, "update_id") == Str(List(pending, "attempts")[0], "update_id"))
	projectedJob := func(label, controlState string) Object {
		controls := QueryObjects(sub, "SELECT data FROM update_control")
		sub.Check(label+"_control_exists", len(controls) == 1)
		before := Map(controls[0])
		started := time.Now().UTC().Unix()
		status, projected := sub.Request("GET", "/v1/jobs/"+Str(receipt, "job_id"), nil, nil, nil)
		ended := time.Now().UTC().Unix()
		controls = QueryObjects(sub, "SELECT data FROM update_control")
		sub.Check(label+"_control_readback_exists", len(controls) == 1)
		after := Map(controls[0])
		observations[label] = Object{"status": status, "job": projected, "control_before": before, "control_after": after, "request_started_utc": started, "response_received_utc": ended}
		stable := status == 200 && Str(before, "state") == controlState && Str(after, "state") == controlState &&
			Str(before, "clock", "boot") == Str(after, "clock", "boot") &&
			Int(before, "clock", "utc") <= Int(after, "clock", "utc") &&
			Int(before, "clock", "continuous_ns") <= Int(after, "clock", "continuous_ns")
		for _, key := range []string{"generation", "active_update_id", "last_update_id", "snapshot_sha256", "next_allowed_utc", "remaining_seconds"} {
			stable = stable && Equal(before[key], after[key])
		}
		sub.Check(label+"_same_update_state_during_GET", stable && Str(projected, "update_id") == Str(before, "last_update_id"))
		value, present := projected["next_allowed_at"]
		valid := present && value == nil && controlState == "UNKNOWN"
		if controlState == "IN_FLIGHT" {
			parsed, err := time.Parse(time.RFC3339, Str(projected, "next_allowed_at"))
			valid = present && err == nil && parsed.UTC().Format(time.RFC3339) == value &&
				Int(before, "next_allowed_utc") == 0 && Int(before, "remaining_seconds") == 0 &&
				Str(before, "active_update_id") == Str(projected, "update_id") &&
				parsed.Unix() >= started && parsed.Unix() <= ended &&
				parsed.Unix() >= Int(before, "clock", "utc") && parsed.Unix() <= Int(after, "clock", "utc")
		}
		sub.Check(label+"_next_allowed_matches_current_state_and_time", valid)
		return projected
	}
	var cancelled Object
	var cancelledRows [][]any
	if name == "ready-cancel" {
		status, job := sub.Request("POST", "/v1/jobs/"+Str(receipt, "job_id")+"/cancel", nil, nil, nil)
		projected := projectedJob("cancelled_projection", "IN_FLIGHT")
		cancelled = projected
		cancelledRows = sub.Query("SELECT id,created,finished,data FROM jobs WHERE id=?", Str(receipt, "job_id"))
		state := SnapshotUpdate(filepath.Join(sub.Data, "state.sqlite"), true, false)
		observations["waiter_cancel"] = Object{"status": status, "job": job, "get_status": Get(observations, "cancelled_projection", "status"), "projected_job": projected, "durable_rows": cancelledRows, "state": state}
		sub.Check("waiter_cancel_releases_only_job", status == 200 && Str(job, "phase") == "CANCELLED" && Str(job, "verdict") == "HOLD" && Str(job, "wait_reason") == "" && len(List(state, "waiters")) == 0 && Int(state, "pins") == 0 && Int(state, "reserved_bytes") == 6<<30 && Str(state, "control", "active_update_id") == Str(waiting, "update_id"))
		sub.Check("cancelled_get_and_durable_job_bound", len(cancelledRows) == 1 && Equal(QueryObjects(sub, "SELECT data FROM jobs WHERE id=?", Str(receipt, "job_id")), []any{job}))
	}
	sub.Stop(name == "broker-death")
	normalStart(sub, manifest)
	after := SnapshotUpdate(filepath.Join(sub.Data, "state.sqlite"), true, false)
	var job Object
	if name == "ready-cancel" {
		job = projectedJob("reopened_projection", "UNKNOWN")
	} else {
		_, job = sub.Request("GET", "/v1/jobs/"+Str(receipt, "job_id"), nil, nil, nil)
	}
	observations["after"], observations["job"] = after, job
	ids := func(state Object) []string {
		values := []string{}
		for _, a := range List(state, "attempts") {
			values = append(values, Str(a, "update_id"))
		}
		return values
	}
	sub.Check("same_attempt_recovered", Equal(ids(after), ids(pending)))
	stopped := Int(after, "reserved_bytes") == 0
	for _, a := range List(after, "attempts") {
		stopped = stopped && Bool(a, "stop_confirmed") && Bool(a, "cleanup_confirmed")
	}
	sub.Check("stopped_cleaned_reservation_zero", stopped)
	finished := Str(after, "control", "active_update_id") == ""
	for _, row := range List(after, "runtime") {
		finished = finished && Str(row, "state") == "FINISHED"
	}
	sub.Check("runtime_finished_and_active_slot_empty", finished)
	sub.Check("waiters_pins_released", len(List(after, "waiters")) == 0 && Int(after, "pins") == 0)
	sub.Check("control_unknown_no_definition", Str(after, "control", "state") == "UNKNOWN" && Get(after, "control", "definition") == nil)
	phase, reason := "FAILED", "DATABASE_STALE"
	if name == "ready-cancel" {
		phase, reason = "CANCELLED", "CANCELLED"
	}
	sub.Check("job_hold_original_preserved", Str(job, "phase") == phase && Contains(Get(job, "reason_codes"), reason) && Str(job, "verdict") == "HOLD" && Get(job, "release", "eligible") == false && Equal(job["input_receipt"], receipt["input_receipt"]) && bytes.Equal(Read(filepath.Join(sub.Data, "objects", Str(receipt, "input_receipt", "object_id"))), InputA))
	if cancelled != nil {
		withoutTiming := func(value Object) Object {
			result := Object{}
			for key, field := range value {
				if key != "next_allowed_at" {
					result[key] = field
				}
			}
			return result
		}
		observations["separately_verified_projection_fields"] = []string{"next_allowed_at"}
		sub.Check("cancelled_waiter_not_rewritten", Equal(withoutTiming(job), withoutTiming(cancelled)))
		rows := sub.Query("SELECT id,created,finished,data FROM jobs WHERE id=?", Str(receipt, "job_id"))
		observations["cancelled_durable_rows_after"] = rows
		sub.Check("cancelled_durable_job_not_rewritten", Equal(rows, cancelledRows))
	}
	sub.Check("no_final_no_network_forward", !Exists(filepath.Join(h.Out, "forward-forbidden.json")) && !Exists(filepath.Join(runtime, "output/final.json")))
	observations["cleanup_evidence"] = UpdateCleanupEvidence(sub, runtime)
	stable := Encoded(after["attempts"])
	sub.Stop(false)
	normalStart(sub, manifest)
	sub.Check("finished_attempt_not_rewritten", bytes.Equal(Encoded(SnapshotUpdate(filepath.Join(sub.Data, "state.sqlite"), true, false)["attempts"]), stable))
}
