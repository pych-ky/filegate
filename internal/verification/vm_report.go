package verification

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filegate.local/filegate/internal/av"
)

const vmReportJob = "job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const vmReportAttempt = "attempt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const vmReportObject = "object_cccccccccccccccccccccccccccccccc"

type vmReportSuite struct {
	h                       *Harness
	binary, binding, inputs string
	cases                   []Object
}

func init()                       { Register("product-av-report", runVMReport); Register("report-contract", runVMReport) }
func vmClone(value Object) Object { return Decode(Encoded(value)) }
func vmReportFixtures(h *Harness) (string, Object) {
	inputs := filepath.Join(h.Out, "inputs")
	Must(os.Mkdir(inputs, 0700))
	text := []byte("FileGate harmless report-contract input.\n")
	Write(filepath.Join(inputs, "plain.txt"), text)
	Write(filepath.Join(inputs, "empty.txt"), nil)
	var stream bytes.Buffer
	writer := zip.NewWriter(&stream)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"empty.txt", nil}, {"plain.txt", text}, {"empty-directory/", nil}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		header.SetMode(0644)
		if strings.HasSuffix(entry.name, "/") {
			header.SetMode(os.ModeDir | 0755)
		}
		target, err := writer.CreateHeader(header)
		Must(err)
		_, err = target.Write(entry.body)
		Must(err)
	}
	Must(writer.Close())
	Write(filepath.Join(inputs, "mixed.zip"), stream.Bytes())
	binding := Object{"profile_sha256": Digest([]byte("fixture-only profile")), "scanner_manifest_sha256": Digest([]byte("fixture-only scanner manifest")), "binary_sha256": av.BinarySHA256, "configuration_sha256": av.ConfigurationSHA256, "definition_set_sha256": Digest([]byte("fixture-only definitions")), "observation_sha256": Digest([]byte("fixture-only observations")), "fixture_definitions_only": true}
	WriteJSON(filepath.Join(h.Out, "expected-binding.json"), binding)
	return inputs, binding
}
func makeVMReport(inputs, name string, binding Object, started, detected bool) Object {
	text := Read(filepath.Join(inputs, "plain.txt"))
	original := Read(filepath.Join(inputs, name))
	kind, format := "regular_file", "txt"
	if strings.HasSuffix(name, ".zip") {
		kind, format = "container", "zip"
	}
	manifest := []Object{{"object_id": "object_000001", "kind": kind, "format": format, "sha256": Digest(original), "byte_size": len(original), "av_required": true}}
	if format == "zip" {
		for i, content := range [][]byte{nil, text} {
			id := []string{"object_000002", "object_000003"}[i]
			manifest = append(manifest, Object{"object_id": id, "parent_id": "object_000001", "kind": "regular_file", "format": "txt", "sha256": Digest(content), "byte_size": len(content), "av_required": true, "path": id + ".data"})
		}
		manifest = append(manifest, Object{"object_id": "object_000004", "parent_id": "object_000001", "kind": "verified_empty_directory", "byte_size": 0, "av_required": false, "av_exclusion_reason": "VERIFIED_EMPTY_DIRECTORY"})
	}
	objects := []Object{}
	for _, item := range manifest {
		if item["av_required"] == true {
			objects = append(objects, Object{"object_id": item["object_id"], "sha256": item["sha256"], "byte_size": item["byte_size"], "status": "clean", "reason_code": "", "signature_sha256": "", "input_verified": true, "normal_result_present": true})
		}
	}
	engine := Object{"schema_version": 1, "profile_id": av.ProfileID, "process_status": "completed", "av_result": "clean", "results_complete": true, "binding_verified": true, "binding": binding, "required_input_count": len(objects), "normal_result_count": len(objects), "exit_code": 0, "stdout_bytes": len("fixture transcript\n"), "stdout_sha256": Digest([]byte("fixture transcript\n")), "stderr_bytes": 0, "stderr_sha256": Digest(nil), "reason_codes": []string{}, "objects": objects, "confirmed_detections": []Object{}}
	if detected {
		last := objects[len(objects)-1]
		last["status"] = "detected"
		last["reason_code"] = "MALWARE_DETECTED"
		last["signature_sha256"] = Digest([]byte("fixture-only-detection"))
		detection := Object{}
		for _, key := range []string{"object_id", "sha256", "byte_size", "reason_code", "signature_sha256"} {
			detection[key] = last[key]
		}
		engine["exit_code"] = 1
		engine["av_result"] = "detected"
		engine["confirmed_detections"] = []Object{detection}
	}
	if !started {
		for key, value := range (Object{"process_status": "not_started", "av_result": "inconclusive", "results_complete": false, "binding_verified": false, "binding": nil, "required_input_count": 0, "normal_result_count": 0, "exit_code": nil, "stdout_bytes": 0, "stdout_sha256": "", "stderr_sha256": "", "reason_codes": []string{"INCOMPLETE_REQUIRED_CHECKS"}, "objects": []Object{}, "confirmed_detections": []Object{}}) {
			engine[key] = value
		}
	}
	extracted := 0
	if format == "zip" {
		extracted = len(text)
	}
	result := Object{"schema_version": 1, "structure_status": "ACCEPT_FORMAT_STRUCTURE", "structure_checks_complete": true, "format_checks_complete": true, "required_checks_complete": false, "reason_codes": []string{}, "completed_checks": []string{"manifest"}, "archive_entry_count": len(manifest) - 1, "extracted_file_count": len(objects) - 1, "required_av_input_count": len(objects), "extracted_bytes": extracted, "manifest": manifest, "confirmed_rejections": []Object{}}
	return vmClone(Object{"schema_version": 2, "event": "product_result", "job_id": vmReportJob, "attempt_id": vmReportAttempt, "policy_digest": "filegate-product-scan-v4", "input": Object{"sha256": Digest(original), "byte_size": len(original)}, "worker_uid": 65534, "report_complete": true, "manifest_complete": true, "av_process_status": engine["process_status"], "av_result": engine["av_result"], "result": result, "av": engine})
}
func vmReportJobValue(report Object) Object {
	return Object{"schema_version": "4", "job_id": vmReportJob, "attempt_id": vmReportAttempt, "phase": "INSPECTING", "verdict": "UNDECIDED", "intake_status": "COMMITTED", "reason_codes": []string{}, "execution_errors": []string{}, "input_receipt": Object{"object_id": vmReportObject, "sha256": Get(report, "input", "sha256"), "byte_size": Get(report, "input", "byte_size"), "content_available": true}, "release": Object{"eligible": false}, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "coverage": Object{"profile_id": "filegate-standard-av-v1-unadopted", "required_checks_complete": false, "av_process_status": "not_started", "av_result": "pending", "av_coverage_assurance": "standard_engine_best_effort", "required_av_input_count": 0, "av_normal_result_count": 0, "known_limitations": []string{"AV_INTERNAL_LIMITS_NOT_FULLY_OBSERVABLE"}}, "confirmed_rejections": []Object{}, "runtime_cleanup_complete": false}
}
func (s *vmReportSuite) invoke(directory, name string, options Object, exit int) Object {
	path := filepath.Join(directory, name+"-options.json")
	WriteJSON(path, options)
	args := []string{s.binary, "report-fixture-driver", path}
	result := Execute(s.h.Root, args, nil, 60*time.Second)
	Write(filepath.Join(directory, name+".stdout"), result.Stdout)
	Write(filepath.Join(directory, name+".stderr"), result.Stderr)
	var value Object
	if len(result.Stdout) > 0 {
		value = Decode(result.Stdout)
	}
	WriteJSON(filepath.Join(directory, name+"-execution.json"), Object{"command": args, "exit_code": result.ExitCode, "response": value, "stdout_sha256": Digest(result.Stdout), "stderr_sha256": Digest(result.Stderr), "stderr_bytes": len(result.Stderr)})
	s.h.Check(name+"_driver_exit", result.ExitCode == exit && len(result.Stderr) == 0 && value != nil)
	s.h.Check(name+"_stage0_closed", Get(value, "stage0_passed") == false)
	return value
}
func (s *vmReportSuite) decode(name string, report Object, accepted, bind bool, raw []byte) {
	directory := filepath.Join(s.h.Out, name)
	Must(os.Mkdir(directory, 0700))
	path, job := filepath.Join(directory, "report.json"), filepath.Join(directory, "job.json")
	if raw == nil {
		raw = append(Encoded(report), '\n')
	}
	Write(path, raw)
	WriteJSON(job, vmReportJobValue(report))
	binding := ""
	if bind {
		binding = s.binding
	}
	value := s.invoke(directory, name, Object{"action": "decode", "report": path, "job": job, "binding": binding}, 0)
	expectedError := "REPORT_VALIDATION_FAILED"
	if accepted {
		expectedError = ""
	}
	s.h.Check(name+"_acceptance", Get(value, "accepted") == accepted && Str(value, "error") == expectedError)
	if accepted {
		s.h.Check(name+"_digest_and_counts", Str(value, "report_sha256") == FileDigest(path) && Int(value, "validation", "NormalResultCount") == Int(report, "av", "normal_result_count") && len(List(value, "validation", "ConfirmedRejections")) == len(List(report, "av", "confirmed_detections")))
	}
	s.cases = append(s.cases, Object{"name": name, "kind": "decoder_only", "expected_accepted": accepted, "report_sha256": FileDigest(path), "passed": true})
}
func vmReportSnapshot(h *Harness, directory, label string) Object {
	copy := *h
	copy.Data = filepath.Join(directory, "state")
	value := Object{}
	for _, table := range []string{"jobs", "attempts", "objects", "runtime_runs", "runtime_finalizations", "resource_pins", "scan_queue", "rejection_evidence", "releases"} {
		value[table] = vmRows(&copy, "SELECT * FROM "+table+" ORDER BY rowid")
	}
	entries, err := os.ReadDir(filepath.Join(copy.Data, "objects"))
	Must(err)
	originals := []Object{}
	for _, entry := range entries {
		path := filepath.Join(copy.Data, "objects", entry.Name())
		info, err := entry.Info()
		Must(err)
		originals = append(originals, Object{"name": entry.Name(), "sha256": FileDigest(path), "byte_size": info.Size(), "mode": int(info.Mode().Perm())})
	}
	value["originals"] = originals
	WriteJSON(filepath.Join(directory, label+"-database.json"), value)
	return value
}
func reportRows(value Object, name string) []Object { rows, _ := value[name].([]Object); return rows }
func (s *vmReportSuite) durable(name string, report Object, cancel bool) {
	h := s.h
	directory := filepath.Join(h.Out, name)
	Must(os.Mkdir(directory, 0700))
	path, job := filepath.Join(directory, "report.json"), filepath.Join(directory, "job.json")
	Write(path, append(Encoded(report), '\n'))
	WriteJSON(job, vmReportJobValue(report))
	invalid := vmClone(report)
	Map(List(invalid, "av", "confirmed_detections")[0])["sha256"] = strings.Repeat("0", 64)
	invalidPath := filepath.Join(directory, "invalid-report.json")
	WriteJSON(invalidPath, invalid)
	options := Object{"action": "seed-crash", "report": path, "job": job, "binding": s.binding, "state": filepath.Join(directory, "state"), "input": filepath.Join(s.inputs, "mixed.zip"), "invalid_report": invalidPath, "cancel": cancel}
	response := s.invoke(directory, "commit-then-crash", options, 91)
	before := vmReportSnapshot(h, directory, "after-crash")
	evidence := reportRows(before, "rejection_evidence")
	h.Check(name+"_durable_before_exit", Bool(response, "accepted") && Str(response, "invalid_report_error") == "REPORT_VALIDATION_FAILED" && len(evidence) == 1 && Str(evidence[0], "reason_code") == "MALWARE_DETECTED" && Str(evidence[0], "report_sha256") == FileDigest(path) && Get(evidence[0], "input_sha256") == Get(report, "input", "sha256") && Str(evidence[0], "job_id") == vmReportJob && Str(evidence[0], "attempt_id") == vmReportAttempt && Str(reportRows(before, "jobs")[0], "data", "verdict") == "BLOCK" && Str(reportRows(before, "runtime_runs")[0], "report_sha256") == FileDigest(path))
	options["action"] = "reopen"
	response = s.invoke(directory, "restart-unresolved", options, 0)
	terminal := vmReportSnapshot(h, directory, "after-restart")
	current := Map(reportRows(terminal, "jobs")[0], "data")
	phase := "FAILED"
	if cancel {
		phase = "CANCELLED"
	}
	run := reportRows(terminal, "runtime_runs")[0]
	h.Check(name+"_confirmed_block_survives_stop_failure", Str(current, "verdict") == "BLOCK" && Str(current, "coverage", "av_result") == "detected" && Str(current, "phase") == phase && Get(current, "release", "eligible") == false && Get(current, "runtime_cleanup_complete") == false && Equal(terminal["rejection_evidence"], evidence) && Str(response, "close_error") == "VM_STOP_FAILED" && Str(run, "state") == "STOP_FAILED" && Int(run, "raw_reserved") == 4<<30 && len(reportRows(terminal, "resource_pins")) == 1)
	options["action"] = "settle"
	s.invoke(directory, "synthetic-reservation-settlement", options, 0)
	settled := vmReportSnapshot(h, directory, "after-settlement")
	h.Check(name+"_terminal_attempt_unchanged", Equal(settled["attempts"], terminal["attempts"]) && Equal(settled["rejection_evidence"], evidence))
	run = reportRows(settled, "runtime_runs")[0]
	current = Map(reportRows(settled, "jobs")[0], "data")
	h.Check(name+"_reservation_settled_without_pass", Str(run, "state") == "FINISHED" && Int(run, "raw_reserved") == 0 && Int(run, "raw_written") == 0 && len(reportRows(settled, "resource_pins")) == 0 && len(reportRows(settled, "scan_queue")) == 0 && len(reportRows(settled, "releases")) == 0 && Str(current, "verdict") == "BLOCK" && Bool(current, "runtime_cleanup_complete") && Get(current, "release", "eligible") == false && Equal(settled["originals"], before["originals"]))
	options["action"] = "reopen"
	s.invoke(directory, "restart-settled", options, 0)
	h.Check(name+"_settled_restart_stable", Equal(vmReportSnapshot(h, directory, "final"), settled))
	s.cases = append(s.cases, Object{"name": name, "kind": "synthetic_report_and_isolated_database", "passed": true, "no_vm_launched": true, "state_retained": filepath.Join(directory, "state"), "database_sha256": FileDigest(filepath.Join(directory, "state/state.sqlite"))})
}
func runVMReport(h *Harness) {
	validator, report, main := filepath.Join(h.Root, "internal/broker/av_report.go"), filepath.Join(h.Root, "internal/broker/report.go"), filepath.Join(h.Root, "cmd/filegate/main.go")
	source := ReplaceOnce(string(Read(validator)), "\t\"bytes\"\n", "\t\"bytes\"\n\t\"context\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"time\"\n") + vmReportDriver
	mainSource := ReplaceOnce(string(Read(main)), "\tos.Exit(run(os.Args[1:]))", "\tif len(os.Args)==3 && os.Args[1]==\"report-fixture-driver\" { if err:=broker.RunAVReportFixture(os.Args[2]);err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(2) };return }\n\tos.Exit(run(os.Args[1:]))")
	binary := filepath.Join(h.Out, "filegate-report-fixture")
	BuildOverlay(h, "av-report", binary, map[string]string{validator: source, report: ReplaceOnce(string(Read(report)), "validateAVReport(r, report.AV, expected)", "validateAVReport(r, report.AV, avReportFixtureExpected)"), main: mainSource})
	inputs, binding := vmReportFixtures(h)
	s := &vmReportSuite{h: h, binary: binary, binding: filepath.Join(h.Out, "expected-binding.json"), inputs: inputs}
	makeReport := func(name string, started, detected bool) Object {
		return makeVMReport(inputs, name, binding, started, detected)
	}
	plain, zero, mixed, detected := makeReport("plain.txt", true, false), makeReport("empty.txt", true, false), makeReport("mixed.zip", true, false), makeReport("mixed.zip", true, true)
	s.decode("not-started", makeReport("plain.txt", false, false), true, false, nil)
	s.decode("clean", plain, true, true, nil)
	s.decode("zero-byte-required", zero, true, true, nil)
	s.decode("empty-directory-excluded", mixed, true, true, nil)
	s.decode("detected", detected, true, true, nil)
	for _, test := range []struct {
		status string
		exit   int
		reason string
	}{{"failed", 2, "SCANNER_ERROR"}, {"timed_out", -1, "SCAN_TIMEOUT"}} {
		value := vmClone(detected)
		engine := Map(value, "av")
		engine["process_status"] = test.status
		engine["exit_code"] = test.exit
		engine["results_complete"] = false
		engine["reason_codes"] = []string{test.reason}
		value["av_process_status"] = test.status
		s.decode("detected-"+test.status, value, true, true, nil)
	}
	pending := vmClone(plain)
	engine := Map(pending, "av")
	for key, value := range (Object{"process_status": "failed", "av_result": "inconclusive", "results_complete": false, "binding_verified": false, "normal_result_count": 0, "exit_code": nil, "stdout_bytes": 0, "stdout_sha256": "", "stderr_sha256": "", "reason_codes": []string{"INCOMPLETE_REQUIRED_CHECKS", "SCANNER_ERROR"}}) {
		engine[key] = value
	}
	obj := Map(List(pending, "av", "objects")[0])
	obj["status"] = "pending"
	obj["reason_code"] = "INCOMPLETE_REQUIRED_CHECKS"
	obj["input_verified"] = false
	obj["normal_result_present"] = false
	pending["av_process_status"] = "failed"
	pending["av_result"] = "inconclusive"
	s.decode("pre-exec-failed", pending, true, true, nil)
	hold := vmClone(detected)
	engine = Map(hold, "av")
	engine["av_result"] = "inconclusive"
	engine["results_complete"] = false
	engine["reason_codes"] = []string{"LIMIT_EXCEEDED"}
	engine["confirmed_detections"] = []Object{}
	obj = Map(List(hold, "av", "objects")[len(List(hold, "av", "objects"))-1])
	obj["status"] = "hold"
	obj["reason_code"] = "LIMIT_EXCEEDED"
	hold["av_result"] = "inconclusive"
	s.decode("heuristic-hold", hold, true, true, nil)
	s.decode("started-without-host-binding", plain, false, false, nil)
	mutations := []struct {
		name   string
		source Object
		mutate func(Object)
	}{
		{"old-report-version", plain, func(v Object) { v["schema_version"] = 1 }}, {"wrong-job", plain, func(v Object) { v["job_id"] = "job_" + strings.Repeat("d", 32) }}, {"missing-av-field", plain, func(v Object) { delete(Map(v, "av"), "results_complete") }}, {"null-av-boolean", plain, func(v Object) { Map(v, "av")["binding_verified"] = nil }}, {"null-objects", plain, func(v Object) { Map(v, "av")["objects"] = nil }}, {"missing-binding-field", plain, func(v Object) { delete(Map(v, "av", "binding"), "fixture_definitions_only") }}, {"null-binding-field", plain, func(v Object) { Map(v, "av", "binding")["observation_sha256"] = nil }}, {"binding-mismatch", plain, func(v Object) { Map(v, "av", "binding")["profile_sha256"] = strings.Repeat("0", 64) }},
		{"missing-object-field", plain, func(v Object) { delete(Map(List(v, "av", "objects")[0]), "input_verified") }}, {"null-object-field", plain, func(v Object) { Map(List(v, "av", "objects")[0])["byte_size"] = nil }}, {"object-id-mismatch", plain, func(v Object) { Map(List(v, "av", "objects")[0])["object_id"] = "object_000009" }}, {"object-hash-mismatch", plain, func(v Object) { Map(List(v, "av", "objects")[0])["sha256"] = strings.Repeat("0", 64) }}, {"object-size-mismatch", plain, func(v Object) { Map(List(v, "av", "objects")[0])["byte_size"] = 1 }}, {"normal-count-mismatch", plain, func(v Object) { Map(v, "av")["normal_result_count"] = 0 }}, {"required-count-mismatch", plain, func(v Object) { Map(v, "av")["required_input_count"] = 2 }}, {"duplicate-object", mixed, func(v Object) { List(v, "av", "objects")[1] = vmClone(Map(List(v, "av", "objects")[0])) }}, {"empty-file-omitted", mixed, func(v Object) {
			rows := List(v, "av", "objects")
			Map(v, "av")["objects"] = append(rows[:1], rows[2:]...)
		}}, {"empty-directory-included", mixed, func(v Object) { Map(List(v, "av", "objects")[1])["object_id"] = "object_000004" }},
		{"clean-with-exit-one", plain, func(v Object) { Map(v, "av")["exit_code"] = 1 }}, {"detected-with-exit-zero", detected, func(v Object) { Map(v, "av")["exit_code"] = 0 }}, {"completed-with-exit-two", plain, func(v Object) { Map(v, "av")["exit_code"] = 2 }}, {"incorrect-completion", plain, func(v Object) { Map(v, "av")["results_complete"] = false }}, {"missing-detection", detected, func(v Object) { Map(v, "av")["confirmed_detections"] = []Object{} }}, {"detection-hash-mismatch", detected, func(v Object) { Map(List(v, "av", "confirmed_detections")[0])["sha256"] = strings.Repeat("0", 64) }}, {"missing-detection-field", detected, func(v Object) { delete(Map(List(v, "av", "confirmed_detections")[0]), "signature_sha256") }}, {"null-detection-field", detected, func(v Object) { Map(List(v, "av", "confirmed_detections")[0])["byte_size"] = nil }}, {"extra-reason", plain, func(v Object) { Map(v, "av")["reason_codes"] = []string{"SCANNER_ERROR"} }}, {"stdout-overflow-completed", plain, func(v Object) { Map(v, "av")["stdout_bytes"] = (4 << 20) + 1 }}, {"empty-stream-hash-mismatch", plain, func(v Object) { Map(v, "av")["stderr_sha256"] = strings.Repeat("0", 64) }}, {"not-started-with-binding", makeReport("plain.txt", false, false), func(v Object) { Map(v, "av")["binding"] = vmClone(Map(plain, "av", "binding")) }},
	}
	for _, test := range mutations {
		value := vmClone(test.source)
		test.mutate(value)
		s.decode(test.name, value, false, true, nil)
	}
	raw := append(Encoded(plain), '\n')
	s.decode("duplicate-json-field", plain, false, true, bytes.Replace(raw, []byte(`"schema_version":2`), []byte(`"schema_version":2,"schema_version":2`), 1))
	s.decode("truncated-json", plain, false, true, raw[:len(raw)-7])
	s.durable("durable-block-stop-failure", detected, false)
	s.durable("durable-block-cancel", detected, true)
	h.Record["cases"] = s.cases
	h.Record["scope"] = "synthetic report decoder and isolated durable database; no VM or scanner executed"
	h.Record["product_profile_adopted"] = false
	h.Check("exact_report_case_count", len(s.cases) == 44)
}
