package verification

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filegate.local/filegate/internal/buildtools"
	"filegate.local/filegate/internal/hostvm"
)

func init() {
	Register("vm", runVM)
	Register("documents", runVMDocuments)
	Register("url", runVMURL)
	Register("product-av-vm", runProductAVVM)
}
func runVM(h *Harness) {
	s := newVMSuite(h)
	defer s.finish()
	vmRunnerObserver(h)
	root := vmCorpus(h)
	text := vmCorpusCases(h, root, "text_cases", []string{"ascii"})[0]
	archive := vmCorpusCases(h, root, "cases", []string{"parent_path"})[0]
	h.Check("existing_fixture_expectations", Str(text, "expected", "text_validation") == "ACCEPT_TXT_STRUCTURE" && Str(archive, "expected", "zip_validation") == "BLOCK" && Str(archive, "expected", "reason") == "UNSAFE_ARCHIVE_PATH")
	h.Check("gates_closed", GatesClosed(s.start()))
	var blocked Object
	var blockedDB Object
	for _, test := range []struct {
		name, verdict string
		code          int
		input         Object
	}{{"normal-txt", "HOLD", 10, text}, {"unsafe-zip", "BLOCK", 20, archive}} {
		fmt.Println(string(Encoded(Object{"event": "STARTING_CASE", "case": test.name})))
		receipt, directory := s.submit(test.input, test.name)
		code, job := vmWaitCLI(h, Str(receipt, "job_id"))
		h.Check(test.name+"_terminal", code == test.code && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == test.verdict)
		vmAssertRunnerExit(h, job)
		db := s.persist(test.name, receipt, job, directory, true)
		if test.verdict == "BLOCK" {
			blocked = job
			blockedDB = db
		}
	}
	h.Stop(false)
	s.start()
	status, reopened := h.Request("GET", "/v1/jobs/"+Str(blocked, "job_id"), nil, nil, nil)
	h.Check("block_survives_restart", status == 200 && Str(reopened, "verdict") == "BLOCK" && Equal(s.database(reopened)["rejection_evidence"], blockedDB["rejection_evidence"]))
	receipt, directory := s.submit(text, "broker-death")
	started := vmWaitFile(h, filepath.Join(directory, "output/vm-started.json"), 90*time.Second)
	roles := map[string]bool{}
	identities := List(started, "processes")
	valid := len(identities) == 3
	for _, row := range identities {
		role := Str(row, "role")
		valid = valid && !roles[role] && Int(row, "pid") > 1 && Int(row, "start_abstime") > 0
		roles[role] = true
	}
	h.Check("kill_bound_to_live_attempt", Get(started, "job_id") == Get(receipt, "job_id") && Get(started, "attempt_id") == Get(receipt, "job", "attempt_id") && valid && roles["guardian"] && roles["vm"] && roles["helper"])
	children := Execute(h.Root, []string{"/usr/bin/pgrep", "-P", strconv.Itoa(h.Process.Process.Pid)}, nil, 5*time.Second)
	pids := strings.Fields(string(children.Stdout))
	h.Check("single_direct_runner", children.ExitCode == 0 && len(pids) == 1)
	pid, err := strconv.Atoi(pids[0])
	Must(err)
	identity, err := hostvm.NativeIdentity(pid)
	Must(err)
	h.Check("runner_start_identity", identity != nil && Int(identity, "start_abstime") > 0 && Int(identity, "exit_abstime") == 0)
	s.runner = Object{"pid": pid, "start_abstime": identity["start_abstime"]}
	h.Stop(true)
	s.stopped(directory)
	end := time.Now().Add(15 * time.Second)
	for time.Now().Before(end) && hostvm.IdentityReadback(s.runner)["same_identity_live"] != false {
		time.Sleep(50 * time.Millisecond)
	}
	h.Check("orphan_runner_exited", hostvm.IdentityReadback(s.runner)["same_identity_live"] == false)
	s.start()
	job := vmWaitJob(h, Str(receipt, "job_id"), 45*time.Second)
	h.Check("broker_death_recovers_hold", Str(job, "phase") == "FAILED" && Str(job, "verdict") == "HOLD" && Contains(Get(job, "execution_errors"), "INTERRUPTED"))
	s.persist("broker-death", receipt, job, directory, false)
}
func runVMDocuments(h *Harness) {
	s := newVMSuite(h)
	defer s.finish()
	root := vmCorpus(h)
	cases := vmCorpusCases(h, root, "ooxml", []string{"docx_plain", "xlsx_values", "docx_field_simple_ddeauto", "xlsx_formula_image", "docx_content_type_mismatch"})
	h.Check("gates_closed", GatesClosed(s.start()))
	for _, test := range cases {
		name := Str(test, "id")
		receipt, directory := s.submit(test, name)
		code, job := vmWaitCLI(h, Str(receipt, "job_id"))
		h.Check(name+"_terminal_hold", code == 10 && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "HOLD" && len(List(job, "execution_errors")) == 0 && Get(job, "release", "eligible") == false)
		db := s.persist(name, receipt, job, directory, true)
		report := ReadJSON(filepath.Join(directory, "output/report.json"))
		expected := Map(test, "expected")
		reason := Str(expected, "reason")
		reasons := []string{}
		if reason != "" {
			reasons = append(reasons, reason)
		}
		h.Check(name+"_profile_result", Get(report, "result", "structure_status") == Get(expected, "product_validation") && Equal(Get(report, "result", "reason_codes"), reasons) && len(db["rejection_evidence"].([]Object)) == 0)
		if Str(expected, "product_validation") == "ACCEPT_FORMAT_STRUCTURE" {
			manifest := List(report, "result", "manifest")
			valid := Bool(report, "manifest_complete") && len(manifest) > 0 && Str(manifest[0], "format") == Str(test, "kind") && Str(manifest[0], "kind") == "container"
			formats := []string{}
			for i, item := range manifest {
				formats = append(formats, Str(item, "format"))
				if i > 0 {
					valid = valid && Str(item, "format") == "ooxml-part" && Str(item, "parent_id") == Str(manifest[0], "object_id") && Bool(item, "av_required")
				}
			}
			for _, check := range List(expected, "completed_checks") {
				valid = valid && Contains(Get(report, "result", "completed_checks"), check)
			}
			h.Check(name+"_complete_ooxml_manifest", valid && Int(report, "result", "required_av_input_count") == int64(len(manifest)) && Int(report, "result", "archive_entry_count") == Int(expected, "archive_entry_count") && Int(report, "result", "required_av_input_count") == Int(expected, "required_av_input_count") && Equal(formats, Get(expected, "manifest_formats")))
		} else {
			h.Check(name+"_reason_persists", Get(report, "manifest_complete") == false && Contains(Get(job, "reason_codes"), reason))
		}
	}
	h.Stop(false)
	s.start()
	for _, test := range s.cases {
		status, job := h.Request("GET", "/v1/jobs/"+Str(test, "job_id"), nil, nil, nil)
		saved := ReadJSON(filepath.Join(h.Out, Str(test, "name"), "state.json"))
		h.Check(Str(test, "name")+"_restart_preserves_hold", status == 200 && Str(job, "verdict") == "HOLD" && Equal(job, Get(saved, "job")))
	}
}
func runVMURL(h *Harness) {
	info, stopNetwork := StartNetworkFixture(h)
	defer func() {
		stopNetwork()
		h.Check("url_fixture_exact_counts", Equal(h.Record["tls_fixture_counts"], Object{"/ok": 1, "/hash": 1, "/broken": 1, "/status": 1}))
	}()
	binary := filepath.Join(h.Out, "filegate-url")
	source := filepath.Join(h.Root, "internal/acquire/network.go")
	BuildOverlay(h, "url-network", binary, map[string]string{source: NetworkFactory(info)})
	h.Binary = binary
	var suite *vmSuite
	if !h.IntakeOnly {
		suite = newVMSuite(h)
		defer suite.finish()
		h.Check("gates_closed", GatesClosed(suite.start()))
	} else {
		h.Check("gates_closed", GatesClosed(h.Start()))
	}
	defer h.Stop(false)
	submit := func(path, expected string) (int, Object) {
		url := "https://example.com/" + path + "?synthetic=PRIVATE_URL_QUERY_MARKER"
		return h.CLIInput([]byte(url+"\n"), "submit", "url", "--url-stdin", "--idempotency-key", "url-"+path, "--expected-type", "txt", "--expected-sha256", expected)
	}
	code, first := submit("ok", Str(info, "sha256"))
	h.Check("url_initial_receipt", code == 0 && Str(first, "job_id") != "" && Get(first, "replayed") == false)
	var job Object
	if h.IntakeOnly {
		job = vmWaitJob(h, Str(first, "job_id"), 30*time.Second)
	} else {
		code, job = vmWaitCLI(h, Str(first, "job_id"))
		h.Check("url_vm_hold", code == 10)
	}
	h.Check("url_complete_holds", Str(job, "verdict") == "HOLD" && Str(job, "intake_status") == "COMMITTED" && Get(job, "release", "eligible") == false)
	receipt := Map(job, "input_receipt")
	original := Read(filepath.Join(h.Data, "objects", Str(receipt, "object_id")))
	h.Check("url_original_binding", Str(receipt, "sha256") == Str(info, "sha256") && Int(receipt, "byte_size") == Int(info, "byte_size") && string(original) == Str(info, "body"))
	code, replay := submit("ok", Str(info, "sha256"))
	h.Check("url_replay_does_not_refetch", code == 0 && Bool(replay, "replayed") && Get(replay, "current_input_checked") == false && Get(replay, "job_id") == Get(first, "job_id") && Equal(Get(replay, "input_receipt"), receipt))
	if suite != nil {
		directory := filepath.Join(h.Data, "runtime", Str(job, "attempt_id"))
		suite.directories = append(suite.directories, directory)
		suite.persist("url-txt", replay, job, directory, true)
	}
	for _, test := range []struct{ path, expected, reason string }{{"hash", strings.Repeat("0", 64), "INPUT_HASH_MISMATCH"}, {"broken", Str(info, "sha256"), "DOWNLOAD_INCOMPLETE"}, {"status", Str(info, "sha256"), "DOWNLOAD_HTTP_STATUS"}} {
		code, submitted := submit(test.path, test.expected)
		h.Check(test.path+"_accepted_for_acquisition", code == 0)
		failed := vmWaitJob(h, Str(submitted, "job_id"), 30*time.Second)
		h.Check(test.path+"_failed_without_original", Str(failed, "phase") == "FAILED" && Str(failed, "verdict") == "HOLD" && Get(failed, "input_receipt") == nil && Contains(Get(failed, "execution_errors"), test.reason) && Bool(failed, "runtime_cleanup_complete") && Get(failed, "release", "eligible") == false)
	}
	metadata := vmRows(h, "SELECT data FROM intake_metadata WHERE job_id=?", Str(first, "job_id"))
	h.Check("response_mime_persisted", len(metadata) == 1 && Str(metadata[0], "data", "declared_media_type") == "text/plain")
	partials, err := os.ReadDir(filepath.Join(h.Data, "partial"))
	Must(err)
	objects, err := os.ReadDir(filepath.Join(h.Data, "objects"))
	Must(err)
	h.Check("only_success_commits_original", vmScalar(h, "SELECT count(*) FROM reservations") == 0 && len(partials) == 0 && len(objects) == 1)
	h.Stop(false)
	if suite != nil {
		suite.start()
	} else {
		h.Start()
	}
	code, replay = submit("ok", Str(info, "sha256"))
	h.Check("url_replay_survives_restart", code == 0 && Bool(replay, "replayed") && Get(replay, "job_id") == Get(first, "job_id") && Equal(Get(replay, "input_receipt"), receipt) && Str(replay, "job", "verdict") == "HOLD")
	h.Stop(false)
	leaked := bytes.Contains(Read(filepath.Join(h.Data, "state.sqlite")), []byte("PRIVATE_URL_QUERY_MARKER"))
	for _, body := range append(h.Logs, h.Responses...) {
		leaked = leaked || bytes.Contains(body, []byte("PRIVATE_URL_QUERY_MARKER"))
	}
	h.Check("url_query_not_persisted_or_logged", !leaked)
	h.Record["expected_fixture_counts"] = Object{"/ok": 1, "/hash": 1, "/broken": 1, "/status": 1}
}
func runProductAVVM(h *Harness) {
	s := newVMSuite(h)
	build := ReadJSON(filepath.Join(h.Workspace, "experiments/vm/evidence/build.json"))
	h.Check("fixture_profile_adoption_disabled", Get(build, "normal_product_profile_installed") == false && Get(build, "official_definitions_adopted") == false)
	observation := Str(build, "av_fixture", "observation_path")
	h.Check("fixture_observation_binding", observation != "" && FileDigest(observation) == Str(build, "av_fixture", "observation_sha256"))
	inputs := filepath.Join(h.Out, "inputs")
	generated, err := buildtools.GenerateAVFixtures(h.Workspace, inputs, observation)
	Must(err)
	h.Check("installed_fixture_inputs_exact", Equal(generated["files_sha256"], Get(build, "av_fixture", "files_sha256")))
	Write(filepath.Join(h.Out, "observation-matrix.json"), Read(observation))
	expectedCases := List(ReadJSON(filepath.Join(inputs, "product-fixtures/manifest.json")), "cases")
	out := filepath.Join(h.Out, "runtime")
	result := Execute(h.Workspace, []string{h.Runner, "--fixture", "product-av-normalization", "--out", out, "--proof", h.Proof}, nil, 330*time.Second)
	h.Record["runtime_exit_code"] = result.ExitCode
	runtime := ReadJSON(filepath.Join(out, "results.json"))
	h.Check("protected_runtime_and_cleanup", result.ExitCode == 0 && Bool(runtime, "passed") && Bool(runtime, "raw_reclaimed") && Bool(runtime, "vm_slot_finalized") && Int(runtime, "reservation_charge_bytes") == 0 && Get(runtime, "product_enabled") == false && Get(runtime, "stage0_gate_passed") == false)
	exchange := ReadJSON(filepath.Join(out, "exchange.json"))
	events := []Object{}
	for _, event := range List(exchange, "events") {
		if Str(event, "event") == "product_av_result" {
			events = append(events, Map(event))
		}
	}
	h.Check("single_fixture_report", len(events) == 1)
	cases := List(events[0], "cases")
	actualExpected := []any{}
	for _, test := range cases {
		actualExpected = append(actualExpected, Get(test, "expected"))
	}
	h.Check("exact_four_case_set", len(cases) == 4 && Equal(actualExpected, expectedCases))
	for _, test := range cases {
		expected, actual := Map(test, "expected"), Map(test, "actual")
		engine, form := Map(actual, "av"), Map(actual, "result")
		name := Str(expected, "id")
		h.Check(name+"_result", Bool(test, "passed") && Int(actual, "schema_version") == 1 && Str(engine, "process_status") == "completed" && Bool(engine, "results_complete") && Bool(engine, "binding_verified") && Get(engine, "av_result") == Get(expected, "expected_av_result") && len(List(engine, "reason_codes")) == 0 && Int(engine, "required_input_count") == Int(expected, "expected_required_count") && Int(engine, "normal_result_count") == Int(expected, "expected_required_count") && int64(len(List(engine, "confirmed_detections"))) == Int(expected, "expected_detected_count"))
		required, normal := map[string]bool{}, map[string]bool{}
		key := func(item any) string {
			return string(Encoded([]any{Get(item, "object_id"), Get(item, "sha256"), Get(item, "byte_size")}))
		}
		for _, item := range List(form, "manifest") {
			if Bool(item, "av_required") {
				required[key(item)] = true
			}
		}
		for _, item := range List(engine, "objects") {
			if Bool(item, "input_verified") && Bool(item, "normal_result_present") {
				normal[key(item)] = true
			}
		}
		h.Check(name+"_object_set", Equal(required, normal) && len(normal) == len(List(engine, "objects")))
		manifest := List(form, "manifest")
		h.Check(name+"_binding", Bool(engine, "binding", "fixture_definitions_only") && Str(engine, "binding", "profile_sha256") == FileDigest(filepath.Join(inputs, "product-profile-fixture.json")) && Str(engine, "binding", "observation_sha256") == Str(build, "av_fixture", "observation_sha256") && len(manifest) > 0 && Str(manifest[0], "sha256") == Str(expected, "sha256") && Get(form, "required_checks_complete") == false)
	}
	native := ReadJSON(filepath.Join(out, "watchdog/results.json"))
	state, err := hostvm.New(h.Workspace)
	Must(err)
	kind, err := state.NativeChecks(native)
	Must(err)
	preparation := ReadJSON(filepath.Join(out, "preparation-intent.json"))
	h.Check("fixture_cleanup_independent_readback", kind == "native_guardian" && Get(native, "emergency_owned_cleanup") != true && !Exists(Str(preparation, "run_directory")) && !Exists(Str(native, "control_directory")) && !Exists(filepath.Join(state.State, "active-vm.json")))
	h.Record["fixture_definitions_only"] = true
	h.Record["official_definitions_adopted"] = false
	h.Record["runtime_sha256"] = FileDigest(filepath.Join(out, "results.json"))
	h.Record["all_runtime_cleanup_confirmed"] = true
	s.directories = nil
}
