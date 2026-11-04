package verification

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filegate.local/filegate/internal/fixtures"
	"filegate.local/filegate/internal/hostvm"
)

type vmSuite struct {
	h           *Harness
	directories []string
	cases       []Object
	runner      Object
}

func newVMSuite(h *Harness) *vmSuite {
	for _, entry := range []struct {
		path  *string
		alias string
	}{{&h.Runner, "vm-runner"}, {&h.Workspace, "vm-workspace"}, {&h.Proof, "vm-proof"}} {
		if *entry.path == "" {
			*entry.path = h.Paths[entry.alias]
		}
		h.Check("required_"+entry.alias, *entry.path != "")
		canonical, err := filepath.EvalSymlinks(*entry.path)
		Must(err)
		*entry.path = canonical
	}
	h.Check("go_runner_fixed_workspace_path", h.Runner == filepath.Join(h.Workspace, ".build/filegate-vm"))
	if h.StopTimeout == 0 {
		h.StopTimeout = 30 * time.Second
	}
	runtime, err := hostvm.New(h.Workspace)
	Must(err)
	h.Check("shared_runtime_slot_initially_empty", !Exists(filepath.Join(runtime.State, "active-vm.json")))
	h.Record["vm_runner_sha256"] = FileDigest(h.Runner)
	h.Record["native_proof_sha256"] = FileDigest(h.Proof)
	h.Record["vm_build_sha256"] = FileDigest(filepath.Join(h.Workspace, "experiments/vm/evidence/build.json"))
	Write(filepath.Join(h.Out, "vm-build.json"), Read(filepath.Join(h.Workspace, "experiments/vm/evidence/build.json")))
	return &vmSuite{h: h}
}
func (s *vmSuite) start() Object {
	return s.h.Start("--vm-runner", s.h.Runner, "--vm-workspace", s.h.Workspace, "--vm-proof", s.h.Proof)
}
func vmWaitFile(h *Harness, path string, timeout time.Duration) Object {
	end := time.Now().Add(timeout)
	next := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		if Exists(path) {
			var value Object
			body, err := os.ReadFile(path)
			if err == nil && json.Unmarshal(body, &value) == nil && value != nil {
				return Decode(body)
			}
		}
		if !time.Now().Before(next) {
			fmt.Println(string(Encoded(Object{"event": "WAITING_FOR_RUNTIME", "artifact": filepath.Base(path)})))
			next = time.Now().Add(10 * time.Second)
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.Check("runtime_artifact_timeout_"+filepath.Base(path), false)
	return nil
}
func vmWaitJob(h *Harness, id string, timeout time.Duration) Object {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		status, job := h.Request("GET", "/v1/jobs/"+id, nil, nil, nil)
		h.Check("job_poll_"+id, status == 200)
		phase := Str(job, "phase")
		if phase == "FINISHED" || phase == "FAILED" || phase == "CANCELLED" {
			return job
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.Check("runtime_job_timeout", false)
	return nil
}
func vmWaitCLI(h *Harness, id string) (int, Object) {
	args := []string{h.Binary, "--data-dir", h.Data, "wait", id, "--require-pass", "--timeout", "330"}
	result := Execute(h.Root, args, nil, 345*time.Second)
	h.Responses = append(h.Responses, result.Stdout, result.Stderr)
	h.Commands = append(h.Commands, Object{"operation": "wait", "exit_code": result.ExitCode})
	h.Check("wait_response", len(result.Stderr) == 0 && len(result.Stdout) > 0)
	return result.ExitCode, Decode(result.Stdout)
}
func vmRows(h *Harness, query string, args ...any) []Object {
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(h.Data, "state.sqlite")+"?mode=ro")
	Must(err)
	defer db.Close()
	rows, err := db.Query(query, args...)
	Must(err)
	defer rows.Close()
	columns, err := rows.Columns()
	Must(err)
	result := []Object{}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		Must(rows.Scan(pointers...))
		value := Object{}
		for i, name := range columns {
			item := values[i]
			if raw, ok := item.([]byte); ok {
				if name == "data" {
					item = Decode(raw)
				} else {
					item = string(raw)
				}
			}
			if raw, ok := item.(string); ok && name == "data" {
				item = Decode([]byte(raw))
			}
			value[name] = item
		}
		result = append(result, value)
	}
	Must(rows.Err())
	return result
}
func vmScalar(h *Harness, query string, args ...any) int64 {
	rows := h.Query(query, args...)
	h.Check("scalar_query", len(rows) == 1 && len(rows[0]) == 1)
	return Int(Object{"value": rows[0][0]}, "value")
}
func (s *vmSuite) database(job Object) Object {
	h := s.h
	attempt := vmRows(h, "SELECT * FROM attempts WHERE id=?", Str(job, "attempt_id"))
	runtime := vmRows(h, "SELECT * FROM runtime_runs WHERE attempt_id=?", Str(job, "attempt_id"))
	h.Check("attempt_runtime_rows", len(attempt) == 1 && len(runtime) == 1)
	return Object{"attempt": attempt[0], "runtime": runtime[0], "rejection_evidence": vmRows(h, "SELECT * FROM rejection_evidence WHERE attempt_id=?", Str(job, "attempt_id")), "remaining_pins": vmScalar(h, "SELECT count(*) FROM resource_pins WHERE owner_id=?", Str(job, "attempt_id")), "remaining_queue": vmScalar(h, "SELECT count(*) FROM scan_queue WHERE job_id=?", Str(job, "job_id"))}
}
func (s *vmSuite) submit(test Object, key string) (Object, string) {
	h := s.h
	name := Str(test, "name")
	code, receipt := vmSubmit(h, filepath.Join(h.InputDirectory, name), Object{"idempotency_key": key, "expected_type": Str(test, "kind"), "expected_sha256": Str(test, "sha256")})
	h.Check(key+"_intake", code == 0 && Str(receipt, "intake_status") == "COMMITTED" && Str(receipt, "input_receipt", "sha256") == Str(test, "sha256") && Int(receipt, "input_receipt", "byte_size") == Int(test, "bytes"))
	directory := filepath.Join(h.Data, "runtime", Str(receipt, "job", "attempt_id"))
	s.directories = append(s.directories, directory)
	return receipt, directory
}
func vmSubmit(h *Harness, source string, metadata Object) (int, Object) {
	file, err := os.CreateTemp(h.Out, "vm-metadata-")
	Must(err)
	defer os.Remove(file.Name())
	defer file.Close()
	value := Object{"source": source}
	for k, v := range metadata {
		value[k] = v
	}
	_, err = file.Write(Encoded(value))
	Must(err)
	_, err = file.Seek(0, 0)
	Must(err)
	result := Execute(h.Root, []string{h.Binary, "--data-dir", h.Data, "submit", "file", "--metadata-fd", "3"}, nil, 125*time.Second, file)
	h.Responses = append(h.Responses, result.Stdout, result.Stderr)
	h.Commands = append(h.Commands, Object{"operation": "submit-file", "exit_code": result.ExitCode})
	return result.ExitCode, Decode(result.Stdout)
}
func vmIdentityKey(identity Object) string {
	return string(Encoded([]any{Get(identity, "pid"), Get(identity, "start_abstime")}))
}
func (s *vmSuite) stopped(directory string) (Object, Object) {
	h := s.h
	out := filepath.Join(directory, "output")
	path := filepath.Join(out, "results.json")
	if Exists(filepath.Join(out, "recovery-results.json")) {
		path = filepath.Join(out, "recovery-results.json")
	}
	summary := vmWaitFile(h, path, 45*time.Second)
	native := vmWaitFile(h, filepath.Join(out, "watchdog/results.json"), 5*time.Second)
	request := ReadJSON(filepath.Join(directory, "request.json"))
	terminal := Map(native, "terminal")
	h.Check(filepath.Base(directory)+"_native_stop", Bool(terminal, "all_exited") && Bool(native, "guardian_result_verified") && Bool(native, "cleanup_all_exited") && Bool(native, "temporary_service_absent") && Get(native, "emergency_owned_cleanup") != true)
	started := ReadJSON(filepath.Join(out, "vm-started.json"))
	exited := map[string]bool{}
	for _, row := range List(native, "cleanup_after") {
		id := Map(row, "identity")
		if Get(row, "same_identity_live") == false && hostvm.IdentityReadback(id)["same_identity_live"] == false {
			exited[vmIdentityKey(id)] = true
		}
	}
	identities := List(started, "processes")
	same := len(identities) == 3
	for _, row := range identities {
		same = same && exited[vmIdentityKey(Map(row))]
	}
	h.Check(filepath.Base(directory)+"_same_processes_exited", same)
	preparation := ReadJSON(filepath.Join(out, "preparation-intent.json"))
	h.Check(filepath.Base(directory)+"_raw_and_slot_reclaimed", Bool(summary, "raw_reclaimed") && Bool(summary, "vm_slot_finalized") && Int(summary, "reservation_charge_bytes") == 0 && Get(summary, "job_id") == Get(request, "job_id") && Get(summary, "attempt_id") == Get(request, "attempt_id") && Str(summary, "native_evidence", "sha256") == FileDigest(filepath.Join(out, "watchdog/results.json")) && !Exists(filepath.Join(Str(preparation, "run_directory"), "work.raw")))
	return summary, native
}
func (s *vmSuite) persist(name string, receipt, job Object, directory string, reportRequired bool) Object {
	h := s.h
	summary, _ := s.stopped(directory)
	database := s.database(job)
	request := ReadJSON(filepath.Join(directory, "request.json"))
	original := filepath.Join(h.Data, "objects", Str(receipt, "input_receipt", "object_id"))
	stat, err := os.Stat(original)
	Must(err)
	h.Check(name+"_input_binding", Get(request, "job_id") == Get(job, "job_id") && Get(request, "attempt_id") == Get(job, "attempt_id") && Str(request, "expected_sha256") == Str(receipt, "input_receipt", "sha256") && Int(request, "byte_size") == Int(receipt, "input_receipt", "byte_size") && FileDigest(original) == Str(receipt, "input_receipt", "sha256") && stat.Size() == Int(receipt, "input_receipt", "byte_size"))
	h.Check(name+"_cleanup_accounting", Bool(job, "runtime_cleanup_complete") && Int(database, "runtime", "raw_reserved") == 0 && Int(database, "remaining_pins") == 0 && Int(database, "remaining_queue") == 0)
	h.Check(name+"_durable_attempt", Get(database, "attempt", "data", "verdict") == Get(job, "verdict") && Get(database, "attempt", "data", "phase") == Get(job, "phase") && Get(job, "release", "eligible") == false)
	reportPath := filepath.Join(directory, "output/report.json")
	if reportRequired {
		report := ReadJSON(reportPath)
		h.Check(name+"_report_binding", Get(report, "job_id") == Get(job, "job_id") && Get(report, "attempt_id") == Get(job, "attempt_id") && Equal(Get(report, "input"), Object{"sha256": Get(receipt, "input_receipt", "sha256"), "byte_size": Get(receipt, "input_receipt", "byte_size")}) && Int(report, "worker_uid") == 65534 && Int(report, "schema_version") == 2 && Str(report, "policy_digest") == "filegate-product-scan-v4" && Bool(report, "report_complete") && Bool(summary, "report_accepted") && Str(summary, "report_sha256") == FileDigest(reportPath) && Get(report, "result", "required_checks_complete") == false)
		if Int(request, "schema_version") == 2 {
			h.Check(name+"_format_only_av_incomplete", Str(report, "av_process_status") == "not_started" && Str(report, "av_result") == "inconclusive" && Get(report, "av", "binding") == nil && Int(report, "av", "normal_result_count") == 0 && len(List(report, "av", "objects")) == 0 && len(List(report, "av", "confirmed_detections")) == 0 && Equal(Get(report, "av", "reason_codes"), []string{"INCOMPLETE_REQUIRED_CHECKS"}))
		}
		if Str(job, "verdict") == "BLOCK" {
			evidence := database["rejection_evidence"].([]Object)
			h.Check(name+"_validated_rejection", Str(report, "result", "structure_status") == "BLOCK" && Equal(Get(report, "result", "reason_codes"), []string{"UNSAFE_ARCHIVE_PATH"}) && len(List(report, "result", "confirmed_rejections")) == 1 && len(evidence) == 1 && Str(evidence[0], "report_sha256") == FileDigest(reportPath) && Str(evidence[0], "input_sha256") == Str(receipt, "input_receipt", "sha256") && Str(evidence[0], "job_id") == Str(job, "job_id") && Str(evidence[0], "reason_code") == "UNSAFE_ARCHIVE_PATH")
		}
	}
	files := []string{"request.json", "output/results.json", "output/vm-started.json", "output/preparation-intent.json", "output/raw-cleanup.json", "output/watchdog/results.json", "output/watchdog/config.json", "output/watchdog/events.jsonl", "output/watchdog/guardian-result.json", "output/watchdog/producer-source.json", "output/prepared.json"}
	if Get(summary, "recovery_evidence") != nil {
		for _, file := range []string{"cleanup-complete.json", "cleanup-intent.json", "stop-proof.json", "slot-owner.json", "preparation-owner.json", "prepared-identity.json"} {
			files = append(files, "output/"+file)
		}
	}
	if reportRequired || Exists(reportPath) {
		files = append(files, "output/report.json")
	}
	if Exists(filepath.Join(directory, "output/exchange.json")) {
		files = append(files, "output/exchange.json")
	}
	copied := Object{}
	for _, file := range files {
		if !Exists(filepath.Join(directory, file)) {
			h.Check(name+"_artifact_"+file, false)
		}
		destination := filepath.Join(h.Out, name, file)
		Write(destination, Read(filepath.Join(directory, file)))
		copied[file] = FileDigest(destination)
	}
	WriteJSON(filepath.Join(h.Out, name, "state.json"), Object{"intake": receipt, "job": job, "database": database})
	s.cases = append(s.cases, Object{"name": name, "job_id": job["job_id"], "attempt_id": job["attempt_id"], "verdict": job["verdict"], "artifacts_sha256": copied})
	h.Record["cases"] = s.cases
	return database
}
func (s *vmSuite) finish() {
	h := s.h
	h.Stop(false)
	if s.runner != nil {
		h.Check("runner_exited", hostvm.IdentityReadback(s.runner)["same_identity_live"] == false)
	}
	for _, directory := range s.directories {
		s.stopped(directory)
	}
	h.Record["all_runtime_cleanup_confirmed"] = true
	h.Check("runtime_cleanup_complete", true)
}
func vmCorpus(h *Harness) string {
	archive := filepath.Join(h.Workspace, "experiments/vm/.build/contracts-fixtures.tar.gz")
	if h.Workspace == "" {
		archive = h.Paths["source"]
	}
	h.Check("fixture_corpus_available", archive != "" && Exists(archive))
	destination := filepath.Join(h.Out, "corpus")
	manifest := filepath.Join(h.Root, "experiments/contracts/corpus-v1.json")
	_, err := fixtures.ExtractCorpus(archive, manifest, destination, false)
	Must(err)
	h.Record["corpus_sha256"] = FileDigest(archive)
	h.Record["corpus_manifest_sha256"] = FileDigest(manifest)
	return destination
}
func vmCorpusCases(h *Harness, root, collection string, names []string) []Object {
	manifest := "fixture-manifest.json"
	if collection == "ooxml" {
		manifest = "ooxml-manifest.json"
	}
	value := ReadJSON(filepath.Join(root, manifest))
	rows := List(value, collection)
	if collection == "ooxml" {
		rows = List(value, "cases")
	}
	result := []Object{}
	for _, name := range names {
		var test Object
		for _, row := range rows {
			if Str(row, "id") == name {
				test = Map(row)
				break
			}
		}
		h.Check("fixture_exists_"+name, test != nil)
		source := filepath.Join(root, Str(test, "input"))
		body := Read(source)
		h.Check("fixture_identity_"+name, Digest(body) == Str(test, "sha256") && int64(len(body)) == Int(test, "bytes"))
		kind := Str(test, "metadata", "expected_type")
		if kind == "" {
			kind = "zip"
			if collection == "text_cases" {
				kind = "txt"
			}
		}
		copy := Decode(Encoded(test))
		copy["kind"] = kind
		copy["name"] = name + "." + kind
		Write(filepath.Join(h.InputDirectory, Str(copy, "name")), body)
		Write(filepath.Join(h.Out, "inputs", Str(copy, "name")), body)
		result = append(result, copy)
	}
	return result
}
func vmRunnerObserver(h *Harness) {
	path := filepath.Join(h.Root, "internal/broker/runtime.go")
	marker := "\tsummary, e := readRuntimeSummary(run)\n"
	exits := filepath.Join(h.Out, "runner-exits")
	Must(os.Mkdir(exits, 0700))
	insert := "\tif writePrivate(filepath.Join(" + string(Encoded(exits)) + ", run.job.AttemptID+\".json\"), map[string]any{\"schema\":1,\"job_id\":run.job.JobID,\"attempt_id\":run.job.AttemptID,\"finished_event\":seenFinished,\"exit_code\":cmd.ProcessState.ExitCode(),\"exit_success\":!runnerFailed})!=nil { panic(\"FIXTURE_RUNNER_EXIT_RECORD_FAILED\") }\n"
	binary := filepath.Join(h.Out, "filegate-observed")
	BuildOverlay(h, "runner-exit", binary, map[string]string{path: ReplaceOnce(string(Read(path)), marker, insert+marker)})
	h.Binary = binary
}
func vmAssertRunnerExit(h *Harness, job Object) {
	path := filepath.Join(h.Out, "runner-exits", Str(job, "attempt_id")+".json")
	value := ReadJSON(path)
	h.Check("runner_normal_exit_"+Str(job, "attempt_id"), Equal(value, Object{"schema": 1, "job_id": job["job_id"], "attempt_id": job["attempt_id"], "finished_event": true, "exit_code": 0, "exit_success": true}) && len(List(job, "execution_errors")) == 0)
}
func vmEntryInput(name, kind string, body []byte) Object {
	return Object{"id": strings.TrimSuffix(name, filepath.Ext(name)), "name": name, "kind": kind, "sha256": Digest(body), "bytes": len(body)}
}
