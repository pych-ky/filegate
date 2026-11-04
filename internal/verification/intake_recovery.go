package verification

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var intakeA = []byte("FileGate synthetic original A for intake recovery.\n")
var intakeB = []byte("FileGate synthetic replacement B must not replace A.\n")
var intakeCrashes = []string{"before-complete", "after-complete", "after-link", "after-objects-sync", "after-partial-unlink", "before-commit", "after-commit"}
var intakeCases = append(append([]string{}, intakeCrashes...), "delete-failed", "delete-cancelled", "terminal-complete-proof", "db-complete-failed", "db-job-failed", "admission-pressure")

func init() { Register("intake-recovery", runIntakeRecovery) }
func intakeBuild(h *Harness) {
	intake, recovery, filesystem, download := filepath.Join(h.Root, "internal/broker/intake.go"), filepath.Join(h.Root, "internal/broker/recovery.go"), filepath.Join(h.Root, "internal/broker/filesystem.go"), filepath.Join(h.Root, "internal/acquire/url.go")
	changes := map[string]string{}
	for _, path := range []string{intake, recovery, filesystem, download} {
		changes[path] = string(Read(path))
	}
	for _, entry := range []struct{ point, path, marker string }{{"before-complete", intake, "\tif _, err = b.db.Exec(\"UPDATE reservations SET complete_sha=?,complete_size=? WHERE job_id=?\", digest, size, j.JobID); err != nil {"}, {"after-complete", intake, "\tif err = b.publishObject(objectID, digest, size); err != nil {"}, {"before-commit", intake, "\tj, err = b.commitInput(j.JobID, objectID, digest, size)"}, {"after-commit", intake, "\tb.wakeScan()\n\treturn j, nil"}, {"after-link", recovery, "\tif err = b.verifyObject(final, digest, size); err != nil {"}, {"after-objects-sync", recovery, "\tif _, err = os.Lstat(tmp); err == nil {"}, {"after-partial-unlink", recovery, "\tif syncDirectory(filepath.Dir(tmp)) != nil {"}} {
		changes[entry.path] = ReplaceOnce(changes[entry.path], entry.marker, "\tintakeFixtureBoundary("+string(Encoded(entry.point))+")\n"+entry.marker)
	}
	changes[intake] = ReplaceOnce(changes[intake], "if e = os.Remove(p); e != nil {", "if e = intakeFixtureRemove(p); e != nil {")
	changes[intake] += `
func intakeFixtureMode() string {value,err:=os.ReadFile(` + string(Encoded(filepath.Join(h.Out, "mode.txt"))) + `);if err!=nil{panic("fixture mode missing")};return string(value)}
func intakeFixtureBoundary(point string) {if intakeFixtureMode()!=point{return};marker,err:=os.OpenFile(` + string(Encoded(filepath.Join(h.Out, "crash-hit.txt"))) + `,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{os.Exit(92)};if _,err=marker.WriteString(point);err!=nil{os.Exit(92)};if marker.Sync()!=nil||marker.Close()!=nil{os.Exit(92)};os.Exit(91)}
func intakeFixtureRemove(path string) error {if intakeFixtureMode()=="delete-fault"{return os.ErrPermission};return os.Remove(path)}
`
	marker := "\tavailable := uint64(st.Bavail) * uint64(st.Bsize)"
	changes[filesystem] = ReplaceOnce(changes[filesystem], marker, "\tif intakeFixtureMode() == \"admission-pressure\" { st.Bavail = 0 }\n"+marker)
	changes[download] = ReplaceOnce(changes[download], "func Open(ctx context.Context, rawURL string) (*Body, error) {\n\treturn open(ctx, rawURL, transport())\n}", "func Open(ctx context.Context, rawURL string) (*Body, error) {\n\treturn nil, Error(\"INTAKE_FIXTURE_URL_OPEN_FORBIDDEN\")\n}")
	h.Record["build"] = BuildOverlay(h, "intake-recovery", h.Binary, changes)
}

type intakeSuite struct {
	h                  *Harness
	name, out, rootOut string
	observations       Object
}

func (s *intakeSuite) mode(value string) {
	atomicFixture(filepath.Join(s.rootOut, "mode.txt"), []byte(value))
}
func (s *intakeSuite) observe(label string, value any) any {
	s.observations[label] = value
	WriteJSON(filepath.Join(s.out, "observations.json"), s.observations)
	return value
}
func (s *intakeSuite) sql(statement string, args ...any) {
	db, err := sql.Open("sqlite3", filepath.Join(s.h.Data, "state.sqlite"))
	Must(err)
	defer db.Close()
	_, err = db.Exec(statement, args...)
	Must(err)
}
func (s *intakeSuite) snapshot(label string) Object {
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(s.h.Data, "state.sqlite")+"?mode=ro")
	Must(err)
	defer db.Close()
	result := Object{}
	for _, table := range []string{"jobs", "intakes", "attempts", "objects", "reservations", "runtime_runs", "resource_pins", "scan_queue"} {
		rows, err := db.Query("SELECT * FROM " + table)
		Must(err)
		columns, err := rows.Columns()
		Must(err)
		values := []any{}
		for rows.Next() {
			data := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range data {
				pointers[i] = &data[i]
			}
			Must(rows.Scan(pointers...))
			value := Object{}
			for i, column := range columns {
				item := data[i]
				if raw, ok := item.([]byte); ok {
					item = string(raw)
				}
				if column == "data" && (table == "jobs" || table == "attempts") {
					item = Decode([]byte(item.(string)))
				}
				value[column] = item
			}
			values = append(values, value)
		}
		Must(rows.Err())
		Must(rows.Close())
		result[table] = values
	}
	for _, directory := range []string{"objects", "partial"} {
		files := []any{}
		entries, err := os.ReadDir(filepath.Join(s.h.Data, directory))
		Must(err)
		for _, entry := range entries {
			path := filepath.Join(s.h.Data, directory, entry.Name())
			var stat unix.Stat_t
			Must(unix.Stat(path, &stat))
			files = append(files, Object{"name": entry.Name(), "bytes": stat.Size, "sha256": FileDigest(path), "device": uint64(stat.Dev), "inode": stat.Ino, "mode": stat.Mode & 07777})
		}
		result[directory+"_files"] = files
	}
	s.observe(label, result)
	return result
}
func (s *intakeSuite) metadata(expected string) Object {
	if expected == "" {
		expected = Digest(intakeA)
	}
	return Object{"source_kind": "upload", "idempotency_key": s.name, "display_name": "synthetic.txt", "expected_type": "txt", "expected_sha256": expected}
}
func (s *intakeSuite) upload(metadata Object, body []byte) (int, Object) {
	return s.h.Request("POST", "/v1/uploads", nil, map[string]string{"Content-Type": "application/octet-stream", "FileGate-Metadata": base64Raw(metadata)}, body)
}
func (s *intakeSuite) start() { s.h.Check("gates_closed", GatesClosed(s.h.Start())) }
func (s *intakeSuite) blocked(label string) {
	before := s.snapshot(label + "_before_url")
	status, value := s.h.Request("POST", "/v1/jobs/url", Object{"url": "https://example.invalid/synthetic.txt", "expected_type": "txt"}, map[string]string{"Idempotency-Key": s.name + "-new-url"}, nil)
	s.observe(label+"_url_response", Object{"status": status, "value": value})
	s.h.Check(label+"_new_work_refused", status == 503 && ErrorCode(value) == "RECOVERY_REQUIRED")
	s.h.Check(label+"_no_new_reservation", Equal(s.snapshot(label+"_after_url"), before))
}
func (s *intakeSuite) replay(metadata, job Object, status int) {
	label := fmt.Sprint("replay_", status)
	before := s.snapshot(label + "_before")
	actual, value := s.upload(metadata, intakeB)
	s.observe(label, Object{"status": actual, "value": value, "sent_body_sha256": Digest(intakeB), "sent_body_bytes": len(intakeB)})
	receipt := value
	if actual >= 400 {
		receipt = Map(value, "error", "receipt")
	}
	s.h.Check("same_key_body_b_not_acquired", actual == status && receipt != nil && Str(receipt, "job_id") == Str(job, "job_id") && Equal(receipt["job"], job) && Equal(receipt["input_receipt"], job["input_receipt"]) && Get(receipt, "current_input_checked") == false && Get(receipt, "body_consumed") == false && (status != 409 || ErrorCode(value) == "INTAKE_TERMINAL_WITHOUT_INPUT"))
	s.h.Check("replay_preserves_every_durable_row", Equal(s.snapshot(label+"_after"), before))
}
func (s *intakeSuite) settled(state Object, committed bool) Object {
	h := s.h
	h.Check("single_job_and_key", len(List(state, "jobs")) == 1 && len(List(state, "intakes")) == 1)
	empty := true
	for _, key := range []string{"reservations", "runtime_runs", "resource_pins", "scan_queue", "partial_files"} {
		empty = empty && len(List(state, key)) == 0
	}
	h.Check("no_reservation_runtime_pin_queue", empty)
	job := Map(List(state, "jobs")[0], "data")
	h.Check("hold_without_release", Str(job, "verdict") == "HOLD" && Bool(job, "runtime_cleanup_complete") && Get(job, "release", "eligible") == false)
	if committed {
		attempts, objects, files := List(state, "attempts"), List(state, "objects"), List(state, "objects_files")
		h.Check("single_original_attempt_a", Str(job, "intake_status") == "COMMITTED" && Str(job, "phase") == "FINISHED" && len(attempts) == 1 && len(objects) == 1 && len(files) == 1 && Equal(Get(attempts[0], "data"), job) && Str(files[0], "sha256") == Digest(intakeA) && Int(files[0], "bytes") == int64(len(intakeA)) && Str(job, "input_receipt", "sha256") == Digest(intakeA) && Int(job, "input_receipt", "byte_size") == int64(len(intakeA)))
	} else {
		h.Check("no_original_or_attempt", Get(job, "input_receipt") == nil && len(List(state, "attempts")) == 0 && len(List(state, "objects")) == 0 && len(List(state, "objects_files")) == 0)
	}
	return job
}
func (h *Harness) AwaitExit(timeout time.Duration) int {
	select {
	case err := <-h.processDone:
		h.processDone <- err
		return h.Process.ProcessState.ExitCode()
	case <-time.After(timeout):
		panic(Failure{"service_exit_timeout"})
	}
}
func (s *intakeSuite) crash() {
	h := s.h
	metadata := s.metadata("")
	s.observe("request", Object{"metadata": metadata, "body_sha256": Digest(intakeA), "bytes": len(intakeA)})
	hit := filepath.Join(s.rootOut, "crash-hit.txt")
	if Exists(hit) {
		Must(os.Remove(hit))
	}
	s.mode(s.name)
	func() { defer func() { _ = recover() }(); s.upload(metadata, intakeA) }()
	code := h.AwaitExit(10 * time.Second)
	marker := ""
	if Exists(hit) {
		marker = string(Read(hit))
	}
	s.observe("crash", Object{"exit_code": code, "marker": marker})
	h.Check("exact_crash_boundary", code == 91 && marker == s.name)
	h.Stop(true)
	before := s.snapshot("after_crash")
	h.Check("crash_one_job_key", len(List(before, "jobs")) == 1 && len(List(before, "intakes")) == 1)
	previous := Map(List(before, "jobs")[0], "data")
	committed := s.name != "before-complete"
	objectID := ""
	if s.name == "after-commit" {
		objectID = Str(previous, "input_receipt", "object_id")
		h.Check("db_committed_before_reply", len(List(before, "objects")) == 1 && len(List(before, "attempts")) == 1 && len(List(before, "reservations")) == 0)
	} else {
		h.Check("reservation_held_before_commit", len(List(before, "reservations")) == 1 && len(List(before, "objects")) == 0 && len(List(before, "attempts")) == 0)
		reserved := Map(List(before, "reservations")[0])
		objectID = Str(reserved, "object_id")
		expected := ""
		if committed {
			expected = Digest(intakeA)
		}
		h.Check("completion_proof_boundary", Str(reserved, "complete_sha") == expected)
	}
	expectedPartial := s.name == "before-complete" || s.name == "after-complete" || s.name == "after-link" || s.name == "after-objects-sync"
	expectedOriginal := s.name != "before-complete" && s.name != "after-complete"
	partial, objects := List(before, "partial_files"), List(before, "objects_files")
	matches := true
	for _, row := range append(append([]any{}, partial...), objects...) {
		matches = matches && Str(row, "name") == objectID && Str(row, "sha256") == Digest(intakeA) && Int(row, "bytes") == int64(len(intakeA))
	}
	pc, oc := 0, 0
	if expectedPartial {
		pc = 1
	}
	if expectedOriginal {
		oc = 1
	}
	h.Check("filesystem_boundary", len(partial) == pc && len(objects) == oc && matches)
	if expectedPartial && expectedOriginal {
		h.Check("published_link_same_inode", Equal(Get(partial[0], "device"), Get(objects[0], "device")) && Equal(Get(partial[0], "inode"), Get(objects[0], "inode")))
	}
	s.mode("normal")
	s.start()
	after := s.snapshot("after_restart")
	job := s.settled(after, committed)
	h.Check("original_job_identity_preserved", Str(job, "job_id") == Str(previous, "job_id"))
	if committed {
		h.Check("original_object_identity_preserved", Str(job, "input_receipt", "object_id") == objectID)
		if s.name == "after-commit" {
			h.Check("committed_attempt_unchanged", Equal(after["attempts"], before["attempts"]) && Equal(job, previous))
		}
	} else {
		h.Check("no_completion_proof_holds_interrupted", Str(job, "phase") == "FAILED" && Equal(job["reason_codes"], []string{"INTERRUPTED"}))
	}
	status := 409
	if committed {
		status = 200
	}
	s.replay(metadata, job, status)
}
func (s *intakeSuite) deletion() {
	h := s.h
	s.mode("delete-fault")
	var metadata, job, value Object
	expected, phase := "INPUT_HASH_MISMATCH", "FAILED"
	if s.name == "delete-cancelled" {
		var c net.Conn
		var id string
		metadata, c, id = h.BeginPartial(s.name)
		deadline := time.Now().Add(3 * time.Second)
		var before Object
		one := false
		for {
			before = h.CapacitySnapshot(id, "")
			one = false
			for _, size := range Map(before, "partial_files") {
				one = Int(Object{"v": size}, "v") == 1
			}
			if len(Map(before, "partial_files")) == 1 && one || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		s.observe("before_cancel", before)
		h.Check("cancel_after_partial_write", len(Map(before, "partial_files")) == 1 && one && len(Get(before, "reserved_objects").([]string)) == 1)
		status, cancel := h.Request("POST", "/v1/jobs/"+id+"/cancel", Object{}, nil, nil)
		s.observe("cancel_response", []any{status, cancel})
		job = h.WaitJob(id, true)
		_, value = ReadUploadResponse(h, c)
		Must(c.Close())
		expected, phase = "CANCELLED", "CANCELLED"
	} else {
		metadata = s.metadata(Digest(intakeB))
		status, response := s.upload(metadata, intakeA)
		value = response
		s.observe("hash_mismatch_response", Object{"status": status, "value": value})
		h.Check("hash_mismatch_rejected", status == 409 && ErrorCode(value) == "INPUT_HASH_MISMATCH")
		job = Map(value, "error", "receipt", "job")
	}
	s.observe("first_failure", value)
	first := s.snapshot("failed_with_retained_reservation")
	h.Check("terminal_failure_and_reservation_preserved", Str(job, "phase") == phase && Str(job, "verdict") == "HOLD" && Equal(job["reason_codes"], []string{expected, "CLEANUP_PENDING"}) && Equal(job["execution_errors"], []string{expected}) && Str(job, "finished_at") != "" && len(List(first, "reservations")) == 1 && len(List(first, "partial_files")) == 1 && len(List(first, "objects")) == 0)
	publicStatus, publicBefore := h.Request("GET", "/v1/jobs/"+Str(job, "job_id"), nil, nil, nil)
	h.Check("terminal_job_public_readback", publicStatus == 200)
	s.blocked("cleanup_pending")
	h.Stop(false)
	if s.name == "terminal-complete-proof" {
		s.sql("UPDATE reservations SET complete_sha=?,complete_size=?", Digest(intakeA), len(intakeA))
		s.observe("fixture_terminal_completion_marker", Object{"sha256": Digest(intakeA), "bytes": len(intakeA), "scope": "isolated fixture DB negative; a terminal failed intake must never publish even with a complete marker"})
	}
	s.start()
	repeated := s.snapshot("restart_with_same_delete_fault")
	h.Check("terminal_job_unchanged_while_cleanup_fails", Equal(repeated["jobs"], first["jobs"]) && len(List(repeated, "reservations")) == 1 && len(List(repeated, "attempts")) == 0 && len(List(repeated, "objects")) == 0 && len(List(repeated, "objects_files")) == 0)
	s.blocked("restart_cleanup_pending")
	h.Stop(false)
	s.mode("normal")
	s.start()
	final := s.snapshot("restart_after_delete_fault_removed")
	settled := s.settled(final, false)
	publicStatus, publicAfter := h.Request("GET", "/v1/jobs/"+Str(job, "job_id"), nil, nil, nil)
	h.Check("terminal_job_and_finished_time_never_rewritten", Equal(final["jobs"], first["jobs"]) && publicStatus == 200 && Equal(publicAfter, publicBefore))
	s.replay(metadata, settled, 409)
}
func (s *intakeSuite) databaseFailure() {
	complete := s.name == "db-complete-failed"
	statement := "CREATE TRIGGER intake_fixture_failure BEFORE UPDATE ON jobs BEGIN SELECT RAISE(FAIL,'synthetic_job_failure'); END"
	if complete {
		statement = "CREATE TRIGGER intake_fixture_failure BEFORE UPDATE OF complete_sha ON reservations BEGIN SELECT RAISE(FAIL,'synthetic_complete_failure'); END"
	}
	s.sql(statement)
	s.observe("fixture_trigger", statement)
	expected := Digest(intakeB)
	if complete {
		expected = Digest(intakeA)
	}
	metadata := s.metadata(expected)
	status, value := s.upload(metadata, intakeA)
	s.observe("database_failure_response", Object{"status": status, "value": value})
	before := s.snapshot("after_sqlite_failure")
	count := 0
	if complete {
		count = 1
	}
	s.h.Check("real_sqlite_failure_stops_commit", status == 503 && ErrorCode(value) == "STORE_UNAVAILABLE" && len(List(before, "jobs")) == 1 && len(List(before, "intakes")) == 1 && len(List(before, "reservations")) == 1 && len(List(before, "objects")) == 0 && len(List(before, "attempts")) == 0 && len(List(before, "objects_files")) == 0 && len(List(before, "partial_files")) == count && Str(List(before, "reservations")[0], "complete_sha") == "")
	job := Map(List(before, "jobs")[0], "data")
	s.h.Check("uncommitted_failure_not_terminal", Str(job, "phase") == "ACQUIRING" && Get(job, "input_receipt") == nil)
	s.blocked("database_failure")
	s.replay(metadata, job, 202)
	s.sql("DROP TRIGGER intake_fixture_failure")
	s.h.Stop(false)
	s.start()
	settled := s.settled(s.snapshot("after_sqlite_recovery"), false)
	s.h.Check("missing_completion_proof_recovers_interrupted", Str(settled, "job_id") == Str(job, "job_id") && Str(settled, "phase") == "FAILED" && Equal(settled["reason_codes"], []string{"INTERRUPTED"}))
	s.replay(metadata, settled, 409)
}
func (s *intakeSuite) admission() {
	metadata := s.metadata("")
	s.mode("admission-pressure")
	status, value := s.upload(metadata, intakeA)
	s.observe("capacity_rejection", Object{"status": status, "value": value})
	before := s.snapshot("before_reservation_rejection")
	empty := true
	for _, rows := range before {
		empty = empty && len(rows.([]any)) == 0
	}
	s.h.Check("pre_reservation_capacity_rejection_consumes_no_key", status == 507 && ErrorCode(value) == "DISK_PRESSURE" && empty)
	s.mode("normal")
	status, value = s.upload(metadata, intakeA)
	s.observe("same_key_after_capacity_normal", Object{"status": status, "value": value})
	s.h.Check("same_key_can_be_first_accepted", status == 202 && Get(value, "replayed") == false && Str(value, "intake_status") == "COMMITTED")
	settled := s.settled(s.snapshot("admitted_after_capacity_recovery"), true)
	s.replay(metadata, settled, 200)
}
func runIntakeRecovery(h *Harness) {
	if h.Binary == "" {
		h.Binary = filepath.Join(h.Out, "filegate")
	}
	selected := h.Cases
	if len(selected) == 0 {
		selected = intakeCases
	}
	known, seen := map[string]bool{}, map[string]bool{}
	for _, name := range intakeCases {
		known[name] = true
	}
	for _, name := range selected {
		h.Check("intake_case_"+name, known[name] && !seen[name])
		seen[name] = true
	}
	h.Record["scope"] = "actual intake service and SQLite crash/recovery with isolated faults; no VM"
	h.Record["selected_cases"] = selected
	h.Record["vm_started"] = false
	h.Record["not_demonstrated"] = []string{"OS reboot or power loss", "physical disk exhaustion", "AV, PASS or release", "customer material"}
	Write(filepath.Join(h.Out, "inputs/a.txt"), intakeA)
	Write(filepath.Join(h.Out, "inputs/b.txt"), intakeB)
	h.Record["input_sha256"] = Object{"a.txt": Digest(intakeA), "b.txt": Digest(intakeB)}
	intakeBuild(h)
	records := []Object{}
	for _, name := range selected {
		fmt.Println(string(Encoded(Object{"event": "STARTING_CASE", "case": name})))
		directory := filepath.Join(h.Temporary, name)
		Must(os.Mkdir(directory, 0700))
		sub := &Harness{Options: h.Options, Data: filepath.Join(directory, "data"), InputDirectory: filepath.Join(directory, "inputs"), Socket: filepath.Join(directory, "data/filegate.sock"), Record: Object{}}
		sub.Binary = h.Binary
		Must(os.Mkdir(sub.InputDirectory, 0700))
		out := filepath.Join(h.Out, name)
		Must(os.Mkdir(out, 0700))
		suite := &intakeSuite{sub, name, out, h.Out, Object{}}
		func() {
			defer func() {
				h.Checks = append(h.Checks, sub.Checks...)
				record := Object{"name": name, "checks": sub.Checks, "service_output_bytes": len(bytesJoin(sub.Logs))}
				if Exists(filepath.Join(out, "observations.json")) {
					record["observations_sha256"] = FileDigest(filepath.Join(out, "observations.json"))
				}
				records = append(records, record)
				h.Record["cases"] = records
				WriteJSON(filepath.Join(h.Out, "results.json"), h.Record)
			}()
			defer sub.Stop(true)
			suite.mode("normal")
			suite.start()
			crash := false
			for _, value := range intakeCrashes {
				crash = crash || value == name
			}
			switch {
			case crash:
				suite.crash()
			case strings.HasPrefix(name, "delete-") || name == "terminal-complete-proof":
				suite.deletion()
			case strings.HasPrefix(name, "db-"):
				suite.databaseFailure()
			default:
				suite.admission()
			}
			sub.Stop(false)
			outputBytes := 0
			for _, body := range sub.Logs {
				outputBytes += len(body)
			}
			sub.Record["service_output_bytes"] = outputBytes
			sub.Check("service_output_empty", outputBytes == 0)
		}()
		fmt.Println(string(Encoded(Object{"event": "CASE_FINISHED", "case": name})))
	}
}
