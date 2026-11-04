package verification

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func init() { Register("pressure", runPressure) }
func pressureBuild(h *Harness) {
	Must(os.Mkdir(filepath.Join(h.Out, "core-records"), 0700))
	path := filepath.Join(h.Root, "internal/pressure/monitor_darwin.go")
	original := string(Read(path))
	marker := "func (m *Monitor) Read() (Sample, error) {"
	source := ReplaceOnce(original, "import (\n", "import (\n\t\"encoding/json\"\n")
	source = ReplaceOnce(source, marker, "func (m *Monitor) readMeasured() (Sample, error) {")
	source += `
func (m *Monitor) Read() (Sample, error) {
 measured, err := m.readMeasured()
 if err != nil || measured.Level != Normal || measured.Pending&(Warning|Critical) != 0 { return measured, err }
 body, err := os.ReadFile(` + string(Encoded(filepath.Join(h.Out, "pressure-state.json"))) + `)
 if err != nil { return Sample{}, Unavailable }
 var fixture struct { Level uint32 ` + "`json:\"level\"`" + `; ContinuousNS uint64 ` + "`json:\"continuous_ns\"`" + `; Failed bool ` + "`json:\"failed\"`" + ` }
 if json.Unmarshal(body, &fixture) != nil || fixture.Failed { return Sample{}, Unavailable }
 if fixture.Level != Normal && fixture.Level != Warning && fixture.Level != Critical { return Sample{}, Unavailable }
 return Sample{Level:fixture.Level,Pending:fixture.Level,ContinuousNS:fixture.ContinuousNS},nil
}
`
	corePath := filepath.Join(h.Root, "cmd/filegate/core.go")
	core := string(Read(corePath))
	capture := ReplaceOnce(core, `import "golang.org/x/sys/unix"`, `import ("golang.org/x/sys/unix"; "encoding/json"; "os"; "path/filepath"; "strconv")`)
	capture = ReplaceOnce(capture, "\treturn nil\n", `
 role := "cli"
 for _, argument := range os.Args[1:] { if argument == "serve" || argument == "mcp" {role=argument;break} }
 evidence,_:=json.Marshal(map[string]any{"pid":os.Getpid(),"role":role,"soft":actual.Cur,"hard":actual.Max})
 proof,err:=os.OpenFile(filepath.Join(`+string(Encoded(filepath.Join(h.Out, "core-records")))+`,strconv.Itoa(os.Getpid())+".json"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return err};if _,err=proof.Write(evidence);err==nil{err=proof.Sync()};closeErr:=proof.Close();if err!=nil{return err};if closeErr!=nil{return closeErr};return nil
`)
	refuse := ReplaceOnce(core, "func disableCoreDumps() error {", "func disableCoreDumps() error {\n\treturn unix.EPERM\n}\nfunc unusedCoreDumpFixture() error {")
	builds := []Object{BuildOverlay(h, "pressure", h.Binary, map[string]string{path: source, corePath: capture}), BuildOverlay(h, "core-refusal", h.Binary+"-core-refusal", map[string]string{corePath: refuse})}
	h.Record["builds"] = builds
}
func runPressure(h *Harness) {
	if h.Binary == "" {
		h.Binary = filepath.Join(h.Out, "filegate")
	}
	pressureBuild(h)
	h.Record["scope"] = "broker memory-pressure synthetic notifications and continuous clock; real Dispatch subscription; no VM or OS pressure induction"
	h.Record["real_pressure_induced"] = false
	h.Record["real_clock_changed"] = false
	h.Record["vm_started"] = false
	h.Record["not_demonstrated"] = []string{"native VM warning/critical termination", "real OS pressure transition", "release write interruption while PASS gate is closed"}
	state := filepath.Join(h.Out, "pressure-state.json")
	marker := filepath.Join(h.Data, "host-pressure.blocked")
	writeState := func(level, clock int64, failed bool) {
		atomicFixture(state, Encoded(Object{"level": level, "continuous_ns": clock * 1000000000, "failed": failed}))
	}
	denied := func(key, reason string) {
		status, value := h.Request("POST", "/v1/jobs", Object{"source_kind": "local", "root_id": "fixture", "source": "pressure.txt", "idempotency_key": key}, nil, nil)
		h.Check(key+"_refused", status == 503 && ErrorCode(value) == reason)
	}
	waitMarker := func(present bool) {
		deadline := time.Now().Add(4 * time.Second)
		for Exists(marker) != present && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		h.Check(fmt.Sprint("pressure_marker_", present), Exists(marker) == present)
	}
	normal := func(clock int64, restart bool) {
		writeState(1, clock, false)
		denied(fmt.Sprint("normal-start-", clock), "HOST_RESOURCE_PRESSURE")
		writeState(1, clock+29, false)
		denied(fmt.Sprint("normal-before-30-", clock), "HOST_RESOURCE_PRESSURE")
		if restart {
			var before, after unix.Stat_t
			Must(unix.Stat(marker, &before))
			h.Stop(false)
			h.Start()
			Must(unix.Stat(marker, &after))
			h.Check("restart_retains_pressure_marker_identity", before.Dev == after.Dev && before.Ino == after.Ino)
			writeState(1, clock+30, false)
			denied("restart-does-not-clear-pressure", "HOST_RESOURCE_PRESSURE")
			clock += 29
		}
		writeState(1, clock+30, false)
		waitMarker(false)
	}
	Write(filepath.Join(h.InputDirectory, "pressure.txt"), []byte("FileGate harmless pressure fixture.\n"))
	writeState(1, 100, false)
	health := h.Start()
	h.Check("all_acceptance_gates_closed", GatesClosed(health))
	h.CapacitySuccess("pressure-before", true)
	observations := []Object{}
	for index, test := range []struct {
		name  string
		level int64
	}{{"warning", 2}, {"critical", 4}} {
		metadata, c, id := h.BeginPartial("memory-" + test.name)
		before := h.CapacitySnapshot(id, "")
		started := time.Now()
		clock := int64(index+1) * 1000
		writeState(test.level, clock, false)
		failed := h.WaitJob(id, true)
		elapsed := time.Since(started)
		status, body := ReadUploadResponse(h, c)
		Must(c.Close())
		after := h.CapacitySnapshot(id, "")
		h.Check(test.name+"_interrupts_stalled_upload", elapsed < 4*time.Second && status == 503 && ErrorCode(body) == "HOST_RESOURCE_PRESSURE" && Str(failed, "phase") == "FAILED" && Str(failed, "verdict") == "HOLD" && Contains(Get(failed, "execution_errors"), "HOST_RESOURCE_PRESSURE"))
		h.Check(test.name+"_reclaims_partial_and_reservation", len(Get(after, "reserved_objects").([]string)) == 0 && len(Map(after, "partial_files")) == 0 && Int(after, "committed_objects") == 0 && Get(failed, "input_receipt") == nil)
		waitMarker(true)
		info, err := os.Stat(marker)
		Must(err)
		h.Check(test.name+"_marker_private_empty", info.Size() == 0 && info.Mode().Perm() == 0600)
		denied(test.name+"-new-start", "HOST_RESOURCE_PRESSURE")
		status, replay, closed, _ := h.UnreadUpload(metadata, "length")
		h.Check(test.name+"_failed_key_not_reexecuted", status == 409 && ErrorCode(replay) == "INTAKE_TERMINAL_WITHOUT_INPUT" && Str(replay, "error", "receipt", "job_id") == id && closed)
		normal(clock+100, index == 0)
		h.CapacitySuccess("pressure-after-"+test.name, false)
		_, unchanged := h.Request("GET", "/v1/jobs/"+id, nil, nil, nil)
		h.Check(test.name+"_interrupted_job_not_requeued", Equal(unchanged, failed))
		observations = append(observations, Object{"name": test.name, "before": before, "after": after, "interrupted_job": failed, "elapsed_seconds": elapsed.Seconds()})
		h.Record["observations"] = observations
	}
	_, c, id := h.BeginPartial("memory-monitor-failure")
	writeState(1, 3000, true)
	failed := h.WaitJob(id, true)
	status, body := ReadUploadResponse(h, c)
	Must(c.Close())
	h.Check("failed_measurement_cancels_with_own_reason", status == 503 && ErrorCode(body) == "RESOURCE_MONITOR_FAILED" && Contains(Get(failed, "execution_errors"), "RESOURCE_MONITOR_FAILED"))
	denied("failed-monitor-new-start", "RESOURCE_MONITOR_FAILED")
	writeState(1, 3100, false)
	denied("monitor-normal-start", "RESOURCE_MONITOR_FAILED")
	writeState(1, 3129, false)
	denied("monitor-before-normal-30", "RESOURCE_MONITOR_FAILED")
	writeState(1, 3130, false)
	waitMarker(false)
	h.CapacitySuccess("pressure-after-monitor-recovery", false)
	r := Execute(h.Root, []string{h.Binary, "--data-dir", h.Data, "mcp"}, nil, 10*time.Second)
	h.Check("mcp_entry_clean_exit", r.ExitCode == 0 && len(r.Stderr) == 0)
	h.Stop(false)
	refusedData := filepath.Join(h.Out, "core-refusal-data")
	r = Execute(h.Root, []string{h.Binary + "-core-refusal", "--data-dir", refusedData, "serve"}, nil, 10*time.Second)
	h.Check("core_limit_failure_refuses_before_processing", r.ExitCode == 2 && !Exists(refusedData) && ErrorCode(Decode(r.Stdout)) == "CORE_DUMP_POLICY_FAILED" && len(r.Stderr) == 0)
	invalid := []Object{}
	for _, kind := range []string{"symlink", "mode", "size", "hardlink"} {
		data := filepath.Join(h.Out, "invalid-marker-"+kind)
		Must(os.Mkdir(data, 0700))
		path := filepath.Join(data, "host-pressure.blocked")
		other := filepath.Join(data, "fixture-target")
		if kind == "symlink" {
			Write(other, []byte("FileGate marker fixture target.\n"))
			Must(os.Symlink(other, path))
		} else {
			content := []byte{}
			if kind == "size" {
				content = []byte("x")
			}
			Write(path, content)
			if kind == "mode" {
				Must(os.Chmod(path, 0644))
			}
			if kind == "hardlink" {
				Must(os.Link(path, other))
			}
		}
		var before, after unix.Stat_t
		Must(unix.Lstat(path, &before))
		r := Execute(h.Root, []string{h.Binary, "--data-dir", data, "serve"}, nil, 10*time.Second)
		Must(unix.Lstat(path, &after))
		h.Check(kind+"_marker_startup_refused", r.ExitCode == 2 && ErrorCode(Decode(r.Stdout)) == "RESOURCE_MONITOR_FAILED" && len(r.Stderr) == 0)
		h.Check(kind+"_unknown_marker_unchanged", before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode && before.Size == after.Size && before.Nlink == after.Nlink)
		invalid = append(invalid, Object{"kind": kind, "exit_code": r.ExitCode, "error": ErrorCode(Decode(r.Stdout)), "device": before.Dev, "inode": before.Ino, "mode": before.Mode, "size": before.Size, "links": before.Nlink})
		Must(os.RemoveAll(data))
	}
	h.Record["invalid_markers"] = invalid
	core := []Object{}
	roles := map[string]bool{}
	zero := true
	paths, err := filepath.Glob(filepath.Join(h.Out, "core-records/*.json"))
	Must(err)
	for _, path := range paths {
		value := ReadJSON(path)
		core = append(core, value)
		roles[Str(value, "role")] = true
		zero = zero && Int(value, "soft") == 0 && Int(value, "hard") == 0
	}
	h.Record["core_readbacks"] = core
	h.Check("cli_broker_mcp_core_limits_zero", roles["cli"] && roles["serve"] && roles["mcp"] && zero)
	outputBytes := 0
	for _, body := range h.Logs {
		outputBytes += len(body)
	}
	h.Record["service_output_bytes"] = outputBytes
	h.Check("service_outputs_empty", outputBytes == 0)
	pressureSnapshot(h)
}
func pressureSnapshot(h *Harness) {
	target := filepath.Join(h.Out, "state.sqlite")
	source, err := sql.Open("sqlite3", filepath.Join(h.Data, "state.sqlite"))
	Must(err)
	_, err = source.Exec("VACUUM INTO ?", target)
	Must(err)
	Must(source.Close())
	saved, err := sql.Open("sqlite3", target)
	Must(err)
	defer saved.Close()
	var journal, integrity string
	Must(saved.QueryRow("PRAGMA journal_mode=DELETE").Scan(&journal))
	Must(saved.QueryRow("PRAGMA integrity_check").Scan(&integrity))
	rows, err := saved.Query("SELECT data FROM jobs ORDER BY id")
	Must(err)
	jobs := []Object{}
	for rows.Next() {
		var body []byte
		Must(rows.Scan(&body))
		jobs = append(jobs, Decode(body))
	}
	Must(rows.Err())
	Must(rows.Close())
	counts := Object{}
	empty := true
	for _, table := range []string{"reservations", "resource_pins", "scan_queue", "runtime_runs", "release_reservations", "releases"} {
		var count int64
		Must(saved.QueryRow("SELECT count(*) FROM " + table).Scan(&count))
		counts[table] = count
		empty = empty && count == 0
	}
	failed := 0
	terminal := true
	for _, job := range jobs {
		phase := Str(job, "phase")
		terminal = terminal && Str(job, "verdict") == "HOLD" && (phase == "FINISHED" || phase == "FAILED")
		if phase == "FAILED" {
			failed++
		}
	}
	h.Check("database_snapshot_contains_all_terminal_jobs", strings.EqualFold(journal, "delete") && integrity == "ok" && len(jobs) == 7 && terminal && failed == 3)
	h.Check("database_snapshot_reservations_pins_queue_released", empty)
	Must(saved.Close())
	h.Record["database_snapshot"] = Object{"sha256": FileDigest(target), "journal_mode": journal, "integrity": integrity, "jobs": len(jobs), "counts": counts}
}
