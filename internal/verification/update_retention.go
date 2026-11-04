package verification

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filegate.local/filegate/internal/av"
	updatecontrol "filegate.local/filegate/internal/update"
	"golang.org/x/sys/unix"
)

var updateRetentionCases = []string{"protection-and-expiry", "recent-and-unstarted", "absent-root-reappeared", "after-intent", "after-unlink", "after-directory-sync", "before-db", "unknown-file", "replaced-inode", "unlink-denied", "db-failure"}

func init() { Register("update-retention", runUpdateRetention) }

type retentionFile struct {
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	ModifiedNS int64  `json:"modified_ns"`
	ChangedNS  int64  `json:"changed_ns"`
}
type retentionManifest struct {
	Schema         int             `json:"schema"`
	UpdateID       string          `json:"update_id"`
	BaseGeneration int64           `json:"base_generation"`
	FinalSHA256    string          `json:"final_sha256"`
	Files          []retentionFile `json:"files"`
}
type retentionAdoption struct {
	Schema      int               `json:"schema"`
	RuntimeSHA  string            `json:"runtime_sha256"`
	Manifest    retentionManifest `json:"manifest"`
	ManifestSHA string            `json:"manifest_sha256"`
	Directory   struct {
		Schema   int    `json:"schema"`
		UpdateID string `json:"update_id"`
		Device   uint64 `json:"device"`
		Inode    uint64 `json:"inode"`
	} `json:"directory"`
	Approved        updatecontrol.Clock                   `json:"approved"`
	DefinitionImage updatecontrol.DefinitionImageManifest `json:"definition_image"`
}

func retentionSQL(h *Harness, query string, args ...any) {
	db, err := sql.Open("sqlite3", filepath.Join(h.Data, "state.sqlite"))
	Must(err)
	defer db.Close()
	_, err = db.Exec(query, args...)
	Must(err)
}
func retentionSnapshot(h *Harness) Object {
	rows := h.Query("SELECT data FROM update_control")
	var raw string
	switch data := rows[0][0].(type) {
	case []byte:
		raw = string(data)
	case string:
		raw = data
	default:
		panic(Failure{"CONTROL_RAW_TYPE_INVALID"})
	}
	result := Object{"control_raw": raw, "attempts": QueryObjects(h, "SELECT data FROM update_attempts ORDER BY id"), "integrity": h.Query("PRAGMA integrity_check")[0][0]}
	runtime := []any{}
	for _, row := range h.Query("SELECT update_id,state FROM update_runtime ORDER BY update_id") {
		runtime = append(runtime, row)
	}
	result["runtime"] = runtime
	adoptions := []any{}
	for _, row := range h.Query("SELECT update_id FROM update_adoptions ORDER BY update_id") {
		adoptions = append(adoptions, row[0])
	}
	result["adoptions"] = adoptions
	retention := []any{}
	for _, row := range h.Query("SELECT update_id,resolved_at,definition_removed,runtime_removed,pending,reason FROM update_retention ORDER BY update_id") {
		var pending any
		if row[4] != nil {
			switch data := row[4].(type) {
			case []byte:
				if len(data) > 0 {
					pending = Decode(data)
				}
			case string:
				if data != "" {
					pending = Decode([]byte(data))
				}
			}
		}
		retention = append(retention, Object{"update_id": row[0], "resolved_at": row[1], "definition_removed": row[2], "runtime_removed": row[3], "pending": pending, "reason": row[5]})
	}
	result["retention"] = retention
	return result
}
func retentionAttempt(id string, clock updatecontrol.Clock, old, adopted bool) updatecontrol.Attempt {
	days := int64(1)
	if old {
		days = 31
	}
	a := updatecontrol.Attempt{ID: id, BaseGeneration: 0, State: "FINISHED", Started: clock, DeadlineContinuousNS: clock.ContinuousNS + 600000000000, ControlCommitted: adopted, OriginConfirmed: adopted, StopConfirmed: true, CleanupConfirmed: true, ReservedBytes: 0, AdoptionApproved: adopted, FinishedUTC: time.Now().Unix() - days*86400}
	if adopted {
		a.FinalSHA256 = Digest([]byte("synthetic retention final"))
		a.FinalReceived = &clock
	}
	return a
}
func retentionGeneration(h *Harness, id string, clock updatecontrol.Clock, snapshot updatecontrol.Snapshot, old bool) updatecontrol.DefinitionSet {
	directory := filepath.Join(h.Data, "definitions", id)
	Must(os.MkdirAll(directory, 0700))
	files := []retentionFile{}
	definitions := []av.Definition{}
	for _, name := range []string{"bytecode.cvd", "daily.cvd", "main.cvd"} {
		body := []byte("Synthetic retention bytes; never scanner input.\n")
		path := filepath.Join(directory, name)
		Write(path, body)
		Must(os.Chmod(path, 0400))
		var info unix.Stat_t
		Must(unix.Stat(path, &info))
		file := retentionFile{name, Digest(body), int64(len(body)), uint64(info.Dev), info.Ino, info.Mtim.Nano(), info.Ctim.Nano()}
		files = append(files, file)
		definitions = append(definitions, av.Definition{Name: name, SHA256: file.SHA256, ByteSize: file.Bytes})
	}
	image := filepath.Join(directory, "definitions.ext4")
	file, err := os.OpenFile(image, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	Must(err)
	_, err = file.Write([]byte("Synthetic sparse retention image; never VM input.\n"))
	Must(err)
	Must(file.Truncate(1 << 30))
	Must(file.Close())
	Must(os.Chmod(image, 0400))
	var imageStat unix.Stat_t
	Must(unix.Stat(image, &imageStat))
	profile := av.Profile{SchemaVersion: 1, ProfileID: "filegate-standard-av-1.4.6-candidate-v1", ScannerManifestSHA256: "47be9f07e65948d76d6cf46b38d2baf73cddcccd7562a7a3011e19af9d982b8c", ConfigurationSHA256: "08eaa97d240dde9866c14e709bbf937dbff04c068e28676e690146b150ae7477", DefinitionSetSHA256: av.DefinitionDigest(definitions), ObservationSHA256: "2820f79fce99925c4bbf2301c2bae1c1276e8940439ce61926aadb473be7dd2e", FixtureDefinitionsOnly: false, Definitions: definitions}
	binding := av.Binding{ProfileSHA256: Digest(Encoded(profile)), ScannerManifestSHA256: profile.ScannerManifestSHA256, BinarySHA256: "a174fa3c75b6f544f852cdc8205f61a3198355091ad07679bed1c0f591c31917", ConfigurationSHA256: profile.ConfigurationSHA256, DefinitionSetSHA256: profile.DefinitionSetSHA256, ObservationSHA256: profile.ObservationSHA256, FixtureDefinitionsOnly: false}
	manifest := retentionManifest{1, id, 0, Digest([]byte("synthetic retention final")), files}
	imageManifest := updatecontrol.DefinitionImageManifest{Schema: 1, UpdateID: id, BaseGeneration: 0, FinalSHA256: manifest.FinalSHA256, Profile: profile, Binding: binding}
	imageManifest.Image.Name = "definitions.ext4"
	imageManifest.Image.SHA256 = strings.Repeat("1", 64)
	imageManifest.Image.Bytes = 1 << 30
	imageManifest.Image.Device = uint64(imageStat.Dev)
	imageManifest.Image.Inode = imageStat.Ino
	imageManifest.Image.ModifiedNS = imageStat.Mtim.Nano()
	imageManifest.Image.ChangedNS = imageStat.Ctim.Nano()
	Write(filepath.Join(directory, "manifest.json"), Encoded(manifest))
	Write(filepath.Join(directory, "definition-image.json"), Encoded(imageManifest))
	var info unix.Stat_t
	Must(unix.Stat(directory, &info))
	adoption := retentionAdoption{Schema: 1, RuntimeSHA: strings.Repeat("b", 64), Manifest: manifest, ManifestSHA: Digest(Encoded(manifest)), Approved: clock, DefinitionImage: imageManifest}
	adoption.Directory.Schema = 1
	adoption.Directory.UpdateID = id
	adoption.Directory.Device = uint64(info.Dev)
	adoption.Directory.Inode = info.Ino
	a := retentionAttempt(id, clock, old, true)
	runtime := filepath.Join(h.Data, "updates", id)
	Must(os.MkdirAll(runtime, 0700))
	restore := updatecontrol.RestoreRequest{SchemaVersion: 1, UpdateID: id, BaseGeneration: 0, Snapshot: snapshot}
	requested := struct {
		Schema      int                          `json:"schema"`
		Profile     string                       `json:"profile"`
		FixtureOnly bool                         `json:"fixture_only"`
		Attempt     updatecontrol.Attempt        `json:"attempt"`
		Restore     updatecontrol.RestoreRequest `json:"restore"`
		Library     string                       `json:"library_sha256"`
		ManifestSHA string                       `json:"manifest_sha256"`
		JobID       string                       `json:"job_id"`
		AttemptID   string                       `json:"attempt_id"`
		ExpectedSHA string                       `json:"expected_sha256"`
		ByteSize    int64                        `json:"byte_size"`
	}{1, "filegate-official-update-v1", false, a, restore, fixtureLibrary, strings.Repeat("b", 64), "update_" + id, id, Digest(Encoded(restore)), int64(len(Encoded(restore)))}
	Write(filepath.Join(runtime, "request.json"), Encoded(requested))
	Write(filepath.Join(runtime, "producer.lock"), nil)
	bound := Object{"schema": 1, "job_id": requested.JobID, "attempt_id": id, "input_sha256": requested.ExpectedSHA, "byte_size": requested.ByteSize, "kind": "native_guardian"}
	native := Object{"cleanup_all_exited": true, "temporary_service_absent": true, "cleanup_after": []Object{{"same_identity_live": false}}, "guardian_result_verified": true, "terminal": Object{"all_exited": true}}
	proof := Object{}
	for k, v := range bound {
		proof[k] = v
	}
	proof["stopped"] = true
	proof["evidence"] = Object{"path": "watchdog/results.json", "sha256": Digest(Encoded(native))}
	proof["checks"] = Object{"identities_stopped": true, "service_absent": true, "guardian_verified": true}
	slot := Object{"synthetic_history": true}
	intent := Object{}
	for k, v := range bound {
		intent[k] = v
	}
	intent["stop_proof_sha256"] = Digest(Encoded(proof))
	intent["slot_owner_sha256"] = Digest(Encoded(slot))
	intent["directories"] = []any{}
	complete := Object{}
	for k, v := range bound {
		complete[k] = v
	}
	complete["cleanup_intent_sha256"] = Digest(Encoded(intent))
	complete["stop_proof_sha256"] = Digest(Encoded(proof))
	complete["raw_reclaimed"] = true
	complete["external_directories_reclaimed"] = true
	receipt := Object{"schema": 1, "profile": "filegate-official-update-v1", "fixture_only": false, "update_id": id, "base_generation": 0, "request_sha256": Digest(Encoded(requested)), "stop_confirmed": true, "cleanup_confirmed": true, "cleanup_sha256": Digest(Encoded(complete)), "final_sha256": a.FinalSHA256, "network_enabled": true, "adoption_enabled": false, "startup_only": false, "stop_proof_sha256": ""}
	for name, value := range map[string]any{"watchdog/results.json": native, "stop-proof.json": proof, "slot-owner.json": slot, "cleanup-intent.json": intent, "cleanup-complete.json": complete, "native-intent.json": Object{"config": Object{"owner_kind": "update", "continuous_start_ns": clock.ContinuousNS, "continuous_deadline_ns": a.DeadlineContinuousNS}}, "update-complete.json": receipt} {
		Write(filepath.Join(runtime, "output", name), Encoded(value))
	}
	retentionSQL(h, "INSERT INTO update_attempts VALUES(?,?,0)", id, Encoded(a))
	retentionSQL(h, "INSERT INTO update_runtime VALUES(?,?,?,'FINISHED')", id, runtime, strings.Repeat("b", 64))
	retentionSQL(h, "INSERT INTO update_adoptions VALUES(?,?)", id, Encoded(adoption))
	return updatecontrol.DefinitionSet{UpdateID: id, Generation: 1, Confirmed: clock, ManifestSHA256: adoption.ManifestSHA, ImageManifestSHA256: Digest(Encoded(imageManifest))}
}
func retentionStart(h *Harness) {
	health := h.Start("--update-library-sha256", fixtureLibrary)
	h.Check("gates_closed", GatesClosed(health))
}
func retentionSeed(h *Harness) (string, string, string, Object, updatecontrol.Clock) {
	retentionStart(h)
	source := filepath.Join(h.InputDirectory, "synthetic.txt")
	Write(source, InputA)
	code, receipt := h.Submit("file", source, Object{"idempotency_key": "retention-seed", "expected_sha256": Digest(InputA)}, nil)
	h.Check("synthetic_intake_only", code == 0)
	job := h.WaitJob(Str(receipt, "job_id"), true)
	h.Stop(false)
	control := Decode([]byte(Str(retentionSnapshot(h), "control_raw")))
	var clock updatecontrol.Clock
	var snapshot updatecontrol.Snapshot
	Must(json.Unmarshal(Encoded(control["clock"]), &clock))
	Must(json.Unmarshal(Encoded(control["snapshot"]), &snapshot))
	old, current, last := "update_"+strings.Repeat("1", 32), "update_"+strings.Repeat("2", 32), "update_"+strings.Repeat("3", 32)
	retentionGeneration(h, old, clock, snapshot, true)
	definition := retentionGeneration(h, current, clock, snapshot, true)
	control["state"] = "UNKNOWN"
	control["reason"] = "UPDATE_STATE_UNKNOWN"
	control["generation"] = 3
	control["last_update_id"] = last
	control["definition"] = definition
	retentionSQL(h, "INSERT INTO update_attempts VALUES(?,?,0)", last, Encoded(retentionAttempt(last, clock, true, false)))
	retentionSQL(h, "UPDATE update_control SET data=?", Encoded(control))
	return old, current, last, job, clock
}
func retentionFaultBuild(h *Harness, fault string) string {
	path := filepath.Join(h.Root, "internal/update/retention.go")
	source := string(Read(path))
	source += "\nfunc retentionFixtureHook(point string) {body,_:=os.ReadFile(" + string(Encoded(fault)) + ");if strings.TrimSpace(string(body))==point{os.Exit(91)}}\n"
	source = ReplaceOnce(source, "func (s *Store) finishRetention(dataDir string, plan retentionPlan) error {", "func (s *Store) finishRetention(dataDir string, plan retentionPlan) error {\nretentionFixtureHook(\"after-intent\");if plan.Kind==\"runtime\"&&plan.Root.Inode==0{retentionFixtureHook(\"absent-root-reappeared\")}")
	marker := "err = unix.Unlinkat(parentFD, name, flags)"
	source = ReplaceOnce(source, marker, "if data,_:=os.ReadFile("+string(Encoded(fault))+");strings.TrimSpace(string(data))==\"unlink-denied\"{err=unix.EACCES}else{"+marker+"};if err==nil{retentionFixtureHook(\"after-unlink\")}")
	marker = "if unix.Fstatat(fd, plan.UpdateID, &info, unix.AT_SYMLINK_NOFOLLOW)"
	source = ReplaceOnce(source, marker, "retentionFixtureHook(\"after-directory-sync\")\n"+marker)
	marker = "changed, err := s.db.Exec(\"UPDATE update_retention SET \"+column"
	source = ReplaceOnce(source, marker, "retentionFixtureHook(\"before-db\")\n"+marker)
	binary := filepath.Join(h.Out, "filegate-retention-fault")
	BuildOverlay(h, "update-retention", binary, map[string]string{path: source})
	return binary
}
func runUpdateRetention(h *Harness) {
	selected := h.Cases
	if len(selected) == 0 {
		selected = updateRetentionCases
	}
	known, seen := map[string]bool{}, map[string]bool{}
	for _, name := range updateRetentionCases {
		known[name] = true
	}
	for _, name := range selected {
		h.Check("retention_case_"+name, known[name] && !seen[name])
		seen[name] = true
	}
	h.Record["scope"] = "synthetic SQLite adoption/stop history; real local service and filesystem retention only; no VM, network, official signature or adoption acceptance"
	h.Record["synthetic_image_digest_fields"] = true
	h.Record["selected_cases"] = selected
	h.Record["pass_enabled"] = false
	h.Record["release_enabled"] = false
	Write(filepath.Join(h.Out, "synthetic-input.txt"), InputA)
	fault := filepath.Join(h.Out, "fault.txt")
	Write(fault, nil)
	faulted := retentionFaultBuild(h, fault)
	records := []Object{}
	h.Record["retain_state"] = true
	for _, name := range selected {
		directory := filepath.Join(h.Temporary, name)
		Must(os.Mkdir(directory, 0700))
		sub := &Harness{Options: h.Options, Data: filepath.Join(directory, "data"), InputDirectory: filepath.Join(directory, "inputs"), Socket: filepath.Join(directory, "data/filegate.sock"), Record: Object{}}
		sub.Binary = faulted
		Must(os.Mkdir(sub.InputDirectory, 0700))
		out := filepath.Join(h.Out, name)
		Must(os.Mkdir(out, 0700))
		evidence := Object{}
		func() {
			defer func() {
				failure := recover()
				func() {
					defer func() {
						if stopped := recover(); stopped != nil {
							sub.Record["cleanup_failure"] = failureRecord(stopped)
						}
					}()
					sub.Stop(false)
				}()
				Write(fault, nil)
				if Exists(filepath.Join(sub.Data, "state.sqlite")) {
					evidence["database_backup"] = BackupDatabase(filepath.Join(sub.Data, "state.sqlite"), filepath.Join(out, "state.sqlite"), sub.Process == nil)
				}
				WriteJSON(filepath.Join(out, "observations.json"), evidence)
				WriteJSON(filepath.Join(out, "commands.json"), sub.Commands)
				Write(filepath.Join(out, "service.log"), bytesJoin(sub.Logs))
				record := Object{"case": name, "passed": failure == nil && sub.Record["cleanup_failure"] == nil, "checks": sub.Checks, "failure": failureRecordOrNil(failure), "cleanup_failure": sub.Record["cleanup_failure"]}
				WriteJSON(filepath.Join(out, "results.json"), record)
				records = append(records, record)
				h.Record["cases"] = records
				h.Checks = append(h.Checks, sub.Checks...)
				if failure != nil {
					panic(failure)
				}
				if sub.Record["cleanup_failure"] != nil {
					panic(Failure{"retention_stop_unconfirmed"})
				}
			}()
			old, current, last, job, clock := retentionSeed(sub)
			target := filepath.Join(sub.Data, "definitions", old)
			retentionStart(sub)
			extra := map[string]bool{}
			unstarted := []string{}
			recent := ""
			if name == "recent-and-unstarted" || name == "absent-root-reappeared" {
				control := Decode([]byte(Str(retentionSnapshot(sub), "control_raw")))
				var snapshot updatecontrol.Snapshot
				Must(json.Unmarshal(Encoded(control["snapshot"]), &snapshot))
				if name == "recent-and-unstarted" {
					recent = "update_" + strings.Repeat("4", 32)
					retentionGeneration(sub, recent, clock, snapshot, false)
					extra[recent] = true
				}
				for _, entry := range []struct{ digit, kind string }{{"5", "absent"}, {"6", "empty"}, {"7", "partial"}, {"8", "unknown-time"}} {
					if name == "absent-root-reappeared" && entry.kind != "absent" {
						continue
					}
					id := "update_" + strings.Repeat(entry.digit, 32)
					runtime := filepath.Join(sub.Data, "updates", id)
					a := Decode(Encoded(retentionAttempt(id, clock, true, false)))
					if entry.kind != "absent" {
						Must(os.Mkdir(runtime, 0700))
					}
					if entry.kind == "partial" {
						Write(filepath.Join(runtime, "request.json"), []byte(`{"schema":`))
						Write(filepath.Join(runtime, "producer.lock"), nil)
					}
					if entry.kind == "unknown-time" {
						delete(a, "finished_utc")
						extra[id] = true
					} else {
						unstarted = append(unstarted, id)
					}
					retentionSQL(sub, "INSERT INTO update_attempts VALUES(?,?,0)", id, Encoded(a))
					retentionSQL(sub, "INSERT INTO update_runtime VALUES(?,?,?,'FINISHED')", id, runtime, strings.Repeat("b", 64))
				}
			}
			if name == "protection-and-expiry" {
				retentionSQL(sub, "INSERT INTO scan_definition_snapshots VALUES(?,?,1,?)", Str(job, "attempt_id"), old, Encoded(Object{}))
				before := retentionSnapshot(sub)
				status, _ := sub.Request("POST", "/v1/prune", Object{}, nil, nil)
				sub.Check("active_scan_generation_protected", status == 200 && Exists(target) && Str(retentionSnapshot(sub), "control_raw") == Str(before, "control_raw"))
				retentionSQL(sub, "UPDATE scan_definition_snapshots SET active=0")
				release := "release_" + strings.Repeat("4", 32)
				retentionSQL(sub, "INSERT INTO releases VALUES(?,?,?,?,?,0,?)", release, "fixture-release", "fixture", Str(job, "job_id"), "PREPARED", Encoded(Object{}))
				retentionSQL(sub, "INSERT INTO release_authorizations VALUES(?,1,?,?)", release, Str(job, "attempt_id"), Encoded(Object{}))
				status, _ = sub.Request("POST", "/v1/prune", Object{}, nil, nil)
				sub.Check("unresolved_release_generation_protected", status == 200 && Exists(target))
				retentionSQL(sub, "DELETE FROM release_authorizations")
				retentionSQL(sub, "DELETE FROM releases")
				var a Object
				for _, value := range List(retentionSnapshot(sub), "attempts") {
					if Str(value, "update_id") == old {
						a = Map(value)
					}
				}
				a["state"], a["cleanup_confirmed"], a["reserved_bytes"] = "CLEANUP_PENDING", false, 6<<30
				retentionSQL(sub, "UPDATE update_attempts SET data=?,reserved_bytes=? WHERE id=?", Encoded(a), 6<<30, old)
				status, _ = sub.Request("POST", "/v1/prune", Object{}, nil, nil)
				sub.Check("unresolved_update_generation_protected", status == 200 && Exists(target))
				a["state"], a["cleanup_confirmed"], a["reserved_bytes"] = "FINISHED", true, 0
				retentionSQL(sub, "UPDATE update_attempts SET data=?,reserved_bytes=0 WHERE id=?", Encoded(a), old)
			} else if name == "unknown-file" {
				Write(filepath.Join(target, "unknown.txt"), []byte("owned synthetic negative marker"))
			} else if name == "replaced-inode" {
				original := filepath.Join(target, "main.cvd")
				replacement := filepath.Join(target, "replacement.tmp")
				Write(replacement, Read(original))
				Must(os.Chmod(replacement, 0400))
				Must(os.Rename(replacement, original))
			} else if name == "db-failure" {
				retentionSQL(sub, "CREATE TRIGGER retention_failure BEFORE UPDATE OF pending ON update_retention BEGIN SELECT RAISE(ABORT,'synthetic retention failure'); END")
			}
			before := retentionSnapshot(sub)
			evidence["before"] = before
			mode := ""
			if strings.HasPrefix(name, "after-") || name == "before-db" || name == "unlink-denied" || name == "absent-root-reappeared" {
				mode = name
			}
			Write(fault, []byte(mode))
			func() {
				defer func() {
					if err := recover(); err != nil {
						evidence["prune_response"] = Object{"connection_error": fmt.Sprint(err)}
					}
				}()
				status, result := sub.Request("POST", "/v1/prune", Object{}, nil, nil)
				evidence["prune_response"] = Object{"status": status, "result": result}
			}()
			after := retentionSnapshot(sub)
			evidence["after_first"] = after
			sub.Check("prune_control_bytes_unchanged", Str(after, "control_raw") == Str(before, "control_raw"))
			if strings.HasPrefix(name, "after-") || name == "before-db" || name == "absent-root-reappeared" {
				exit := sub.AwaitExit(8 * time.Second)
				sub.Check("owned_service_crash_exit91", exit == 91)
				sub.Stop(true)
				id := old
				if name == "absent-root-reappeared" {
					id = unstarted[0]
				}
				pending := false
				for _, row := range List(after, "retention") {
					pending = pending || Str(row, "update_id") == id && Get(row, "pending") != nil
				}
				sub.Check("durable_deletion_intent", pending)
				reappeared := ""
				var identity unix.Stat_t
				if name == "absent-root-reappeared" {
					reappeared = filepath.Join(sub.Data, "updates", id)
					Must(os.Mkdir(reappeared, 0700))
					Write(filepath.Join(reappeared, "unknown.txt"), []byte("harness-owned replacement marker"))
					Must(unix.Stat(reappeared, &identity))
				}
				Write(fault, nil)
				retentionStart(sub)
				if reappeared != "" {
					observed := retentionSnapshot(sub)
					evidence["reappeared_refused"] = observed
					sentinel := false
					for _, row := range List(observed, "retention") {
						sentinel = sentinel || Str(row, "update_id") == id && Get(row, "pending") != nil && Int(row, "pending", "root", "inode") == 0
					}
					sub.Check("absent_sentinel_rejects_new_inode", string(Read(filepath.Join(reappeared, "unknown.txt"))) == "harness-owned replacement marker" && sentinel)
					var current unix.Stat_t
					Must(unix.Stat(reappeared, &current))
					sub.Check("only_owned_negative_removed", current.Ino == identity.Ino)
					Must(os.Remove(filepath.Join(reappeared, "unknown.txt")))
					Must(os.Remove(reappeared))
				}
			} else if name == "unknown-file" || name == "replaced-inode" || name == "unlink-denied" || name == "db-failure" {
				retained := false
				for _, a := range List(after, "attempts") {
					retained = retained || Str(a, "update_id") == old
				}
				sub.Check("uncertain_or_failed_deletion_retained", Exists(target) && retained)
				if name == "unknown-file" {
					Must(os.Remove(filepath.Join(target, "unknown.txt")))
				}
				if name == "db-failure" {
					retentionSQL(sub, "DROP TRIGGER retention_failure")
				}
				Write(fault, nil)
			}
			if name != "replaced-inode" {
				status, result := sub.Request("POST", "/v1/prune", Object{}, nil, nil)
				evidence["final_prune"] = Object{"status": status, "result": result}
				settled := retentionSnapshot(sub)
				evidence["settled"] = settled
				ids := map[string]bool{}
				for _, a := range List(settled, "attempts") {
					ids[Str(a, "update_id")] = true
				}
				sub.Check("old_generation_and_history_reclaimed", status == 200 && !Exists(target) && !ids[old])
				expected := map[string]bool{current: true, last: true}
				for id := range extra {
					expected[id] = true
				}
				sub.Check("current_and_last_metadata_protected", Equal(ids, expected) && Exists(filepath.Join(sub.Data, "definitions", current)) && Str(settled, "integrity") == "ok")
				if name == "recent-and-unstarted" {
					sub.Check("recent_metadata_retained_heavy_unpinned_removed", !Exists(filepath.Join(sub.Data, "definitions", recent)) && Exists(filepath.Join(sub.Data, "updates", recent)))
					absent := true
					for _, id := range unstarted {
						absent = absent && !Exists(filepath.Join(sub.Data, "updates", id))
					}
					sub.Check("unstarted_absent_empty_partial_reclaimed", absent)
					now := false
					for _, row := range List(settled, "retention") {
						if Str(row, "update_id") == "update_"+strings.Repeat("8", 32) {
							delta := Int(row, "resolved_at") - time.Now().Unix()
							now = delta > -30 && delta < 30
						}
					}
					sub.Check("unknown_resolution_time_starts_now", now)
				}
				oldControl, newControl := Decode([]byte(Str(before, "control_raw"))), Decode([]byte(Str(settled, "control_raw")))
				same := true
				for _, key := range []string{"state", "snapshot", "snapshot_sha256", "last_update_id", "definition", "next_allowed_utc"} {
					same = same && Equal(oldControl[key], newControl[key])
				}
				sub.Check("control_uuid_snapshot_unknown_preserved", same)
				sub.Stop(false)
				retentionStart(sub)
				repeat := retentionSnapshot(sub)
				evidence["restart"] = repeat
				sub.Check("restart_does_not_resurrect_expired_history", Equal(repeat["attempts"], settled["attempts"]) && Equal(repeat["runtime"], settled["runtime"]))
			}
		}()
	}
}
func failureRecordOrNil(value any) any {
	if value == nil {
		return nil
	}
	return failureRecord(value)
}
