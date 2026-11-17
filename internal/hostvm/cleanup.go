package hostvm

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type fileRule struct {
	socket  bool
	maximum int64
}

func runRules(names []string, normal bool) (map[string]fileRule, error) {
	rules := map[string]fileRule{}
	for _, name := range []string{"prepared.json", "product-request.json", "product-accepted.json", "product-accepted.json.pending"} {
		rules[name] = fileRule{maximum: ControlLimit}
	}
	for _, name := range []string{"exchange.json", "exchange.json.pending"} {
		rules[name] = fileRule{maximum: 4 << 20}
	}
	for _, name := range []string{"product-report.json", "product-report.json.pending"} {
		rules[name] = fileRule{maximum: ReportLimit}
	}
	for _, n := range []string{"1", "2", "3"} {
		for _, suffix := range []string{".json", ".json.pending"} {
			rules["product-progress-"+n+suffix] = fileRule{maximum: 1024}
		}
	}
	rules["work.raw"] = fileRule{maximum: RawBytes}
	rules["channel.sock"] = fileRule{socket: true}
	if names == nil {
		rules["exchange.json"] = fileRule{maximum: ControlLimit}
		rules["exchange.json.pending"] = fileRule{maximum: ControlLimit}
		return rules, nil
	}
	for _, name := range []string{"normal-exchange.json", "normal-exchange.json.pending", "update-bridge.json", "update-bridge.json.pending", "fixture-observation.json", "fixture-observation.pending", "fixture-observation.json.pending"} {
		rules[name] = fileRule{maximum: 1 << 20}
	}
	// Only workspace-block-io lists these names; QEMU creates qmp.sock and the fixture bridge writes fixture-qmp.json.
	rules["qmp.sock"] = fileRule{socket: true}
	rules["fixture-qmp.json"] = fileRule{maximum: 1 << 20}
	rules["fixture-qmp.json.pending"] = fileRule{maximum: 1 << 20}
	selected := map[string]fileRule{}
	for _, name := range names {
		if name == "normal-exchange.json" || name == "normal-exchange.json.pending" {
			rules["prepared.json"] = fileRule{maximum: 1 << 20}
			if normal {
				rules["prepared.json.pending"] = fileRule{maximum: 1 << 20}
			}
		}
	}
	for _, name := range names {
		rule, ok := rules[name]
		if !ok || selected[name] != (fileRule{}) && name != "channel.sock" {
			return nil, Error("CLEANUP_ALLOWED_FILE_INVALID")
		}
		selected[name] = rule
	}
	return selected, nil
}
func controlRules() map[string]fileRule {
	rules := map[string]fileRule{"watch.sock": {socket: true}}
	for _, name := range []string{"config.json", "watchdog.plist", "events.jsonl", "guardian-result.json"} {
		rules[name] = fileRule{maximum: 4 << 20}
	}
	return rules
}
func (r *Runtime) StopProof(out string, req, native Object, profile Profile) (Object, error) {
	path := filepath.Join(out, "stop-proof.json")
	var existing Object
	if !missing(path) {
		var e error
		existing, _, e = Read(path, ControlLimit)
		if e != nil {
			return nil, e
		}
		if e = Bound(existing, req); e != nil {
			return nil, e
		}
		evidence := Map(existing, "evidence")
		name := Str(evidence, "path")
		if name != "preparation-owner.json" && name != "watchdog/results.json" && name != "native-recovery.json" && name != "native-previous-boot.json" {
			return nil, Error("STOP_EVIDENCE_PATH_INVALID")
		}
		sha, e := DigestControl(filepath.Join(out, name), 16<<20)
		if e != nil || sha != Str(evidence, "sha256") {
			return nil, Error("STOP_EVIDENCE_CHANGED")
		}
		if Str(existing, "kind") != "prepare_unstarted" {
			native, _, e = Read(filepath.Join(out, name), 16<<20)
			if e != nil {
				return nil, e
			}
		}
	}
	kind := ""
	checks := Object{}
	evidenceName := ""
	switch Str(native, "kind") {
	case "native_previous_boot":
		if e := r.ValidatePreviousBoot(out, req, native, profile); e != nil {
			return nil, e
		}
		kind = "native_previous_boot"
		evidenceName = "native-previous-boot.json"
		checks = Object{"boot_changed": true, "producer_stopped": true, "service_absent": true}
	case "native_prelaunch":
		if e := Bound(native, req); e != nil {
			return nil, e
		}
		_, control, sha, e := r.ReadPlan(out, req, profile)
		if e != nil {
			return nil, e
		}
		absent, e := ServiceAbsent(launchTarget(control))
		if e != nil || !absent || Str(native, "native_intent_sha256") != sha || Str(native, "control_directory") != control || !Bool(native, "bootstrap_not_started") || !Bool(native, "service_absent") || !missing(filepath.Join(out, "native-bootstrap-dispatched.json")) || !missing(filepath.Join(out, "native-start.json")) {
			return nil, Error("NATIVE_PRELAUNCH_PROOF_INVALID")
		}
		ownerPath := filepath.Join(out, "native-bootstrap-owner.json")
		if native["bootstrap_owner_sha256"] == nil {
			if !missing(ownerPath) {
				return nil, Error("NATIVE_PRELAUNCH_OWNER_CHANGED")
			}
		} else {
			sum, e := DigestControl(ownerPath, ControlLimit)
			if e != nil || sum != Str(native, "bootstrap_owner_sha256") {
				return nil, Error("NATIVE_PRELAUNCH_OWNER_CHANGED")
			}
			owner, e := ReadOwnership(ownerPath)
			if e != nil {
				return nil, e
			}
			stopped, e := VerifyStopped(owner)
			if e != nil || !Bool(stopped, "stop_verified") {
				return nil, Error("NATIVE_PRELAUNCH_OWNER_CHANGED")
			}
		}
		kind = "native_prelaunch"
		evidenceName = "native-recovery.json"
		checks = Object{"producer_stopped": true, "bootstrap_not_started": true, "service_absent": true}
	default:
		if native != nil {
			var e error
			kind, e = r.NativeChecks(native)
			if e != nil {
				return nil, e
			}
			evidenceName = "watchdog/results.json"
			switch kind {
			case "native_guardian":
				checks = Object{"identities_stopped": true, "service_absent": true, "guardian_verified": true}
			case "native_stopped_group":
				checks = Object{"identities_stopped": true, "group_empty": true, "service_absent": true}
			case "native_unstarted":
				checks = Object{"terminal_empty": true, "transfer_disabled": true, "watchdog_stopped": true, "service_absent": true}
			default:
				return nil, Error("NATIVE_STOP_KIND_INVALID")
			}
		} else {
			if !missing(filepath.Join(out, "watchdog")) || !missing(filepath.Join(out, "vm-started.json")) {
				return nil, Error("PREPARATION_ONLY_PROOF_INVALID")
			}
			owner, e := ReadOwnership(filepath.Join(out, "preparation-owner.json"))
			if e != nil {
				return nil, e
			}
			prep, _, e := Read(filepath.Join(out, "preparation-intent.json"), ControlLimit)
			if e != nil {
				return nil, e
			}
			args := []string{r.Executable, "--prepare", "--run-directory", Str(prep, "run_directory"), "--request", filepath.Join(filepath.Dir(out), "request.json")}
			if Str(req, "profile") == fixtureProfile {
				args = []string{r.Executable, "--prepare", "--run-directory", Str(prep, "run_directory"), "--fixture", Str(req, "fixture")}
			}
			if profile == UpdateProfile {
				args, e = r.updatePreparationRecoveryArgs(out, req, prep)
				if e != nil {
					return nil, e
				}
			} else {
				if _, e = CheckedArguments(args); e != nil {
					return nil, e
				}
			}
			b, _ := Canonical(args)
			status, e := VerifyStopped(owner)
			if e != nil || Str(owner, "command_sha256") != HashBytes(b) || !Bool(status, "stop_verified") || !Bool(status, "group_empty") {
				return nil, Error("PREPARATION_STILL_ACTIVE")
			}
			kind = "prepare_unstarted"
			evidenceName = "preparation-owner.json"
			checks = Object{"leader_stopped": true, "group_empty": true}
		}
	}
	sha, e := DigestControl(filepath.Join(out, evidenceName), 16<<20)
	if e != nil {
		return nil, e
	}
	proof := Merge(Binding(req), Object{"kind": kind, "stopped": true, "evidence": Object{"path": evidenceName, "sha256": sha}, "checks": checks})
	if existing != nil && !Equal(existing, proof) {
		return nil, Error("STOP_PROOF_CHANGED")
	}
	_, e = WriteOnce(path, proof)
	return proof, e
}
func directoryScope(path, prefix string) bool {
	return filepath.Dir(path) == "/private/tmp" && (prefix == "filegate-vm-" && runPattern.MatchString(path) || prefix == "fgw-" && controlPattern.MatchString(path))
}
func openDirectory(path string) (*os.File, unix.Stat_t, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, unix.Stat_t{}, e
	}
	f := os.NewFile(uintptr(fd), path)
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != uint32(os.Getuid()) || s.Mode&07777 != 0700 {
		f.Close()
		return nil, s, Error("CLEANUP_DIRECTORY_IDENTITY_CHANGED")
	}
	return f, s, nil
}
func fileRecord(name string, s unix.Stat_t) Object {
	return Object{"name": name, "device": uint64(s.Dev), "inode": s.Ino, "size": s.Size, "mtime_ns": s.Mtim.Sec*1e9 + s.Mtim.Nsec, "mode": s.Mode}
}
func snapshotDirectory(path string, identity Object, rules map[string]fileRule, prefix string) (Object, error) {
	actual, e := filepath.EvalSymlinks(path)
	if !directoryScope(path, prefix) || e != nil || actual != path {
		return nil, Error("CLEANUP_DIRECTORY_SCOPE_INVALID")
	}
	f, s, e := openDirectory(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if !SameDirectory(s, identity) {
		return nil, Error("CLEANUP_DIRECTORY_IDENTITY_CHANGED")
	}
	names, e := f.Readdirnames(-1)
	if e != nil {
		return nil, e
	}
	sort.Strings(names)
	records := []Object{}
	for _, name := range names {
		rule, ok := rules[name]
		if !ok {
			return nil, Error("CLEANUP_UNKNOWN_FILE")
		}
		var child unix.Stat_t
		if e = unix.Fstatat(int(f.Fd()), name, &child, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return nil, e
		}
		kind := uint32(unix.S_IFREG)
		if rule.socket {
			kind = unix.S_IFSOCK
		}
		mode := child.Mode & 07777
		if uint32(child.Mode)&unix.S_IFMT != kind || child.Uid != uint32(os.Getuid()) || child.Size < 0 || child.Size > rule.maximum || mode != 0600 && (!rule.socket || mode != 0700) || name == "work.raw" && child.Nlink != 1 {
			return nil, Error("CLEANUP_FILE_INVALID")
		}
		records = append(records, fileRecord(name, child))
	}
	return Object{"path": path, "device": uint64(s.Dev), "inode": s.Ino, "files": records}, nil
}
func cleanupDirectories(intent Object) ([]Object, error) {
	rows, ok := intent["directories"].([]any)
	if !ok {
		if typed, yes := intent["directories"].([]Object); yes {
			rows = make([]any, len(typed))
			for i, v := range typed {
				rows[i] = v
			}
		} else {
			return nil, Error("CLEANUP_INTENT_INVALID")
		}
	}
	if len(rows) > 2 {
		return nil, Error("CLEANUP_INTENT_INVALID")
	}
	records := []Object{}
	seen := map[string]bool{}
	for _, row := range rows {
		record, ok := row.(map[string]any)
		if !ok || !Fields(record, "path", "device", "inode", "files") || !validDirectoryIdentity(Object{"device": record["device"], "inode": record["inode"]}) || seen[Str(record, "path")] {
			return nil, Error("CLEANUP_INTENT_INVALID")
		}
		seen[Str(record, "path")] = true
		records = append(records, record)
	}
	return records, nil
}
func reclaimDirectories(intent Object, runFiles map[string]fileRule) error {
	records, e := cleanupDirectories(intent)
	if e != nil {
		return e
	}
	for _, record := range records {
		path := Str(record, "path")
		prefix := "fgw-"
		rules := controlRules()
		if strings.HasPrefix(filepath.Base(path), "filegate-vm-") {
			prefix = "filegate-vm-"
			rules = runFiles
		}
		if !directoryScope(path, prefix) {
			return Error("CLEANUP_DIRECTORY_SCOPE_INVALID")
		}
		f, info, e := openDirectory(path)
		if os.IsNotExist(e) {
			if e = SyncDirectory(filepath.Dir(path)); e != nil {
				return e
			}
			continue
		}
		if e != nil {
			return e
		}
		e = func() error {
			if !SameDirectory(info, record) {
				return Error("CLEANUP_DIRECTORY_REPLACED")
			}
			rows, ok := record["files"].([]any)
			if !ok {
				if typed, yes := record["files"].([]Object); yes {
					rows = make([]any, len(typed))
					for i, v := range typed {
						rows[i] = v
					}
				} else {
					return Error("CLEANUP_INTENT_INVALID")
				}
			}
			expected := map[string]Object{}
			for _, v := range rows {
				item, ok := v.(map[string]any)
				name := Str(item, "name")
				_, allowed := rules[name]
				if !ok || !Fields(item, "name", "device", "inode", "size", "mtime_ns", "mode") || !allowed || expected[name] != nil {
					return Error("CLEANUP_DIRECTORY_CHANGED")
				}
				expected[name] = item
			}
			names, e := f.Readdirnames(-1)
			if e != nil {
				return e
			}
			for _, name := range names {
				if expected[name] == nil {
					return Error("CLEANUP_DIRECTORY_CHANGED")
				}
			}
			for name, item := range expected {
				var child unix.Stat_t
				e = unix.Fstatat(int(f.Fd()), name, &child, unix.AT_SYMLINK_NOFOLLOW)
				if os.IsNotExist(e) {
					continue
				}
				if e != nil {
					return e
				}
				if !Equal(fileRecord(name, child), item) || child.Uid != uint32(os.Getuid()) || name == "work.raw" && child.Nlink != 1 {
					return Error("CLEANUP_FILE_CHANGED")
				}
				if e = unix.Unlinkat(int(f.Fd()), name, 0); e != nil {
					return e
				}
			}
			if e = unix.Fsync(int(f.Fd())); e != nil {
				return e
			}
			var current unix.Stat_t
			if unix.Lstat(path, &current) != nil || current.Dev != info.Dev || current.Ino != info.Ino {
				return Error("CLEANUP_DIRECTORY_REPLACED")
			}
			if e = unix.Rmdir(path); e != nil {
				return e
			}
			return SyncDirectory(filepath.Dir(path))
		}()
		f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (r *Runtime) cleanupIntent(out string, req, proof, native Object, rules map[string]fileRule) (Object, error) {
	stopSHA, e := DigestControl(filepath.Join(out, "stop-proof.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	slotSHA, e := DigestControl(filepath.Join(out, "slot-owner.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(out, "cleanup-intent.json")
	if !missing(path) {
		v, _, e := Read(path, ControlLimit)
		if e != nil {
			return nil, e
		}
		if e = Bound(v, req); e != nil {
			return nil, e
		}
		if Str(v, "kind") != Str(proof, "kind") || Str(v, "stop_proof_sha256") != stopSHA || Str(v, "slot_owner_sha256") != slotSHA {
			return nil, Error("CLEANUP_INTENT_CHANGED")
		}
		return v, nil
	}
	prep, _, e := Read(filepath.Join(out, "preparation-intent.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	if prep["job_id"] != req["job_id"] || prep["attempt_id"] != req["attempt_id"] || !Fields(prep, "schema", "job_id", "attempt_id", "run_directory", "run_directory_identity", "reservation_charge_bytes") || Int(prep, "schema") != 1 || Int(prep, "reservation_charge_bytes") != RawBytes {
		return nil, Error("PREPARATION_INTENT_CHANGED")
	}
	directories := []Object{}
	previous := Str(proof, "kind") == "native_previous_boot"
	if native != nil {
		control := Str(native, "control_directory")
		id := Map(native, "control_directory_identity")
		if id != nil {
			if previous && missing(control) {
				if e = SyncDirectory(filepath.Dir(control)); e != nil {
					return nil, e
				}
			} else {
				record, e := snapshotDirectory(control, id, controlRules(), "fgw-")
				if e != nil {
					return nil, e
				}
				directories = append(directories, record)
			}
		} else if previous {
			if !missing(control) {
				return nil, Error("NATIVE_DIRECTORY_CHANGED")
			}
			if e = SyncDirectory(filepath.Dir(control)); e != nil {
				return nil, e
			}
		}
	}
	run := Str(prep, "run_directory")
	var runRecord Object
	if previous && missing(run) {
		if e = SyncDirectory(filepath.Dir(run)); e != nil {
			return nil, e
		}
	} else {
		runRecord, e = snapshotDirectory(run, Map(prep, "run_directory_identity"), rules, "filegate-vm-")
		if e != nil {
			return nil, e
		}
		directories = append(directories, runRecord)
	}
	if Str(proof, "kind") != "prepare_unstarted" && runRecord != nil {
		prepared, _, e := Read(filepath.Join(out, "prepared-identity.json"), ControlLimit)
		if e != nil {
			return nil, e
		}
		var raw Object
		for _, row := range runRecord["files"].([]Object) {
			if Str(row, "name") == "work.raw" {
				raw = row
			}
		}
		if raw == nil && !previous || Str(prepared, "run_directory") != run || raw != nil && (Int(raw, "size") != RawBytes || !Equal(Map(prepared, "raw_identity"), Object{"device": raw["device"], "inode": raw["inode"]})) {
			return nil, Error("RAW_IDENTITY_CHANGED")
		}
	}
	v := Merge(Binding(req), Object{"kind": proof["kind"], "stop_proof_sha256": stopSHA, "slot_owner_sha256": slotSHA, "directories": directories})
	_, e = WriteOnce(path, v)
	return v, e
}
func (r *Runtime) finishCleanup(out string, req, proof Object, profile Profile) (Object, error) {
	intentSHA, e := DigestControl(filepath.Join(out, "cleanup-intent.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	stopSHA, e := DigestControl(filepath.Join(out, "stop-proof.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	sha, e := WriteOnce(filepath.Join(out, "cleanup-complete.json"), Merge(Binding(req), Object{"kind": proof["kind"], "cleanup_intent_sha256": intentSHA, "stop_proof_sha256": stopSHA, "raw_reclaimed": true, "external_directories_reclaimed": true}))
	if e != nil {
		return nil, e
	}
	if _, e = WriteOnce(filepath.Join(out, "raw-cleanup.json"), Object{"reclaimed": true, "reservation_charge_bytes": 0, "closed_fd_evidence": "identity-bound stop-proof.json", "external_directories_reclaimed": true}); e != nil {
		return nil, e
	}
	if e = r.ReleaseSlot(out, req, profile); e != nil {
		return nil, e
	}
	return Object{"path": "cleanup-complete.json", "sha256": sha}, nil
}
func (r *Runtime) Cleanup(out string, req, native Object, profile Profile, runFiles []string) (Object, error) {
	normal := profile == UpdateProfile && Str(req, "profile") == "filegate-official-update-v1" && req["fixture_only"] == false
	rules, e := runRules(runFiles, normal)
	if e != nil {
		return nil, e
	}
	proof, e := r.StopProof(out, req, native, profile)
	if e != nil {
		return nil, e
	}
	if native == nil && Str(proof, "kind") != "prepare_unstarted" && Str(proof, "kind") != "resources_unstarted" {
		name := "watchdog/results.json"
		if Str(proof, "kind") == "native_prelaunch" {
			name = "native-recovery.json"
		}
		if Str(proof, "kind") == "native_previous_boot" {
			name = "native-previous-boot.json"
		}
		native, _, e = Read(filepath.Join(out, name), 16<<20)
		if e != nil {
			return nil, e
		}
	}
	intent, e := r.cleanupIntent(out, req, proof, native, rules)
	if e != nil {
		return nil, e
	}
	if e = reclaimDirectories(intent, rules); e != nil {
		return nil, e
	}
	return r.finishCleanup(out, req, proof, profile)
}
func (r *Runtime) CleanupUnstartedResources(out string, req Object) (Object, error) {
	resources, e := r.ReadResources(out, req)
	if e != nil {
		return nil, e
	}
	allowed := map[string]bool{"resource-intent.json": true, "runner.lock": true}
	if Str(req, "profile") == fixtureProfile {
		allowed["fixture-producer.lock"] = true
		allowed["fixture-request.json"] = true
	}
	for _, name := range []string{"slot-owner.json", "preparation-intent.json", "stop-proof.json", "cleanup-intent.json", "cleanup-complete.json", "raw-cleanup.json", "recovery-results.json", "results.json"} {
		allowed[name] = true
		allowed[name+".pending"] = true
	}
	allowed["preparation-owner.json.pending"] = true
	entries, e := os.ReadDir(out)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		s, e := Owned(filepath.Join(out, entry.Name()), unix.S_IFREG, 0600)
		if e != nil || !allowed[entry.Name()] || s.Size > ControlLimit {
			return nil, Error("UNSTARTED_RESOURCE_SCOPE_INVALID")
		}
	}
	var slot unix.Stat_t
	slotPath := filepath.Join(r.State, "active-vm.json")
	slotID := Object{"device": 0, "inode": 0}
	if !missing(slotPath) {
		v, b, e := Read(slotPath, ControlLimit)
		if e != nil {
			return nil, e
		}
		slot, e = Owned(slotPath, unix.S_IFREG, 0600)
		if e != nil || !Equal(v, resources["slot_value"]) || HashBytes(b) != Str(resources, "slot_sha256") {
			return nil, Error("FOREIGN_VM_SLOT_OWNER")
		}
		slotID = DirectoryIdentity(slot)
	}
	ownerPath := filepath.Join(out, "slot-owner.json")
	if !missing(ownerPath) {
		owner, _, e := Read(ownerPath, ControlLimit)
		if e != nil {
			return nil, e
		}
		if e = Bound(owner, req); e != nil {
			return nil, e
		}
		if Str(owner, "output_directory") != out || owner["sha256"] != resources["slot_sha256"] || slot.Ino != 0 && !SameDirectory(slot, owner) {
			return nil, Error("SLOT_OWNER_CHANGED")
		}
	} else {
		if _, e = WriteOnce(ownerPath, Merge(Binding(req), Object{"device": slotID["device"], "inode": slotID["inode"], "sha256": resources["slot_sha256"], "output_directory": out})); e != nil {
			return nil, e
		}
	}
	resourceSHA, e := DigestControl(filepath.Join(out, "resource-intent.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	proof := Merge(Binding(req), Object{"kind": "resources_unstarted", "stopped": true, "evidence": Object{"path": "resource-intent.json", "sha256": resourceSHA}, "checks": Object{"producer_stopped": true, "prepare_not_started": true}})
	if _, e = WriteOnce(filepath.Join(out, "stop-proof.json"), proof); e != nil {
		return nil, e
	}
	stopSHA, e := DigestControl(filepath.Join(out, "stop-proof.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	ownerSHA, e := DigestControl(ownerPath, ControlLimit)
	if e != nil {
		return nil, e
	}
	intentPath := filepath.Join(out, "cleanup-intent.json")
	var intent Object
	if !missing(intentPath) {
		intent, _, e = Read(intentPath, ControlLimit)
		if e != nil {
			return nil, e
		}
		if e = Bound(intent, req); e != nil {
			return nil, e
		}
		records, e := cleanupDirectories(intent)
		if e != nil {
			return nil, e
		}
		if Str(intent, "kind") != "resources_unstarted" || Str(intent, "stop_proof_sha256") != stopSHA || Str(intent, "slot_owner_sha256") != ownerSHA || len(records) > 1 {
			return nil, Error("CLEANUP_INTENT_CHANGED")
		}
		for _, record := range records {
			if record["path"] != resources["run_directory"] || len(List(record, "files")) != 0 {
				return nil, Error("CLEANUP_INTENT_CHANGED")
			}
		}
	} else {
		records := []Object{}
		run := Str(resources, "run_directory")
		if !missing(run) {
			s, e := Owned(run, unix.S_IFDIR, 0700)
			if e != nil {
				return nil, e
			}
			record, e := snapshotDirectory(run, DirectoryIdentity(s), map[string]fileRule{}, "filegate-vm-")
			if e != nil {
				return nil, e
			}
			if !missing(filepath.Join(out, "preparation-intent.json")) {
				prep, _, e := Read(filepath.Join(out, "preparation-intent.json"), ControlLimit)
				if e != nil || prep["job_id"] != req["job_id"] || prep["attempt_id"] != req["attempt_id"] || Str(prep, "run_directory") != run || !SameDirectory(s, Map(prep, "run_directory_identity")) {
					return nil, Error("PREPARATION_INTENT_CHANGED")
				}
			}
			records = append(records, record)
		}
		intent = Merge(Binding(req), Object{"kind": "resources_unstarted", "stop_proof_sha256": stopSHA, "slot_owner_sha256": ownerSHA, "directories": records})
		if _, e = WriteOnce(intentPath, intent); e != nil {
			return nil, e
		}
	}
	pending := Str(resources, "slot_pending")
	if !missing(pending) {
		expected, _ := Encoded(resources["slot_value"])
		content, e := ReadBytes(pending, int64(len(expected)))
		if e != nil {
			return nil, e
		}
		info, e := Owned(pending, unix.S_IFREG, 0600)
		if e != nil || !bytes.HasPrefix(expected, content) || slot.Ino != 0 && (slot.Dev != info.Dev || slot.Ino != info.Ino) {
			return nil, Error("SLOT_PENDING_CHANGED")
		}
		if e = os.Remove(pending); e != nil {
			return nil, e
		}
		if e = SyncDirectory(filepath.Dir(pending)); e != nil {
			return nil, e
		}
	}
	if e = reclaimDirectories(intent, map[string]fileRule{}); e != nil {
		return nil, e
	}
	// Unstarted resources have no previous-boot proof.
	return r.finishCleanup(out, req, proof, Profile{})
}
