package hostvm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func RecordedChildren(events []Object, group int64) ([]Object, error) {
	ready := []Object{}
	guardians := []Object{}
	for _, event := range events {
		switch Str(event, "event") {
		case "MONITOR_READY":
			ready = append(ready, event)
		case "GUARDIAN_READY":
			guardians = append(guardians, event)
		}
	}
	if len(ready) > 1 || len(guardians) > 1 {
		return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
	}
	children := []Object{}
	if len(ready) > 0 {
		var e error
		children, e = identities(ready[0]["processes"])
		if e != nil {
			return nil, e
		}
	}
	if len(guardians) > 0 {
		guardian, e := ProcessIdentity(guardians[0], "guardian")
		if e != nil {
			return nil, e
		}
		known := []Object{}
		for _, c := range children {
			if Str(c, "role") == "guardian" {
				known = append(known, c)
			}
		}
		if Int(guardians[0], "process_group") != group || len(known) > 0 && (len(known) != 1 || !Equal(known[0], guardian)) {
			return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
		}
		if len(known) == 0 {
			children = append([]Object{guardian}, children...)
		}
	}
	seenPID := map[int64]bool{}
	seenRole := map[string]bool{}
	for _, c := range children {
		pid := Int(c, "pid")
		role := Str(c, "role")
		if seenPID[pid] || seenRole[role] || role != "guardian" && role != "vm" && role != "helper" {
			return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
		}
		seenPID[pid] = true
		seenRole[role] = true
	}
	if len(children) > 3 {
		return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
	}
	return children, nil
}
func validDirectoryIdentity(value Object) bool {
	return Fields(value, "device", "inode") && Int(value, "device") > 0 && Int(value, "inode") > 0
}
func (r *Runtime) PreviousBootProof(out string, req Object, profile Profile) (Object, error) {
	plan, control, planSHA, e := r.ReadPlan(out, req, profile)
	if e != nil {
		return nil, e
	}
	boot, e := BootUUID()
	if e != nil || Str(plan, "boot_session_uuid") == boot {
		return nil, Error("NATIVE_PREVIOUS_BOOT_UNCONFIRMED")
	}
	absent, e := ServiceAbsent(launchTarget(control))
	if e != nil || !absent {
		return nil, Error("NATIVE_SERVICE_STILL_PRESENT")
	}
	prep, prepBytes, e := Read(filepath.Join(out, "preparation-intent.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	prepared, preparedBytes, e := Read(filepath.Join(out, "prepared-identity.json"), ControlLimit)
	if e != nil {
		return nil, e
	}
	run := Str(Map(plan, "config"), "run_directory")
	runIdentity := Map(prep, "run_directory_identity")
	if !Fields(prep, "schema", "job_id", "attempt_id", "run_directory", "run_directory_identity", "reservation_charge_bytes") || Int(prep, "schema") != 1 || prep["job_id"] != req["job_id"] || prep["attempt_id"] != req["attempt_id"] || Str(prep, "run_directory") != run || Int(prep, "reservation_charge_bytes") != RawBytes || !runPattern.MatchString(run) || !Fields(prepared, "run_directory", "raw_identity") || Str(prepared, "run_directory") != run || !validDirectoryIdentity(runIdentity) || !validDirectoryIdentity(Map(prepared, "raw_identity")) {
		return nil, Error("NATIVE_PREVIOUS_BOOT_RESOURCE_INVALID")
	}
	var controlIdentity Object
	var controlSHA any
	if !missing(filepath.Join(out, "native-directory.json")) {
		owner, b, e := Read(filepath.Join(out, "native-directory.json"), ControlLimit)
		if e != nil {
			return nil, e
		}
		if e = Bound(owner, req); e != nil || !Fields(owner, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "device", "inode") {
			return nil, Error("NATIVE_DIRECTORY_CHANGED")
		}
		controlIdentity = Object{"device": owner["device"], "inode": owner["inode"]}
		if !validDirectoryIdentity(controlIdentity) {
			return nil, Error("NATIVE_DIRECTORY_IDENTITY_INVALID")
		}
		controlSHA = HashBytes(b)
	}
	for path, id := range map[string]Object{run: runIdentity, control: controlIdentity} {
		if !missing(path) {
			s, e := Owned(path, unix.S_IFDIR, 0700)
			if e != nil || id == nil || !SameDirectory(s, id) {
				return nil, Error("NATIVE_DIRECTORY_CHANGED")
			}
		}
	}
	return Merge(Binding(req), Object{"kind": "native_previous_boot", "native_intent_sha256": planSHA, "preparation_intent_sha256": HashBytes(prepBytes), "prepared_identity_sha256": HashBytes(preparedBytes), "native_directory_sha256": controlSHA, "previous_boot_uuid": plan["boot_session_uuid"], "observed_boot_uuid": boot, "control_directory": control, "control_directory_identity": nullableObject(controlIdentity), "run_directory": run, "run_directory_identity": runIdentity, "boot_changed": true, "service_absent": true}), nil
}
func nullableObject(m Object) any {
	if m == nil {
		return nil
	}
	return m
}
func (r *Runtime) ValidatePreviousBoot(out string, req, native Object, profile Profile) error {
	current, e := r.PreviousBootProof(out, req, profile)
	if e != nil {
		return e
	}
	if !bootPattern.MatchString(Str(native, "observed_boot_uuid")) || native["observed_boot_uuid"] == native["previous_boot_uuid"] {
		return Error("NATIVE_PREVIOUS_BOOT_PROOF_INVALID")
	}
	current["observed_boot_uuid"] = native["observed_boot_uuid"]
	if !Equal(current, native) {
		return Error("NATIVE_PREVIOUS_BOOT_PROOF_CHANGED")
	}
	return nil
}
func (r *Runtime) RecoverNative(out string, req Object, profile Profile) (Object, error) {
	plan, control, planSHA, e := r.ReadPlan(out, req, profile)
	if e != nil {
		return nil, e
	}
	boot, e := BootUUID()
	if e != nil {
		return nil, e
	}
	if Str(plan, "boot_session_uuid") != boot {
		return r.PreviousBootProof(out, req, profile)
	}
	target := launchTarget(control)
	ownerPath := filepath.Join(out, "native-bootstrap-owner.json")
	dispatchPath := filepath.Join(out, "native-bootstrap-dispatched.json")
	startedPath := filepath.Join(out, "native-start.json")
	var info unix.Stat_t
	exists := !missing(control)
	if exists {
		info, e = Owned(control, unix.S_IFDIR, 0700)
		if e != nil {
			return nil, e
		}
	}
	if !missing(filepath.Join(out, "native-directory.json")) {
		owner, _, e := Read(filepath.Join(out, "native-directory.json"), ControlLimit)
		if e != nil {
			return nil, e
		}
		if e = Bound(owner, req); e != nil || !exists || !SameDirectory(info, owner) {
			return nil, Error("NATIVE_DIRECTORY_CHANGED")
		}
	}
	var owner Object
	if !missing(ownerPath) {
		owner, e = ReadOwnership(ownerPath)
		if e != nil {
			return nil, e
		}
		args := []string{"/bin/launchctl", "bootstrap", "gui/" + itoa(os.Getuid()), filepath.Join(control, "watchdog.plist")}
		body, _ := Canonical(args)
		stopped, e := VerifyStopped(owner)
		if e != nil || Str(owner, "kind") != "native_bootstrap_group" || Str(owner, "command_sha256") != HashBytes(body) || !Bool(stopped, "stop_verified") {
			return nil, Error("NATIVE_BOOTSTRAP_STOP_UNCONFIRMED")
		}
	}
	if missing(dispatchPath) {
		absent, e := ServiceAbsent(target)
		if e != nil || !missing(startedPath) || !absent {
			return nil, Error("NATIVE_UNSTARTED_SCOPE_INVALID")
		}
		configuration, _ := Encoded(plan["config"])
		expected := map[string][]byte{"config.json": configuration, "watchdog.plist": PlistBytes(control, r.NativeBinary)}
		if exists {
			files, e := os.ReadDir(control)
			if e != nil {
				return nil, e
			}
			for _, file := range files {
				want, ok := expected[file.Name()]
				if !ok {
					return nil, Error("NATIVE_UNSTARTED_FILE_CHANGED")
				}
				body, e := ReadBytes(filepath.Join(control, file.Name()), int64(len(want)))
				if e != nil || !bytes.HasPrefix(want, body) {
					return nil, Error("NATIVE_UNSTARTED_FILE_CHANGED")
				}
			}
		}
		var ownerSHA any
		if owner != nil {
			sha, e := DigestControl(ownerPath, RequestLimit)
			if e != nil {
				return nil, e
			}
			ownerSHA = sha
		}
		return Merge(Binding(req), Object{"kind": "native_prelaunch", "native_intent_sha256": planSHA, "bootstrap_owner_sha256": ownerSHA, "control_directory": control, "control_directory_identity": nullableObject(identityIf(exists, info)), "bootstrap_not_started": true, "service_absent": true}), nil
	}
	dispatch, e := ReadOwnership(dispatchPath)
	if e != nil || owner == nil || !Equal(dispatch, owner) || !exists {
		return nil, Error("NATIVE_BOOTSTRAP_STOP_UNCONFIRMED")
	}
	body, e := ReadBytes(filepath.Join(control, "config.json"), ControlLimit)
	want, _ := Encoded(plan["config"])
	if e != nil || !bytes.Equal(body, want) {
		return nil, Error("NATIVE_LAUNCH_FILES_CHANGED")
	}
	body, e = ReadBytes(filepath.Join(control, "watchdog.plist"), ControlLimit)
	if e != nil || !bytes.Equal(body, PlistBytes(control, r.NativeBinary)) {
		return nil, Error("NATIVE_LAUNCH_FILES_CHANGED")
	}
	until := time.Now().Add(16 * time.Second)
	var events []Object
	var first, terminal Object
	for {
		events, e = NativeEvents(control)
		if e != nil {
			events = []Object{}
		}
		first = firstEvent(events, "WATCHDOG_STARTED")
		terminal = firstEvent(events, "FINISHED")
		if terminal != nil {
			break
		}
		if first != nil {
			id, e := ProcessIdentity(first, "watchdog")
			if e != nil {
				return nil, e
			}
			empty, e := GroupEmpty(int(Int(first, "pid")))
			if e == nil && empty && IdentityReadback(id)["same_identity_live"] == false {
				break
			}
		}
		if !time.Now().Before(until) {
			return nil, Error("NATIVE_TERMINAL_UNAVAILABLE")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if first == nil {
		return nil, Error("NATIVE_START_IDENTITY_MISSING")
	}
	watchdog, e := ProcessIdentity(first, "watchdog")
	if e != nil {
		return nil, e
	}
	counts := map[string]int{}
	for _, v := range events {
		counts[Str(v, "event")]++
	}
	config := Map(plan, "config")
	if counts["WATCHDOG_STARTED"] != 1 || counts["FINISHED"] != map[bool]int{true: 0, false: 1}[terminal == nil] || counts["MONITOR_READY"] > 1 || !Equal(first["continuous_start_ns"], config["continuous_start_ns"]) || !Equal(first["continuous_deadline_ns"], config["continuous_deadline_ns"]) || !Equal(first["process_group"], watchdog["pid"]) || terminal != nil && terminal["all_exited"] != true {
		return nil, Error("NATIVE_TERMINAL_INVALID")
	}
	guardianPath := filepath.Join(control, "guardian-result.json")
	groupStop := false
	if terminal == nil {
		if missing(guardianPath) {
			groupStop = true
		} else {
			raw, e := ReadBytes(guardianPath, ControlLimit)
			if e != nil {
				return nil, e
			}
			groupStop = len(raw) == 0
		}
	}
	children := []Object{}
	terminalChildren := []Object{}
	if terminal == nil {
		if groupStop {
			children, e = RecordedChildren(events, Int(watchdog, "pid"))
		} else {
			ready := firstEvent(events, "MONITOR_READY")
			if ready != nil {
				children, e = identities(ready["processes"])
			}
			if len(children) == 0 && e == nil {
				g, _, er := Read(guardianPath, ControlLimit)
				if er != nil {
					return nil, er
				}
				id, er := ProcessIdentity(Object{"pid": g["guardian_pid"], "start_abstime": g["guardian_start_abstime"]}, "guardian")
				if er != nil {
					return nil, er
				}
				children = []Object{id}
			}
		}
		if e != nil {
			return nil, e
		}
	} else {
		terminalChildren, e = identities(terminal["processes"])
		if e != nil {
			return nil, e
		}
		children, e = primaryIdentities(terminalChildren, watchdog, events)
		if e != nil {
			return nil, e
		}
		for _, v := range List(terminal, "processes") {
			m, ok := v.(Object)
			if !ok || m["exited"] != true {
				return nil, Error("NATIVE_TERMINAL_IDENTITIES_INVALID")
			}
		}
	}
	if !missing(startedPath) {
		started, _, e := Read(startedPath, ControlLimit)
		if e != nil {
			return nil, e
		}
		if e = Bound(started, req); e != nil || !Equal(started["watchdog"], watchdog) {
			return nil, Error("NATIVE_START_BINDING_CHANGED")
		}
	} else if len(children) > 0 || !groupStop && (terminal == nil || terminal["transfer_allowed"] != false) {
		return nil, Error("NATIVE_START_AUTHORIZATION_MISSING")
	}
	var guardian Object
	if len(children) > 0 && !groupStop {
		var death *bool
		if terminal != nil {
			v := false
			death = &v
		}
		guardian, e = GuardianResult(control, watchdog, children, death)
		if e != nil {
			return nil, e
		}
	}
	ids := append([]Object{watchdog}, children...)
	if terminal != nil {
		ids = append([]Object{watchdog}, terminalChildren...)
	}
	known := map[string]bool{}
	for _, id := range ids {
		known[identityKey(id)] = true
	}
	if guardian != nil {
		for _, v := range List(guardian, "targets") {
			m, _ := v.(Object)
			id, e := ProcessIdentity(m, "guardian_target")
			if e != nil {
				return nil, e
			}
			if !known[identityKey(id)] {
				ids = append(ids, id)
				known[identityKey(id)] = true
			}
		}
	}
	var after []any
	for {
		after = ReadbackAll(ids)
		if AllExited(after) {
			break
		}
		if !time.Now().Before(until) {
			return nil, Error("NATIVE_PROCESS_STILL_ACTIVE")
		}
		time.Sleep(50 * time.Millisecond)
	}
	absent, e := ServiceAbsent(target)
	if e != nil {
		return nil, e
	}
	if !absent {
		_ = CommandResult(context.Background(), []string{"/bin/launchctl", "bootout", target}, 5*time.Second)
	}
	absent, e = ServiceAbsent(target)
	if e != nil || !absent {
		return nil, Error("NATIVE_SERVICE_STILL_PRESENT")
	}
	if groupStop {
		empty, e := GroupEmpty(int(Int(watchdog, "pid")))
		if e != nil || !empty {
			return nil, Error("NATIVE_GROUP_STILL_ACTIVE")
		}
	}
	kind := "recovered_native_terminal"
	if groupStop {
		kind = "recovered_native_group"
	} else if terminal == nil {
		kind = "recovered_native_guardian"
	}
	qemu := false
	for _, c := range children {
		qemu = qemu || Str(c, "role") == "vm"
	}
	for _, ev := range events {
		if Str(ev, "event") == "MONITOR_READY" {
			for _, v := range List(ev, "processes") {
				m, _ := v.(Object)
				qemu = qemu || Str(m, "role") == "vm"
			}
		}
	}
	qemu = qemu || guardian != nil && len(List(guardian, "targets")) > 0
	report := Object{"schema": 1, "kind": kind, "passed": false, "control_directory": control, "control_directory_identity": DirectoryIdentity(info), "target": target, "qemu_started": qemu, "terminal": nullableObject(terminal), "broker_events": []any{}, "events": objectsAny(events), "cleanup_after": after, "cleanup_all_exited": true, "temporary_service_absent": true, "guardian_result_verified": guardian != nil, "native_intent_sha256": planSHA, "binary_sha256": plan["native_binary_sha256"], "native_source_sha256": plan["native_source_sha256"]}
	if groupStop {
		report["process_group_empty"] = true
	}
	if guardian != nil {
		report["guardian_result"] = guardian
	}
	watchdogOut := filepath.Join(out, "watchdog")
	if e = os.Mkdir(watchdogOut, 0700); e != nil && !os.IsExist(e) {
		return nil, e
	}
	if _, e = Owned(watchdogOut, unix.S_IFDIR, 0700); e != nil {
		return nil, e
	}
	for _, name := range []string{"config.json", "watchdog.plist", "events.jsonl", "guardian-result.json"} {
		if !missing(filepath.Join(control, name)) {
			b, e := ReadBytes(filepath.Join(control, name), 4<<20)
			if e != nil {
				return nil, e
			}
			if e = SaveCopy(filepath.Join(watchdogOut, name), b); e != nil {
				return nil, e
			}
		}
	}
	source, e := r.ProducerSource()
	if e != nil {
		return nil, e
	}
	b, e := Encoded(source)
	if e != nil {
		return nil, e
	}
	if e = SaveCopy(filepath.Join(watchdogOut, "producer-source.json"), b); e != nil {
		return nil, e
	}
	b, e = os.ReadFile(r.NativeSource)
	if e != nil || len(b) > 1<<20 {
		return nil, Error("NATIVE_SOURCE_LIMIT")
	}
	if e = SaveCopy(filepath.Join(watchdogOut, "integrated_watchdog.m"), b); e != nil {
		return nil, e
	}
	if e = SyncDirectory(watchdogOut); e != nil {
		return nil, e
	}
	if _, e = WriteOnce(filepath.Join(watchdogOut, "results.json"), report); e != nil {
		return nil, e
	}
	return report, nil
}
func identityIf(exists bool, s unix.Stat_t) Object {
	if !exists {
		return nil
	}
	return DirectoryIdentity(s)
}
func (r *Runtime) NativeChecks(native Object) (string, error) {
	terminal := Map(native, "terminal")
	kind := Str(native, "kind")
	if kind == "qemu_watchdog_death" {
		if e := r.validateDeathFixtureProof(native); e != nil {
			return "", e
		}
	}
	death := (kind == "recovered_native_guardian" || kind == "recovered_native_group" || kind == "qemu_watchdog_death") && terminal == nil
	if !death && (terminal == nil || terminal["all_exited"] != true) || native["cleanup_all_exited"] != true || native["temporary_service_absent"] != true || native["emergency_owned_cleanup"] == true {
		return "", Error("NATIVE_STOP_UNCONFIRMED")
	}
	control := Str(native, "control_directory")
	target := Str(native, "target")
	if !controlPattern.MatchString(control) || target != launchTarget(control) {
		return "", Error("NATIVE_SERVICE_SCOPE_INVALID")
	}
	absent, e := ServiceAbsent(target)
	if e != nil || !absent {
		return "", Error("NATIVE_SERVICE_STILL_PRESENT")
	}
	rows := List(native, "cleanup_after")
	if len(rows) == 0 || len(rows) > 129 {
		return "", Error("NATIVE_IDENTITY_PROOF_INVALID")
	}
	for _, row := range rows {
		m, ok := row.(Object)
		if !ok {
			return "", Error("NATIVE_IDENTITY_PROOF_INVALID")
		}
		id, e := ProcessIdentity(Map(m, "identity"), "")
		if e != nil || m["same_identity_live"] != false || IdentityReadback(id)["same_identity_live"] != false {
			return "", Error("NATIVE_IDENTITY_STILL_ACTIVE")
		}
	}
	if kind == "recovered_native_group" {
		events := objectsFromList(native["events"])
		starts := []Object{}
		for _, v := range events {
			if Str(v, "event") == "WATCHDOG_STARTED" {
				starts = append(starts, v)
			}
		}
		if len(starts) != 1 {
			return "", Error("NATIVE_GROUP_IDENTITIES_INVALID")
		}
		watchdog, e := ProcessIdentity(starts[0], "watchdog")
		if e != nil {
			return "", e
		}
		children, e := RecordedChildren(events, Int(watchdog, "pid"))
		if e != nil {
			return "", e
		}
		expected := append([]Object{watchdog}, children...)
		if terminal != nil || native["process_group_empty"] != true || native["guardian_result_verified"] != false || len(rows) > 4 || len(rows) != len(expected) {
			return "", Error("NATIVE_GROUP_STOP_UNCONFIRMED")
		}
		for i, row := range rows {
			if !Equal(row.(Object)["identity"], expected[i]) {
				return "", Error("NATIVE_GROUP_IDENTITIES_INVALID")
			}
		}
		empty, e := GroupEmpty(int(Int(watchdog, "pid")))
		if e != nil || !empty {
			return "", Error("NATIVE_GROUP_STOP_UNCONFIRMED")
		}
		return "native_stopped_group", nil
	}
	if native["guardian_result_verified"] == true {
		if death {
			g := Map(native, "guardian_result")
			if g == nil || g["parent_pipe_eof"] != true || !isBool(g["parent_same_identity_live_at_eof"]) || !isBool(g["parent_stop_intent_seen"]) || g["all_targets_exited"] != true || g["monitor_failed"] != false {
				return "", Error("NATIVE_GUARDIAN_DEATH_UNCONFIRMED")
			}
		}
		return "native_guardian", nil
	}
	events := append(objectsFromList(native["broker_events"]), objectsFromList(native["events"])...)
	if native["qemu_started"] != false || terminal == nil || len(List(terminal, "processes")) != 0 || terminal["transfer_allowed"] != false || len(rows) != 1 || Str(Map(rows[0].(Object), "identity"), "role") != "watchdog" {
		return "", Error("NATIVE_UNSTARTED_PROOF_INVALID")
	}
	for _, v := range events {
		if Str(v, "event") == "GUARDIAN_READY" || Str(v, "event") == "MONITOR_READY" {
			return "", Error("NATIVE_UNSTARTED_PROOF_INVALID")
		}
	}
	return "native_unstarted", nil
}
func (r *Runtime) SyncStopProof(out, run string, native Object) error {
	control := Str(native, "control_directory")
	identity := Map(native, "control_directory_identity")
	s, e := Owned(control, unix.S_IFDIR, 0700)
	if e != nil || !SameDirectory(s, identity) {
		return Error("NATIVE_CONTROL_IDENTITY_CHANGED")
	}
	watchdog := filepath.Join(out, "watchdog")
	for _, name := range []string{"config.json", "watchdog.plist", "events.jsonl"} {
		original, e := ReadBytes(filepath.Join(control, name), 4<<20)
		if e != nil {
			return e
		}
		copied, e := ReadBytes(filepath.Join(watchdog, name), 4<<20)
		if e != nil || HashBytes(original) != HashBytes(copied) {
			return Error("NATIVE_PROOF_COPY_MISMATCH")
		}
	}
	names := []string{"results.json", "config.json", "watchdog.plist", "events.jsonl", "producer-source.json", "integrated_watchdog.m"}
	if native["guardian_result_verified"] == true {
		a, _, e := Read(filepath.Join(control, "guardian-result.json"), 4<<20)
		if e != nil {
			return e
		}
		b, _, e := Read(filepath.Join(watchdog, "guardian-result.json"), 4<<20)
		if e != nil || !Equal(a, b) || !Equal(a, native["guardian_result"]) {
			return Error("GUARDIAN_PROOF_COPY_MISMATCH")
		}
		names = append(names, "guardian-result.json")
	}
	for _, name := range names {
		path := filepath.Join(watchdog, name)
		fd, e := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&07777 != 0600 || info.Size > 16<<20 {
			unix.Close(fd)
			return Error("NATIVE_PROOF_INVALID")
		}
		e = unix.Fsync(fd)
		unix.Close(fd)
		if e != nil {
			return e
		}
	}
	if e = SyncDirectory(watchdog); e != nil {
		return e
	}
	exchangeLimit := ControlLimit
	config, _, e := Read(filepath.Join(watchdog, "config.json"), ControlLimit)
	if e != nil {
		return e
	}
	if fixtureAllowed(Str(config, "fixture")) {
		exchangeLimit = 4 << 20
	}
	for _, name := range []string{"prepared.json", "exchange.json"} {
		source := filepath.Join(run, name)
		dest := filepath.Join(out, name)
		if !missing(source) && missing(dest) {
			limit := ControlLimit
			if name == "prepared.json" && Str(config, "owner_kind") == "update" && Str(config, "fixture") == "product-update" {
				limit = 1 << 20
			}
			if name == "exchange.json" {
				limit = exchangeLimit
			}
			b, e := ReadBytes(source, limit)
			if e != nil {
				return e
			}
			if e = create(dest, b, 0600); e != nil {
				return e
			}
		}
	}
	return SyncDirectory(out)
}
