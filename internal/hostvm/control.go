package hostvm

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func PlistBytes(control, binary string) []byte {
	escape := func(s string) string { var b bytes.Buffer; _ = xml.EscapeText(&b, []byte(s)); return b.String() }
	return []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>AbandonProcessGroup</key><false/><key>KeepAlive</key><false/><key>Label</key><string>com.filegate.stage0.integrated." + escape(filepath.Base(control)) + "</string><key>ProcessType</key><string>Background</string><key>ProgramArguments</key><array><string>" + escape(binary) + "</string><string>" + escape(filepath.Join(control, "config.json")) + "</string></array><key>RunAtLoad</key><true/><key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict></dict></plist>\n")
}

type Control struct {
	Runtime           *Runtime
	Out               string
	Requested         Object
	Profile           Profile
	ProducerFD        int
	Directory         string
	StartRecorded     bool
	StartDeniedReason string
}

func (r *Runtime) NativeControl(out string, req Object, profile Profile, producerFD int) (*Control, error) {
	if profile != ScanProfile && profile != UpdateProfile || producerFD != 3 {
		return nil, Error("NATIVE_PROFILE_INVALID")
	}
	return &Control{Runtime: r, Out: out, Requested: req, Profile: profile, ProducerFD: producerFD}, nil
}
func (c *Control) Prepare(config Object, started uint64) (string, error) {
	control, e := RandomPath("fgw-")
	if e != nil {
		return "", e
	}
	if !missing(control) {
		return "", Error("NATIVE_CONTROL_ALREADY_EXISTS")
	}
	config["schema"] = 1
	config["control_directory"] = control
	config["owner_kind"] = c.Profile.OwnerKind
	config["continuous_start_ns"] = started
	config["continuous_deadline_ns"] = started + uint64(c.Profile.TimeoutSeconds)*1e9
	boot, e := BootUUID()
	if e != nil {
		return "", e
	}
	binary, e := HashFile(c.Runtime.NativeBinary)
	if e != nil {
		return "", e
	}
	source, e := HashFile(c.Runtime.NativeSource)
	if e != nil {
		return "", e
	}
	value := Merge(Binding(c.Requested), Object{"schema": 2, "control_directory": control, "config": config, "boot_session_uuid": boot, "native_binary_sha256": binary, "native_source_sha256": source})
	configuration, e := Encoded(config)
	if e != nil {
		return "", e
	}
	plist := PlistBytes(control, c.Runtime.NativeBinary)
	body, e := Encoded(value)
	if e != nil || len(body) > int(ControlLimit) || len(configuration) > int(ControlLimit) || len(plist) > int(ControlLimit) {
		return "", Error("NATIVE_CONFIGURATION_LIMIT")
	}
	if _, e = WriteNew(filepath.Join(c.Out, "native-intent.json"), value); e != nil {
		return "", e
	}
	if e = os.Mkdir(control, 0700); e != nil {
		return "", e
	}
	if e = SyncDirectory(filepath.Dir(control)); e != nil {
		return "", e
	}
	info, e := Owned(control, unix.S_IFDIR, 0700)
	if e != nil {
		return "", e
	}
	if _, e = WriteNew(filepath.Join(c.Out, "native-directory.json"), Merge(Binding(c.Requested), DirectoryIdentity(info))); e != nil {
		return "", e
	}
	if e = create(filepath.Join(control, "config.json"), configuration, 0600); e != nil {
		return "", e
	}
	if e = create(filepath.Join(control, "watchdog.plist"), plist, 0600); e != nil {
		return "", e
	}
	if e = SyncDirectory(control); e != nil {
		return "", e
	}
	c.Directory = control
	return control, nil
}
func (c *Control) Bootstrap(ctx context.Context) (Object, error) {
	if !controlPattern.MatchString(c.Directory) {
		return nil, Error("NATIVE_CONTROL_SCOPE_INVALID")
	}
	if e := SyncDirectory(c.Out); e != nil {
		return nil, e
	}
	result, e := ControlledCommand(ctx, []string{"/bin/launchctl", "bootstrap", "gui/" + itoa(os.Getuid()), filepath.Join(c.Directory, "watchdog.plist")}, 15, filepath.Join(c.Out, "native-bootstrap-owner.json"), filepath.Join(c.Runtime.Root, "experiments/host"), c.ProducerFD, filepath.Join(c.Out, "native-bootstrap-dispatched.json"))
	if e != nil {
		return result, e
	}
	_, e = WriteNew(filepath.Join(c.Out, "native-bootstrap-result.json"), result)
	return result, e
}
func (c *Control) AuthorizeStart(events []Object) (bool, error) {
	if c.StartRecorded {
		return true, nil
	}
	var first Object
	for _, v := range events {
		if Str(v, "event") == "WATCHDOG_STARTED" {
			first = v
			break
		}
	}
	if first == nil {
		return false, nil
	}
	id, e := ProcessIdentity(first, "watchdog")
	if e != nil || !Equal(first["process_group"], id["pid"]) || IdentityReadback(id)["same_identity_live"] != true {
		return false, Error("NATIVE_START_IDENTITY_INVALID")
	}
	if c.Profile == ScanProfile {
		if e = c.Runtime.FreshBeforeStart(c.Requested); e != nil {
			c.StartDeniedReason = "DATABASE_STALE"
			return false, nil
		}
	}
	if _, e = WriteNew(filepath.Join(c.Out, "native-start.json"), Merge(Binding(c.Requested), Object{"watchdog": id})); e != nil {
		return false, e
	}
	c.StartRecorded = true
	return true, nil
}
func (r *Runtime) ProducerSource() (Object, error) {
	receipt, e := r.VerifyBuild()
	if e != nil {
		return nil, e
	}
	source := Map(receipt, "product_sources_sha256")
	actual, e := HashFile(r.Executable)
	if e != nil {
		return nil, e
	}
	runner := Map(receipt, "host_runner")
	if filepath.Base(r.Executable) == "filegate-update" {
		runner = Map(receipt, "host_update_runner")
	}
	if Str(runner, "path") != r.Executable || Str(runner, "sha256") != actual {
		return nil, Error("PRODUCER_BINARY_CHANGED")
	}
	receiptPath := filepath.Join(r.VM, "evidence/build.json")
	sha, e := HashFile(receiptPath)
	if e != nil {
		return nil, e
	}
	return Object{"schema": 1, "runner": r.Executable, "runner_sha256": actual, "vm_build_path": receiptPath, "vm_build_sha256": sha, "source_sha256": source}, nil
}
func (c *Control) Record(destination string, report Object) error {
	body, e := Encoded(report)
	if e != nil || len(body) > 16<<20 {
		return Error("NATIVE_RESULT_LIMIT")
	}
	for _, name := range []string{"config.json", "watchdog.plist", "events.jsonl", "guardian-result.json"} {
		path := filepath.Join(c.Directory, name)
		if !missing(path) {
			body, e := ReadBytes(path, 4<<20)
			if e != nil {
				return e
			}
			if e = SaveCopy(filepath.Join(destination, name), body); e != nil {
				return e
			}
		}
	}
	source, e := c.Runtime.ProducerSource()
	if e != nil {
		return e
	}
	sourceBody, e := Encoded(source)
	if e != nil || len(sourceBody) > 1<<20 {
		return Error("NATIVE_SOURCE_LIMIT")
	}
	if e = SaveCopy(filepath.Join(destination, "producer-source.json"), sourceBody); e != nil {
		return e
	}
	native, e := os.ReadFile(c.Runtime.NativeSource)
	if e != nil || len(native) > 1<<20 {
		return Error("NATIVE_SOURCE_LIMIT")
	}
	if e = SaveCopy(filepath.Join(destination, "integrated_watchdog.m"), native); e != nil {
		return e
	}
	if e = SyncDirectory(destination); e != nil {
		return e
	}
	name := "results.json"
	if _, e = c.Runtime.NativeChecks(report); e != nil {
		name = "launch-result.json"
	}
	_, e = WriteNew(filepath.Join(destination, name), report)
	return e
}
func (r *Runtime) ReadPlan(out string, req Object, profile Profile) (Object, string, string, error) {
	if profile != ScanProfile && profile != UpdateProfile {
		return nil, "", "", Error("NATIVE_PROFILE_INVALID")
	}
	plan, b, e := Read(filepath.Join(out, "native-intent.json"), ControlLimit)
	if e != nil {
		return nil, "", "", e
	}
	expected := Merge(Binding(req), Object{"schema": 2})
	for k, v := range expected {
		if !Equal(plan[k], v) {
			return nil, "", "", Error("NATIVE_INTENT_MISMATCH")
		}
	}
	if !Fields(plan, "schema", "job_id", "attempt_id", "input_sha256", "byte_size", "control_directory", "config", "boot_session_uuid", "native_binary_sha256", "native_source_sha256") || !bootPattern.MatchString(Str(plan, "boot_session_uuid")) {
		return nil, "", "", Error("NATIVE_INTENT_MISMATCH")
	}
	binary, e := HashFile(r.NativeBinary)
	if e != nil {
		return nil, "", "", e
	}
	source, e := HashFile(r.NativeSource)
	if e != nil {
		return nil, "", "", e
	}
	if Str(plan, "native_binary_sha256") != binary || Str(plan, "native_source_sha256") != source {
		return nil, "", "", Error("NATIVE_INTENT_MISMATCH")
	}
	control := Str(plan, "control_directory")
	prep, _, e := Read(filepath.Join(out, "preparation-intent.json"), ControlLimit)
	if e != nil {
		return nil, "", "", e
	}
	config := Map(plan, "config")
	start, ok := Uint(config, "continuous_start_ns")
	end, ok2 := Uint(config, "continuous_deadline_ns")
	if !controlPattern.MatchString(control) || Str(config, "control_directory") != control || Str(config, "mode") != "qemu" || Str(config, "run_directory") != Str(prep, "run_directory") || Int(config, "schema") != 1 || Str(config, "owner_kind") != profile.OwnerKind || !ok || !ok2 || end < start || end-start != uint64(profile.TimeoutSeconds)*1e9 {
		return nil, "", "", Error("NATIVE_INTENT_SCOPE_INVALID")
	}
	return plan, control, HashBytes(b), nil
}
func ServiceAbsent(target string) (bool, error) {
	if !regexpService(target) {
		return false, Error("NATIVE_SERVICE_SCOPE_INVALID")
	}
	result := CommandResult(context.Background(), []string{"/bin/launchctl", "print", target}, 5*time.Second)
	return Int(result, "exit_status") == 113 && stringsContains(Str(result, "stderr"), "Could not find service"), nil
}
func regexpService(target string) bool {
	prefix := "gui/" + itoa(os.Getuid()) + "/com.filegate.stage0.integrated."
	return len(target) > len(prefix) && target[:len(prefix)] == prefix && controlPattern.MatchString("/private/tmp/"+target[len(prefix):])
}
func stringsContains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
func CommandResult(ctx context.Context, args []string, timeout time.Duration) Object {
	child, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := execCommandContext(child, args)
	var stdout, stderr boundedWriter
	stdout.limit = 65536
	stderr.limit = 65536
	cmd.Stdout = &stdout
	if len(args) == 3 && args[0] == "/bin/launchctl" && args[1] == "print" {
		cmd.Stdout = io.Discard
	}
	cmd.Stderr = &stderr
	e := cmd.Run()
	status := 0
	if e != nil {
		status = exitStatus(e)
	}
	if child.Err() != nil {
		status = 124
	}
	out := string(stdout.body)
	err := string(stderr.body)
	if len(out) > 2048 {
		out = out[:2048]
	}
	if len(err) > 2048 {
		err = err[:2048]
	}
	return Object{"exit_status": status, "stdout": out, "stderr": err}
}
func launchTarget(control string) string {
	return fmt.Sprintf("gui/%d/com.filegate.stage0.integrated.%s", os.Getuid(), filepath.Base(control))
}
