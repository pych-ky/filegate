package verification

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"filegate.local/filegate/internal/hostvm"
)

type vmWindow struct{ file, marker, insert string }

func vmCheckpointSource(mode, marker string) string {
	return `
func verificationCheckpoint(phase,out,run string,extra Object) {
 if phase!=` + string(Encoded(mode)) + ` { return }
 for _,arg:=range os.Args[1:] { if arg=="--recover" { return } }
 current,e:=NativeIdentity(os.Getpid()); if e!=nil||current==nil { os.Exit(93) }
 parent,e:=NativeIdentity(os.Getppid()); if e!=nil||parent==nil { os.Exit(93) }
 value:=Object{"schema":1,"mode":phase,"identity":current,"parent":parent,"output_directory":out,"run_directory":run}
 for k,v:=range extra { value[k]=v }
 if out!="" {
   if plan,_,e:=Read(filepath.Join(out,"native-intent.json"),ControlLimit);e==nil {
     value["control_directory"]=plan["control_directory"];value["run_directory"]=Map(plan,"config")["run_directory"]
     if events,e:=NativeEvents(Str(plan,"control_directory"));e==nil {if first:=firstEvent(events,"WATCHDOG_STARTED");first!=nil {id,e:=ProcessIdentity(first,"watchdog");if e!=nil{os.Exit(93)};value["watchdog"]=id}}
   }
 }
 if context,_,e:=Read(` + string(Encoded(marker+".context")) + `,ControlLimit);e==nil {value["producer_identity"]=context["producer_identity"];value["broker_identity"]=context["broker_identity"];parent=Map(context,"broker_identity")}
 if phase=="watchdog-death"||phase=="pre-guardian-death" {id:=Map(value,"watchdog");if id==nil||signalOwned(id,syscall.SIGKILL)!=nil {os.Exit(93)};value["watchdog_sigkill"]=true}
 if _,e=WriteNew(` + string(Encoded(marker)) + `,value);e!=nil {os.Exit(93)}
 if phase=="prepare-cancel"||phase=="cleanup" {
   for { if _,e:=os.Stat(` + string(Encoded(marker+".release")) + `);e==nil{return};time.Sleep(10*time.Millisecond) }
 }
 for IdentityReadback(Object{"pid":parent["pid"],"start_abstime":parent["start_abstime"]})["same_identity_live"]!=false {time.Sleep(10*time.Millisecond)}
 if phase=="after-start-live" {for {if _,e:=os.Stat(` + string(Encoded(marker+".release")) + `);e==nil{break};time.Sleep(10*time.Millisecond)}}
 os.Exit(0)
}
func verificationPreviousBoot(out string) {
 if _,e:=os.Stat(` + string(Encoded(marker+".previous-boot")) + `);e!=nil{return}
 if _,e:=os.Stat(` + string(Encoded(marker+".boot-injection.json")) + `);e==nil{return}
 path:=filepath.Join(out,"native-intent.json");value,before,e:=Read(path,ControlLimit);if e!=nil{panic(e)};boot,e:=BootUUID();if e!=nil||Str(value,"boot_session_uuid")!=boot {panic("FIXTURE_PREVIOUS_BOOT_SCOPE_INVALID")}
 random,e:=RandomPath("");if e!=nil{panic(e)};hex:=filepath.Base(random);previous:=hex[:8]+"-"+hex[8:12]+"-"+hex[12:16]+"-"+hex[16:20]+"-"+hex[20:];if previous==boot{panic("FIXTURE_PREVIOUS_BOOT_COLLISION")};value["boot_session_uuid"]=previous;after,e:=Encoded(value);if e!=nil{panic(e)};temporary:=filepath.Join(out,"verification-native-intent.json");if e=create(temporary,after,0600);e!=nil{panic(e)};if e=os.Rename(temporary,path);e!=nil{panic(e)};if e=SyncDirectory(out);e!=nil{panic(e)}
 if _,e=WriteNew(` + string(Encoded(marker+".boot-injection.json")) + `,Object{"fixture_only":true,"real_os_restart":false,"actual_boot_uuid":boot,"injected_previous_boot_uuid":previous,"before_sha256":HashBytes(before),"after_sha256":HashBytes(after)});e!=nil{panic(e)}
}
`
}
func vmRuntimeWindow(mode string) vmWindow {
	switch mode {
	case "after-start", "after-start-live":
		return vmWindow{"scan.go", "\treq, e := ReadScanRequest(o.request, o.recover)", "verificationCheckpoint(" + string(Encoded(mode)) + ",o.out,\"\",nil)"}
	case "before-owner", "unknown-output":
		return vmWindow{"scan.go", "\tif e = validateOutput(o.out); e != nil {", "verificationCheckpoint(" + string(Encoded(mode)) + ",o.out,\"\",nil)"}
	case "resource-intent":
		return vmWindow{"scan.go", "\trunner, e := RunnerLock(o.out)", "verificationCheckpoint(\"resource-intent\",o.out,\"\",nil)"}
	case "slot-before":
		return vmWindow{"slot.go", "\tif e = os.Link(pending, intent); e != nil {", "verificationCheckpoint(\"slot-before\",out,Str(resources,\"run_directory\"),Object{\"slot_pending\":pending,\"slot_intent\":intent})"}
	case "slot-after":
		return vmWindow{"slot.go", "\tif e = SyncDirectory(r.State); e != nil {", "verificationCheckpoint(\"slot-after\",out,Str(resources,\"run_directory\"),Object{\"slot_pending\":pending,\"slot_intent\":intent})"}
	case "run-created", "nonempty-run":
		return vmWindow{"slot.go", "\treturn run, SyncDirectory(filepath.Dir(run))", "verificationCheckpoint(" + string(Encoded(mode)) + ",\"\",run,nil)"}
	case "prepare-owner-before":
		return vmWindow{"process.go", "\towner, ownerSHA, e := WriteOwnership(ownershipPath, cmd.Process.Pid, args)", "{fixtureGate,e:=NativeIdentity(cmd.Process.Pid);if e!=nil{return nil,e};verificationCheckpoint(\"prepare-owner-before\",filepath.Dir(ownershipPath),\"\",Object{\"gate_identity\":fixtureGate})}"}
	case "prepare-cancel":
		return vmWindow{"process.go", "\tfailure := any(nil)", "if filepath.Base(ownershipPath)==\"preparation-owner.json\" {verificationCheckpoint(\"prepare-cancel\",filepath.Dir(ownershipPath),\"\",nil);select{case <-ctx.Done():case <-time.After(6*time.Second):return nil,Error(\"FIXTURE_CANCEL_NOT_OBSERVED\")}}"}
	case "cleanup":
		return vmWindow{"cleanup.go", "\tif e = reclaimDirectories(intent, rules); e != nil {", "verificationCheckpoint(\"cleanup\",out,\"\",nil)"}
	case "intent":
		return vmWindow{"control.go", "\tif e = os.Mkdir(control, 0700); e != nil {", "verificationCheckpoint(\"intent\",c.Out,Str(config,\"run_directory\"),Object{\"control_directory\":control})"}
	case "control-directory":
		return vmWindow{"control.go", "\tif e = SyncDirectory(filepath.Dir(control)); e != nil {", "verificationCheckpoint(\"control-directory\",c.Out,Str(config,\"run_directory\"),Object{\"control_directory\":control})"}
	case "config-partial":
		return vmWindow{"control.go", "\tif e = create(filepath.Join(control, \"config.json\"), configuration, 0600); e != nil {", "if e=create(filepath.Join(control,\"config.json\"),configuration[:len(configuration)/2],0600);e!=nil{return \"\",e};verificationCheckpoint(\"config-partial\",c.Out,Str(config,\"run_directory\"),Object{\"control_directory\":control,\"partial_config_bytes\":len(configuration)/2})"}
	case "bootstrap-owner-before":
		return vmWindow{"process.go", "\towner, ownerSHA, e := WriteOwnership(ownershipPath, cmd.Process.Pid, args)", "if filepath.Base(ownershipPath)==\"native-bootstrap-owner.json\" {gate,e:=NativeIdentity(cmd.Process.Pid);if e!=nil{return nil,e};verificationCheckpoint(\"bootstrap-owner-before\",filepath.Dir(ownershipPath),\"\",Object{\"gate_identity\":gate})}"}
	case "bootstrap-owner-after":
		return vmWindow{"process.go", "\tfailure := any(nil)", "if filepath.Base(ownershipPath)==\"native-bootstrap-owner.json\" {gate,e:=NativeIdentity(cmd.Process.Pid);if e!=nil{return nil,e};verificationCheckpoint(\"bootstrap-owner-after\",filepath.Dir(ownershipPath),\"\",Object{\"gate_identity\":gate})}"}
	case "bootstrap-complete":
		return vmWindow{"control.go", "\treturn result, e", "if e==nil {verificationCheckpoint(\"bootstrap-complete\",c.Out,\"\",nil)}"}
	case "native-start", "pre-guardian-death":
		return vmWindow{"control.go", "\tc.StartRecorded = true", "verificationCheckpoint(" + string(Encoded(mode)) + ",c.Out,\"\",Object{\"watchdog\":id})"}
	case "monitor-ready", "watchdog-death":
		return vmWindow{"scan.go", "\t\t\t\tmarked = true", "verificationCheckpoint(" + string(Encoded(mode)) + ",o.out,run,Object{\"processes\":ready[\"processes\"]})"}
	case "record-copy":
		return vmWindow{"control.go", "\tsource, e := c.Runtime.ProducerSource()", "verificationCheckpoint(\"record-copy\",c.Out,\"\",nil)"}
	case "results-pending":
		return vmWindow{"files.go", "\tif e = os.Link(pending, path); e != nil {", "if filepath.Base(path)==\"results.json\"&&filepath.Base(filepath.Dir(path))==\"watchdog\" {f,e:=os.OpenFile(pending,os.O_WRONLY|unix.O_NOFOLLOW,0);if e!=nil{return \"\",e};if e=f.Truncate(int64(len(body)/2));e==nil{e=f.Sync()};f.Close();if e!=nil{return \"\",e};verificationCheckpoint(\"results-pending\",filepath.Dir(filepath.Dir(path)),\"\",Object{\"partial_result_bytes\":len(body)/2})}"}
	case "unknown-control":
		return vmWindow{"control.go", "\tc.Directory = control", "verificationCheckpoint(\"unknown-control\",c.Out,Str(config,\"run_directory\"),Object{\"control_directory\":control})"}
	case "bootstrap-dispatch", "bootstrap-dispatch-unknown", "bootstrap-dispatch-absent":
		return vmWindow{"process.go", "\tif e = syscall.Exec(rest[0], rest, os.Environ()); e != nil {", "if dispatch!=\"\" {verificationCheckpoint(" + string(Encoded(mode)) + ",filepath.Dir(dispatch),\"\",nil)}"}
	}
	panic(Failure{"unknown_runtime_fixture_window:" + mode})
}
func vmReplaceFirst(body, marker, replacement string) string {
	if !strings.Contains(body, marker) {
		panic(Failure{"fixture_marker_missing:" + marker})
	}
	return strings.Replace(body, marker, replacement, 1)
}
func vmFixtureWorkspace(h *Harness, mode, marker string) string {
	base := h.Workspace
	target := filepath.Join(h.Out, "runtime-"+mode)
	Must(os.Mkdir(target, 0700))
	receiptPath := filepath.Join(base, "experiments/vm/evidence/build.json")
	receipt := ReadJSON(receiptPath)
	pins := map[string]string{}
	for _, group := range []struct{ name, base string }{{"product_sources_sha256", base}, {"sources_sha256", filepath.Join(base, "experiments/vm")}, {"external_sources_sha256", filepath.Join(base, "experiments")}, {"artifacts", filepath.Join(base, "experiments/vm")}} {
		for name, hash := range Map(receipt, group.name) {
			expected, ok := hash.(string)
			h.Check("fixture_source_hash", ok)
			path := filepath.Clean(filepath.Join(group.base, name))
			relative, err := filepath.Rel(base, path)
			Must(err)
			h.Check("fixture_source_scope", filepath.IsLocal(relative))
			pins[relative] = expected
		}
	}
	for _, name := range []string{".build/filegate-vm", ".build/filegate-update", "experiments/host/.build/integrated-watchdog"} {
		pins[name] = FileDigest(filepath.Join(base, name))
	}
	for relative, hash := range pins {
		source, destination := filepath.Join(base, relative), filepath.Join(target, relative)
		h.Check("fixture_clone_source_"+relative, FileDigest(source) == hash)
		Must(os.MkdirAll(filepath.Dir(destination), 0700))
		Must(vmCloneFile(source, destination))
		info, err := os.Stat(source)
		Must(err)
		Must(os.Chmod(destination, info.Mode().Perm()))
		h.Check("fixture_clone_hash_"+relative, FileDigest(destination) == hash)
	}
	window := vmRuntimeWindow(mode)
	sourcePath := filepath.Join(target, "internal/hostvm", window.file)
	body := string(Read(sourcePath))
	body = vmReplaceFirst(body, window.marker, "\t"+window.insert+"\n"+window.marker)
	Write(sourcePath, []byte(body))
	processPath := filepath.Join(target, "internal/hostvm/process.go")
	Write(processPath, append(Read(processPath), []byte(vmCheckpointSource(mode, marker))...))
	if strings.HasPrefix(mode, "bootstrap-dispatch") {
		control := filepath.Join(target, "internal/hostvm/control.go")
		source := string(Read(control))
		find := "\tresult, e := ControlledCommand(ctx,"
		insert := "\tproducer,e:=NativeIdentity(os.Getpid());if e!=nil{return nil,e};broker,e:=NativeIdentity(os.Getppid());if e!=nil{return nil,e};if _,e=WriteNew(" + string(Encoded(marker+".context")) + ",Object{\"producer_identity\":producer,\"broker_identity\":broker});e!=nil{return nil,e}\n"
		source = vmReplaceFirst(source, find, insert+find)
		Write(control, []byte(source))
		recovery := filepath.Join(target, "internal/hostvm/native_recovery.go")
		source = string(Read(recovery))
		find = "func (r *Runtime) RecoverNative(out string, req Object, profile Profile) (Object, error) {"
		source = ReplaceOnce(source, find, find+"\n\tverificationPreviousBoot(out)")
		Write(recovery, []byte(source))
	}
	builds := []Object{}
	for _, name := range []string{"filegate-vm", "filegate-update"} {
		binary := filepath.Join(target, ".build", name)
		Must(os.Chmod(binary, 0700))
		args := []string{"/usr/bin/env", "CGO_ENABLED=1", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/" + name}
		built := Execute(target, args, nil, 3*time.Minute)
		Write(filepath.Join(h.Out, mode+"-"+name+"-build.log"), append(built.Stdout, built.Stderr...))
		h.Check(mode+"_"+name+"_build", built.ExitCode == 0)
		Must(os.Chmod(binary, 0500))
		builds = append(builds, Object{"argv": args, "exit_code": built.ExitCode, "sha256": FileDigest(binary)})
		field := "host_runner"
		if name == "filegate-update" {
			field = "host_update_runner"
		}
		receipt[field] = Object{"path": binary, "sha256": FileDigest(binary)}
	}
	for _, group := range []struct{ name, base string }{{"product_sources_sha256", target}, {"sources_sha256", filepath.Join(target, "experiments/vm")}, {"external_sources_sha256", filepath.Join(target, "experiments")}, {"artifacts", filepath.Join(target, "experiments/vm")}} {
		for name := range Map(receipt, group.name) {
			Map(receipt, group.name)[name] = FileDigest(filepath.Join(group.base, name))
		}
	}
	if helper := Map(receipt, "product_helper"); helper != nil {
		helper["sources_sha256"] = receipt["product_sources_sha256"]
	}
	receipt["verification_overlay"] = Object{"fixture_only": true, "mode": mode, "marker": marker, "builds": builds, "original_vm_build_sha256": FileDigest(receiptPath)}
	WriteJSON(filepath.Join(target, "experiments/vm/evidence/build.json"), receipt)
	h.Record["runtime_fixture_"+mode] = Object{"workspace": target, "builds": builds, "vm_build_sha256": FileDigest(filepath.Join(target, "experiments/vm/evidence/build.json")), "guard_changes": "checkpoint insertion only; native binary/boot/base/definitions unchanged"}
	return target
}
func vmBrokerCrashOverlay(h *Harness, name, marker string) string {
	path := filepath.Join(h.Root, "internal/broker/runtime.go")
	source := string(Read(path))
	replacement := "\terr = cmd.Start()\n\tif err==nil {go func(){for deadline:=time.Now().Add(70*time.Second);time.Now().Before(deadline); {if _,e:=os.Stat(" + string(Encoded(marker)) + ");e==nil {os.Exit(91)};time.Sleep(10*time.Millisecond)};os.Exit(92)}()}"
	binary := filepath.Join(h.Out, "filegate-crash-"+name)
	BuildOverlay(h, "crash-"+name, binary, map[string]string{path: ReplaceOnce(source, "\terr = cmd.Start()", replacement)})
	return binary
}
func vmWaitBrokerCrash(h *Harness, name string) {
	end := time.Now().Add(75 * time.Second)
	for time.Now().Before(end) {
		if !h.ServiceAlive() {
			h.Check(name+"_broker_crashed_at_selected_window", h.Process.ProcessState.ExitCode() == 91)
			h.Stop(true)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.Check(name+"_broker_crash_timeout", false)
}
func vmStartupState(s *vmSuite, name string) (Object, string) {
	h := s.h
	rows := vmRows(h, "SELECT data FROM jobs")
	h.Check(name+"_single_job", len(rows) == 1)
	job := Map(rows[0], "data")
	state := s.database(job)
	state["job"] = job
	directory := filepath.Join(h.Data, "runtime", Str(job, "attempt_id"))
	WriteJSON(filepath.Join(h.Out, name+".json"), state)
	return state, directory
}
func vmWaitIdentityExit(h *Harness, name string, id Object, timeout time.Duration) {
	if id == nil {
		return
	}
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if hostvm.IdentityReadback(id)["same_identity_live"] == false {
			h.Check(name, true)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.Check(name, false)
}
