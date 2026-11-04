package hostvm

import (
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"filegate.local/filegate/internal/vmbridge"
	"golang.org/x/sys/unix"
)

type scanOptions struct {
	request, out, proof, run, fixture string
	startupFD                         int
	recover, prepare, fixtureLocked   bool
}
type scanBroker struct {
	ctx                     context.Context
	cancel                  context.CancelFunc
	mu                      sync.Mutex
	last                    time.Time
	ready, accepted, closed bool
	received, monitored     chan struct{}
}

func newScanBroker(parent context.Context) *scanBroker {
	ctx, cancel := context.WithCancel(parent)
	b := &scanBroker{ctx: ctx, cancel: cancel, last: time.Now(), received: make(chan struct{}), monitored: make(chan struct{})}
	go b.receive()
	go func() {
		defer close(b.monitored)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.mu.Lock()
				late := time.Since(b.last) >= 5*time.Second
				b.mu.Unlock()
				if late {
					cancel()
					return
				}
			}
		}
	}()
	return b
}
func (b *scanBroker) receive() {
	defer close(b.received)
	pending := []byte{}
	for b.ctx.Err() == nil {
		fds := []unix.PollFd{{Fd: int32(os.Stdin.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		if _, e := unix.Poll(fds, 200); e != nil {
			if e == unix.EINTR {
				continue
			}
			break
		}
		if fds[0].Revents == 0 {
			continue
		}
		buffer := make([]byte, 64-len(pending))
		n, e := unix.Read(int(os.Stdin.Fd()), buffer)
		if e != nil || n == 0 {
			break
		}
		pending = append(pending, buffer[:n]...)
		for {
			index := bytes.IndexByte(pending, '\n')
			if index < 0 {
				break
			}
			line := string(pending[:index])
			pending = pending[index+1:]
			b.mu.Lock()
			valid := true
			switch {
			case line == "heartbeat":
				b.last = time.Now()
			case line == "report-accepted" && b.ready && !b.accepted:
				b.accepted = true
			default:
				valid = false
			}
			b.mu.Unlock()
			if !valid {
				b.cancel()
				return
			}
		}
		if len(pending) == 64 {
			break
		}
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if !closed {
		b.cancel()
	}
}
func (b *scanBroker) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cancel()
	<-b.received
	<-b.monitored
}
func (b *scanBroker) event(event Object) {
	body, e := Encoded(event)
	if e != nil {
		b.cancel()
		return
	}
	if _, e = os.Stdout.Write(body); e != nil {
		b.cancel()
	}
}
func (b *scanBroker) state() (bool, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ready, b.accepted
}
func (b *scanBroker) reportReady() { b.mu.Lock(); b.ready = true; b.mu.Unlock() }
func scanSummary(req Object) Object {
	return Object{"schema": 1, "job_id": req["job_id"], "attempt_id": req["attempt_id"], "passed": false, "report_sha256": nil, "report_accepted": false, "termination": Object{"all_exited": false, "identity_verified": false, "stop_failed": true, "reason_code": "INCOMPLETE_REQUIRED_CHECKS"}, "raw_reclaimed": false, "vm_slot_finalized": false, "reservation_charge_bytes": RawBytes, "native_evidence": nil, "product_enabled": false, "stage0_gate_passed": false}
}
func validateOutput(out string) error {
	actual, e := filepath.EvalSymlinks(out)
	if e != nil || actual != out || !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return Error("PRODUCT_OUTPUT_VOLUME_INVALID")
	}
	info, e := Owned(out, unix.S_IFDIR, 0700)
	if e != nil {
		return e
	}
	var temp unix.Stat_t
	if unix.Stat("/private/tmp", &temp) != nil || temp.Dev != info.Dev {
		return Error("PRODUCT_OUTPUT_VOLUME_INVALID")
	}
	return nil
}
func (r *Runtime) cleanScan(out string, req Object) (Object, string, error) {
	var native Object
	var e error
	if !missing(filepath.Join(out, "native-previous-boot.json")) {
		native, _, e = Read(filepath.Join(out, "native-previous-boot.json"), ControlLimit)
		if e == nil {
			e = r.ValidatePreviousBoot(out, req, native, ScanProfile)
		}
		if e != nil {
			return nil, "", e
		}
	} else if !missing(filepath.Join(out, "native-intent.json")) && missing(filepath.Join(out, "watchdog/results.json")) && missing(filepath.Join(out, "stop-proof.json")) {
		native, e = r.RecoverNative(out, req, ScanProfile)
		if e != nil {
			return nil, "", e
		}
		switch Str(native, "kind") {
		case "native_prelaunch":
			_, e = WriteOnce(filepath.Join(out, "native-recovery.json"), native)
		case "native_previous_boot":
			_, e = WriteOnce(filepath.Join(out, "native-previous-boot.json"), native)
		}
		if e != nil {
			return nil, "", e
		}
	}
	if !missing(filepath.Join(out, "watchdog/results.json")) && Str(native, "kind") != "native_previous_boot" {
		native, _, e = Read(filepath.Join(out, "watchdog/results.json"), 16<<20)
		if e != nil {
			return nil, "", e
		}
		if missing(filepath.Join(out, "stop-proof.json")) {
			if _, e = r.NativeChecks(native); e != nil {
				return nil, "", e
			}
			prep, _, e := Read(filepath.Join(out, "preparation-intent.json"), ControlLimit)
			if e != nil {
				return nil, "", e
			}
			if e = r.SyncStopProof(out, Str(prep, "run_directory"), native); e != nil {
				return nil, "", e
			}
		}
	}
	var evidence Object
	if !missing(filepath.Join(out, "resource-intent.json")) && missing(filepath.Join(out, "preparation-owner.json")) && native == nil {
		evidence, e = r.CleanupUnstartedResources(out, req)
	} else {
		evidence, e = r.Cleanup(out, req, native, ScanProfile, nil)
	}
	if e != nil {
		return nil, "", e
	}
	proof, _, e := Read(filepath.Join(out, "stop-proof.json"), ControlLimit)
	return evidence, Str(proof, "kind"), e
}
func (r *Runtime) recoverScan(out string, req, summary Object) error {
	producer, e := RecoveryLock(out)
	if e != nil {
		return e
	}
	if producer != nil {
		defer producer.Close()
	}
	runner, e := RunnerLock(out, true)
	if e != nil {
		return e
	}
	defer runner.Close()
	slot, e := r.RecoverySlot()
	if e != nil {
		return e
	}
	defer slot.Close()
	evidence, kind, e := r.cleanScan(out, req)
	if e != nil {
		return e
	}
	summary["raw_reclaimed"] = true
	summary["vm_slot_finalized"] = true
	summary["reservation_charge_bytes"] = 0
	summary["recovery_evidence"] = evidence
	summary["termination"] = Object{"all_exited": true, "identity_verified": true, "stop_failed": false, "reason_code": "INTERRUPTED"}
	if kind == "native_guardian" || kind == "native_stopped_group" {
		sha, e := DigestControl(filepath.Join(out, "watchdog/results.json"), 16<<20)
		if e != nil {
			return e
		}
		summary["native_evidence"] = Object{"path": "watchdog/results.json", "sha256": sha}
	}
	_, e = WriteOnce(filepath.Join(out, "recovery-results.json"), summary)
	return e
}
func (r *Runtime) executeScan(ctx context.Context, o scanOptions, req, summary Object) (returned error) {
	resources, e := r.ResourceIntent(o.out, req, ScanProfile)
	if e != nil {
		return e
	}
	broker := newScanBroker(ctx)
	defer broker.close()
	runner, e := RunnerLock(o.out)
	if e != nil {
		return e
	}
	defer runner.Close()
	slot, e := r.AcquireSlot(o.out, req, resources)
	if e != nil {
		return e
	}
	defer slot.Close()
	if e = CaptureSlot(o.out, slot, req); e != nil {
		return e
	}
	started, e := r.Clock()
	if e != nil {
		return e
	}
	run, e := CreateRun(resources)
	if e != nil {
		return e
	}
	runInfo, e := Owned(run, unix.S_IFDIR, 0700)
	if e != nil {
		return e
	}
	if _, e = WriteNew(filepath.Join(o.out, "preparation-intent.json"), Object{"schema": 1, "job_id": req["job_id"], "attempt_id": req["attempt_id"], "run_directory": run, "run_directory_identity": DirectoryIdentity(runInfo), "reservation_charge_bytes": RawBytes}); e != nil {
		return e
	}
	launched := false
	defer func() {
		if !launched && !missing(filepath.Join(o.out, "preparation-owner.json")) {
			evidence, e := r.Cleanup(o.out, req, nil, ScanProfile, nil)
			if e != nil {
				returned = e
				return
			}
			reason := "INCOMPLETE_REQUIRED_CHECKS"
			if Str(Map(summary, "termination"), "reason_code") == "DATABASE_STALE" {
				reason = "DATABASE_STALE"
			} else if broker.ctx.Err() != nil {
				reason = "INTERRUPTED"
			}
			summary["raw_reclaimed"] = true
			summary["vm_slot_finalized"] = true
			summary["reservation_charge_bytes"] = 0
			summary["recovery_evidence"] = evidence
			summary["termination"] = Object{"all_exited": true, "identity_verified": true, "stop_failed": false, "reason_code": reason}
		}
	}()
	broker.event(Object{"event": "PREPARING"})
	preparation, e := ControlledCommand(broker.ctx, []string{r.Executable, "--prepare", "--run-directory", run, "--request", o.request}, 120, filepath.Join(o.out, "preparation-owner.json"), r.Root, o.startupFD, "")
	if e != nil {
		return e
	}
	if _, e = WriteNew(filepath.Join(o.out, "preparation.json"), preparation); e != nil {
		return e
	}
	if Int(preparation, "exit_status") != 0 || preparation["failure"] != nil || broker.ctx.Err() != nil {
		return Error("PRODUCT_PREPARATION_FAILED")
	}
	raw, e := Owned(filepath.Join(run, "work.raw"), unix.S_IFREG, 0600)
	if e != nil || raw.Size != RawBytes {
		return Error("RAW_CAPACITY_INVALID")
	}
	if _, e = WriteNew(filepath.Join(o.out, "prepared-identity.json"), Object{"run_directory": run, "raw_identity": DirectoryIdentity(raw)}); e != nil {
		return e
	}
	requestPath := filepath.Join(run, "product-request.json")
	if _, e = WriteNew(requestPath, req); e != nil {
		return e
	}
	config, prepared, e := r.PreparedConfig(filepath.Join(run, "prepared.json"), o.proof, "product-inspect", requestPath)
	if e != nil {
		return e
	}
	if broker.ctx.Err() != nil {
		return Error("PRODUCT_CANCELLED")
	}
	if e = r.FreshBeforeStart(req); e != nil {
		Map(summary, "termination")["reason_code"] = "DATABASE_STALE"
		return e
	}
	broker.event(Object{"event": "INSPECTING", "raw_allocated_bytes": RawBytes})
	marked, acknowledged, progressSequence := false, false, 0
	progress := func(observation Object) error {
		err := func() error {
			if Bool(observation, "qemu_started") && !marked {
				ready := firstEvent(objectsFromList(observation["broker_events"]), "MONITOR_READY")
				if ready == nil {
					return Error("NATIVE_MONITOR_IDENTITIES_INVALID")
				}
				if _, e := WriteNew(filepath.Join(o.out, "vm-started.json"), Object{"schema": 1, "job_id": req["job_id"], "attempt_id": req["attempt_id"], "processes": ready["processes"], "control_directory": observation["control_directory"]}); e != nil {
					return e
				}
				marked = true
			}
			ready, accepted := broker.state()
			for !ready && progressSequence < 3 {
				path := filepath.Join(run, "product-progress-"+itoa(progressSequence+1)+".json")
				if missing(path) {
					break
				}
				value, _, e := Read(path, 1024)
				if e != nil {
					return e
				}
				if e = vmbridge.ValidateProductProgress(value); e != nil {
					return e
				}
				if Int(value, "sequence") != int64(progressSequence+1) {
					return Error("PRODUCT_PROGRESS_SEQUENCE_INVALID")
				}
				broker.event(Object{"event": "PROGRESS", "progress": value})
				progressSequence++
			}
			if !ready && !missing(filepath.Join(run, "product-report.json")) {
				source := filepath.Join(run, "product-report.json")
				value, data, e := Read(source, ReportLimit)
				if e != nil {
					return e
				}
				if e = vmbridge.ValidateProductReport(value, req); e != nil {
					return e
				}
				before, e := Owned(source, unix.S_IFREG, 0600)
				if e != nil {
					return e
				}
				report := filepath.Join(o.out, "report.json")
				if e = os.Link(source, report); e != nil {
					return e
				}
				after, e := Owned(report, unix.S_IFREG, 0600)
				if e != nil || !SameIdentity(before, after) {
					return Error("PRODUCT_REPORT_CHANGED")
				}
				linked, e := ReadBytes(report, ReportLimit)
				if e != nil || !bytes.Equal(data, linked) {
					return Error("PRODUCT_REPORT_CHANGED")
				}
				if e = SyncDirectory(o.out); e != nil {
					return e
				}
				summary["report_sha256"] = HashBytes(data)
				broker.reportReady()
				broker.event(Object{"event": "REPORT_READY", "report_path": report})
			}
			_, accepted = broker.state()
			if accepted && !acknowledged && broker.ctx.Err() == nil {
				if _, e := WriteNew(filepath.Join(run, "product-accepted.json"), Object{"job_id": req["job_id"], "attempt_id": req["attempt_id"], "report_sha256": summary["report_sha256"]}); e != nil {
					return e
				}
				acknowledged = true
				summary["report_accepted"] = true
			}
			return nil
		}()
		if err != nil {
			broker.cancel()
		}
		return nil
	}
	control, e := r.NativeControl(o.out, req, ScanProfile, o.startupFD)
	if e != nil {
		return e
	}
	launched = true
	native, e := r.Launch(broker.ctx, config, filepath.Join(o.out, "watchdog"), started, control, progress)
	if e != nil {
		return e
	}
	kind, stopError := r.NativeChecks(native)
	verified := stopError == nil
	reason := Str(Map(native, "terminal"), "reason")
	if Str(native, "start_denied_reason") == "DATABASE_STALE" && !Bool(native, "qemu_started") {
		reason = "DATABASE_STALE"
	}
	allowed := map[string]bool{"EXCHANGE_COMPLETE": true, "INTERRUPTED": true, "SCAN_TIMEOUT": true, "RESOURCE_MONITOR_FAILED": true, "HOST_RESOURCE_PRESSURE": true, "WORKSPACE_LIMIT": true, "WORKSPACE_IO_ERROR": true, "WORKSPACE_CONFIGURATION_ERROR": true, "REPORT_VALIDATION_FAILED": true, "INCOMPLETE_REQUIRED_CHECKS": true, "DATABASE_STALE": true}
	if !allowed[reason] {
		reason = "INCOMPLETE_REQUIRED_CHECKS"
	}
	summary["termination"] = Object{"all_exited": Bool(Map(native, "terminal"), "all_exited"), "identity_verified": verified, "stop_failed": !verified, "reason_code": reason}
	if kind == "native_guardian" {
		sha, e := DigestControl(filepath.Join(o.out, "watchdog/results.json"), 16<<20)
		if e != nil {
			return e
		}
		summary["native_evidence"] = Object{"path": "watchdog/results.json", "sha256": sha}
	}
	if verified {
		if e = r.SyncStopProof(o.out, run, native); e != nil {
			return e
		}
		evidence, e := r.Cleanup(o.out, req, native, ScanProfile, nil)
		if e != nil {
			return e
		}
		summary["recovery_evidence"] = evidence
		summary["raw_reclaimed"] = true
		summary["vm_slot_finalized"] = true
		summary["reservation_charge_bytes"] = 0
	}
	definitionSame := true
	if Int(req, "schema_version") == 3 {
		current, e := SelectedDefinition(o.request, false)
		definitionSame = e == nil && Equal(current, req["definition"])
	}
	baseSHA, e := HashFile(filepath.Join(r.VM, ".build/base.ext4"))
	if e != nil {
		return e
	}
	fixtureDefinitionsSame := true
	if Int(req, "schema_version") == 2 {
		sha, e := HashFile(filepath.Join(r.VM, ".build/definitions.ext4"))
		fixtureDefinitionsSame = e == nil && sha == Str(Map(prepared, "images_before"), "definitions")
	}
	summary["passed"] = Bool(native, "passed") && Bool(summary, "report_accepted") && Bool(summary, "raw_reclaimed") && Bool(summary, "vm_slot_finalized") && definitionSame && fixtureDefinitionsSame && baseSHA == Str(Map(prepared, "images_before"), "base")
	return nil
}
func RunScan(args []string) (int, error) {
	var o scanOptions
	flags := flag.NewFlagSet("filegate-vm", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.request, "request", "", "")
	flags.StringVar(&o.out, "out", "", "")
	flags.StringVar(&o.proof, "proof", "", "")
	flags.StringVar(&o.run, "run-directory", "", "")
	flags.StringVar(&o.fixture, "fixture", "", "")
	flags.BoolVar(&o.fixtureLocked, "fixture-producer-locked", false, "")
	flags.IntVar(&o.startupFD, "startup-lock-fd", -1, "")
	flags.BoolVar(&o.recover, "recover", false, "")
	flags.BoolVar(&o.prepare, "prepare", false, "")
	if e := flags.Parse(args); e != nil || flags.NArg() != 0 {
		return 2, Error("PRODUCT_ARGUMENTS_INVALID")
	}
	executable, e := os.Executable()
	if e != nil {
		return 2, e
	}
	executable, e = filepath.EvalSymlinks(executable)
	if e != nil {
		return 2, e
	}
	r, e := New(filepath.Dir(filepath.Dir(executable)))
	if e != nil {
		return 2, e
	}
	if o.prepare {
		if o.fixture != "" {
			if o.recover || o.fixtureLocked || o.run == "" || o.request != "" || o.out != "" || o.proof != "" || o.startupFD != -1 {
				return 2, Error("PREPARATION_ARGUMENTS_INVALID")
			}
			_, e = r.PrepareFixture(context.Background(), o.run, o.fixture)
			return 0, e
		}
		if o.recover || o.run == "" || o.request == "" || o.out != "" || o.proof != "" || o.startupFD != -1 {
			return 2, Error("PREPARATION_ARGUMENTS_INVALID")
		}
		_, e = r.PrepareScan(context.Background(), o.run, o.request)
		return 0, e
	}
	if o.fixture != "" {
		return r.fixtureMain(o)
	}
	if o.fixtureLocked {
		return 2, Error("PRODUCT_ARGUMENTS_INVALID")
	}
	if o.request == "" || o.out == "" || o.proof == "" || o.run != "" {
		return 2, Error("PRODUCT_ARGUMENTS_INVALID")
	}
	if !o.recover {
		if e = ValidateProducerLock(o.startupFD, o.request, false); e != nil {
			return 2, e
		}
	}
	req, e := ReadScanRequest(o.request, o.recover)
	if e != nil {
		return 2, e
	}
	if !o.recover {
		if e = os.Mkdir(o.out, 0700); e != nil {
			return 2, e
		}
		if e = SyncDirectory(filepath.Dir(o.out)); e != nil {
			return 2, e
		}
	}
	if e = validateOutput(o.out); e != nil {
		return 2, e
	}
	summary := scanSummary(req)
	if o.recover {
		if e = r.recoverScan(o.out, req, summary); e != nil {
			return 2, e
		}
		return 0, nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	runError := r.executeScan(ctx, o, req, summary)
	if runError != nil {
		summary["passed"] = false
	}
	if _, e = WriteNew(filepath.Join(o.out, "results.json"), summary); e != nil {
		return 2, e
	}
	finished, _ := Encoded(Object{"event": "FINISHED"})
	_, _ = os.Stdout.Write(finished)
	if Bool(summary, "raw_reclaimed") && Bool(summary, "vm_slot_finalized") {
		return 0, nil
	}
	return 1, nil
}
