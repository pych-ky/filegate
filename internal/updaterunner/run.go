package updaterunner

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

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

var normalRunFiles = []string{"prepared.json", "prepared.json.pending", "work.raw", "channel.sock", "normal-exchange.json", "normal-exchange.json.pending"}

func allowedRunFiles(r Request) []string {
	if !r.FixtureOnly {
		return normalRunFiles
	}
	files := []string{"prepared.json", "work.raw", "channel.sock", "exchange.json", "exchange.json.pending", "product-request.json", "product-accepted.json", "product-accepted.json.pending", "product-report.json", "product-report.json.pending", "update-bridge.json", "update-bridge.json.pending", "fixture-observation.json", "fixture-observation.pending"}
	for _, sequence := range []string{"1", "2", "3"} {
		files = append(files, "product-progress-"+sequence+".json", "product-progress-"+sequence+".json.pending")
	}
	return files
}

type options struct {
	manifest, request, out, run string
	recoverySHA                 string
	producerFD                  int
	recover, prepare            bool
}

type controller struct {
	ctx          context.Context
	cancel       context.CancelFunc
	runtime      *hostvm.Runtime
	deadline     uint64
	input        int
	output       io.Writer
	mu           sync.Mutex
	last         time.Time
	accepted     bool
	closed       bool
	receiverDone chan struct{}
	monitorDone  chan struct{}
}

func newController(ctx context.Context, runtime *hostvm.Runtime, deadline uint64) *controller {
	ctx, cancel := context.WithCancel(ctx)
	c := &controller{ctx: ctx, cancel: cancel, runtime: runtime, deadline: deadline, input: int(os.Stdin.Fd()), output: os.Stdout, last: time.Now(), receiverDone: make(chan struct{}), monitorDone: make(chan struct{})}
	go c.receive()
	go func() {
		defer close(c.monitorDone)
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if c.stopping() {
					return
				}
			}
		}
	}()
	return c
}

func (c *controller) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	<-c.receiverDone
	<-c.monitorDone
}

func (c *controller) receive() {
	defer close(c.receiverDone)
	var pending []byte
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		poll := []unix.PollFd{{Fd: int32(c.input), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		if _, err := unix.Poll(poll, 200); err != nil {
			if err == unix.EINTR {
				continue
			}
			break
		}
		if poll[0].Revents == 0 {
			continue
		}
		buffer := make([]byte, 64-len(pending))
		n, err := unix.Read(c.input, buffer)
		if err != nil || n == 0 {
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
			c.mu.Lock()
			valid := true
			switch {
			case line == "heartbeat":
				c.last = time.Now()
			case line == "final-accepted" && !c.accepted:
				c.accepted = true
			default:
				valid = false
			}
			c.mu.Unlock()
			if !valid {
				c.cancel()
				return
			}
		}
		if len(pending) == 64 {
			break
		}
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if !closed {
		c.cancel()
	}
}

func (c *controller) stopping() bool {
	if c.ctx.Err() != nil {
		return true
	}
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	now, err := c.runtime.Clock()
	if time.Since(last) >= 5*time.Second || err != nil || now >= c.deadline {
		c.cancel()
		return true
	}
	return false
}

func (c *controller) event(name string) error {
	body, err := hostvm.Encoded(object{"event": name})
	if err == nil {
		var n int
		n, err = c.output.Write(body)
		if err == nil && n != len(body) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		c.cancel()
	}
	return err
}

func outputDirectory(out string) error {
	s, err := owned(out, unix.S_IFDIR, 0700)
	var temporary unix.Stat_t
	if err != nil || !canonical(out) || unix.Stat("/private/tmp", &temporary) != nil || s.Dev != temporary.Dev {
		return invalid("UPDATE_OUTPUT_INVALID")
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func complete(out string, r Request, requestSHA, cleanupSHA string, startupOnly, cleaned bool) error {
	finalSHA := ""
	var err error
	if exists(filepath.Join(out, "final.json")) {
		finalSHA, err = hostvm.DigestControl(filepath.Join(out, "final.json"), 1<<20)
		if err != nil {
			return err
		}
	}
	stopSHA := ""
	if !startupOnly {
		stopSHA, err = hostvm.DigestControl(filepath.Join(out, "stop-proof.json"), hostvm.ControlLimit)
		if err != nil {
			return err
		}
	}
	value := object{"schema": 1, "profile": r.Profile, "fixture_only": r.FixtureOnly, "update_id": r.AttemptID, "base_generation": r.Attempt.BaseGeneration, "request_sha256": requestSHA, "stop_confirmed": true, "cleanup_confirmed": cleaned, "cleanup_sha256": cleanupSHA, "final_sha256": finalSHA, "network_enabled": !r.FixtureOnly, "adoption_enabled": false, "startup_only": startupOnly, "stop_proof_sha256": stopSHA}
	name := "update-complete.json"
	if !cleaned {
		name = "update-pending.json"
	}
	_, err = hostvm.WriteOnce(filepath.Join(out, name), value)
	return err
}

func clean(out string, r Request, requested object, runtime *hostvm.Runtime) (string, error) {
	var native object
	var err error
	if exists(filepath.Join(out, "native-previous-boot.json")) {
		native, _, err = hostvm.Read(filepath.Join(out, "native-previous-boot.json"), hostvm.ControlLimit)
		if err == nil {
			err = runtime.ValidatePreviousBoot(out, requested, native, hostvm.UpdateProfile)
		}
		if err != nil {
			return "", err
		}
	} else if exists(filepath.Join(out, "native-intent.json")) && !exists(filepath.Join(out, "watchdog/results.json")) && !exists(filepath.Join(out, "stop-proof.json")) {
		native, err = runtime.RecoverNative(out, requested, hostvm.UpdateProfile)
		if err != nil {
			return "", err
		}
		switch hostvm.Str(native, "kind") {
		case "native_prelaunch":
			_, err = hostvm.WriteOnce(filepath.Join(out, "native-recovery.json"), native)
		case "native_previous_boot":
			_, err = hostvm.WriteOnce(filepath.Join(out, "native-previous-boot.json"), native)
		}
		if err != nil {
			return "", err
		}
	}
	if exists(filepath.Join(out, "watchdog/results.json")) && (native == nil || hostvm.Str(native, "kind") != "native_previous_boot") {
		native, _, err = hostvm.Read(filepath.Join(out, "watchdog/results.json"), 16<<20)
		if err != nil {
			return "", err
		}
		if !exists(filepath.Join(out, "stop-proof.json")) {
			if _, err = runtime.NativeChecks(native); err != nil {
				return "", err
			}
			preparation, _, err := hostvm.Read(filepath.Join(out, "preparation-intent.json"), hostvm.ControlLimit)
			if err != nil {
				return "", err
			}
			if err = runtime.SyncStopProof(out, hostvm.Str(preparation, "run_directory"), native); err != nil {
				return "", err
			}
		}
	}
	var evidence object
	if !exists(filepath.Join(out, "preparation-owner.json")) && native == nil {
		evidence, err = runtime.CleanupUnstartedResources(out, requested)
	} else {
		evidence, err = runtime.Cleanup(out, requested, native, hostvm.UpdateProfile, allowedRunFiles(r))
	}
	if err != nil || !digestPattern.MatchString(hostvm.Str(evidence, "sha256")) {
		if err == nil {
			err = invalid("UPDATE_CLEANUP_INVALID")
		}
		return "", err
	}
	return hostvm.Str(evidence, "sha256"), nil
}

func recoverRun(options options, r Request, requested object, requestSHA string, runtime *hostvm.Runtime) error {
	out := options.out
	if !exists(out) {
		if err := os.Mkdir(out, 0700); err != nil {
			return err
		}
		if err := hostvm.SyncDirectory(filepath.Dir(out)); err != nil {
			return err
		}
	}
	if err := outputDirectory(out); err != nil {
		return err
	}
	lock, err := hostvm.RunnerLock(out, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if exists(filepath.Join(out, "update-complete.json")) {
		receipt, _, err := hostvm.Read(filepath.Join(out, "update-complete.json"), 16384)
		if err != nil {
			return err
		}
		name := "cleanup-complete.json"
		if receipt["startup_only"] == true {
			name = "startup-complete.json"
		}
		sha, err := hostvm.DigestControl(filepath.Join(out, name), hostvm.ControlLimit)
		if err != nil || hostvm.Str(receipt, "request_sha256") != requestSHA || hostvm.Str(receipt, "cleanup_sha256") != sha {
			return invalid("UPDATE_COMPLETION_CHANGED")
		}
		if name == "cleanup-complete.json" {
			intent, _, err := hostvm.Read(filepath.Join(out, "cleanup-intent.json"), hostvm.ControlLimit)
			if err != nil {
				return err
			}
			for _, item := range hostvm.List(intent, "directories") {
				row, ok := item.(map[string]any)
				if !ok || exists(hostvm.Str(row, "path")) {
					return invalid("UPDATE_CLEANUP_CHANGED")
				}
			}
		}
		return nil
	}
	if !exists(filepath.Join(out, "resource-intent.json")) {
		allowed := map[string]bool{"runner.lock": true, "startup-complete.json": true, "startup-complete.json.pending": true, "update-complete.json.pending": true}
		entries, err := os.ReadDir(out)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !allowed[entry.Name()] {
				return invalid("UPDATE_STARTUP_SCOPE_UNKNOWN")
			}
		}
		digest, err := hostvm.WriteOnce(filepath.Join(out, "startup-complete.json"), object{"schema": 1, "update_id": r.AttemptID, "request_sha256": requestSHA, "producer_stopped": true, "resources_not_created": true})
		if err != nil {
			return err
		}
		return complete(out, r, requestSHA, digest, true, true)
	}
	if err = os.MkdirAll(runtime.State, 0700); err != nil {
		return err
	}
	if _, err = owned(runtime.State, unix.S_IFDIR, 0700); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(runtime.State, "vm-slot.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	slot := os.NewFile(uintptr(fd), "vm-slot")
	defer slot.Close()
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	digest, err := clean(out, r, requested, runtime)
	if err != nil {
		if _, stopErr := runtime.StopProof(out, requested, nil, hostvm.UpdateProfile); stopErr != nil {
			return stopErr
		}
		if err = runtime.ReleaseSlot(out, requested, hostvm.UpdateProfile); err != nil {
			return err
		}
		return complete(out, r, requestSHA, "", false, false)
	}
	return complete(out, r, requestSHA, digest, false, true)
}

func execute(ctx context.Context, options options, r Request, requested object, m Manifest, requestSHA string, runtime *hostvm.Runtime) error {
	out := options.out
	if err := os.Mkdir(out, 0700); err != nil {
		return err
	}
	if err := hostvm.SyncDirectory(filepath.Dir(out)); err != nil {
		return err
	}
	if err := outputDirectory(out); err != nil {
		return err
	}
	boot, err := hostvm.BootUUID()
	if err != nil || r.Attempt.Started.Boot != boot {
		return invalid("UPDATE_CLOCK_UNCERTAIN")
	}
	controller := newController(ctx, runtime, r.Attempt.DeadlineContinuousNS)
	defer controller.close()
	resources, err := runtime.ResourceIntent(out, requested, hostvm.UpdateProfile)
	if err != nil {
		return err
	}
	lock, err := hostvm.RunnerLock(out)
	if err != nil {
		return err
	}
	defer lock.Close()
	slot, err := runtime.AcquireSlot(out, requested, resources)
	if err != nil {
		return err
	}
	defer slot.Close()
	if err = hostvm.CaptureSlot(out, slot, requested); err != nil {
		return err
	}
	if controller.stopping() {
		return invalid("UPDATE_INTERRUPTED")
	}
	run, err := hostvm.CreateRun(resources)
	if err != nil {
		return err
	}
	info, err := owned(run, unix.S_IFDIR, 0700)
	if err != nil {
		return err
	}
	if _, err = hostvm.WriteNew(filepath.Join(out, "preparation-intent.json"), object{"schema": 1, "job_id": r.JobID, "attempt_id": r.AttemptID, "run_directory": run, "run_directory_identity": hostvm.DirectoryIdentity(info), "reservation_charge_bytes": rawBytes}); err != nil {
		return err
	}
	if err = controller.event("PREPARING"); err != nil {
		return err
	}
	preparation, err := hostvm.ControlledCommand(controller.ctx, []string{m.Runner, "--prepare", "--manifest", options.manifest, "--request", options.request, "--run-directory", run}, 120, filepath.Join(out, "preparation-owner.json"), runtime.Root, options.producerFD, "")
	if err != nil {
		return err
	}
	if _, err = hostvm.WriteNew(filepath.Join(out, "preparation.json"), preparation); err != nil {
		return err
	}
	if hostvm.Int(preparation, "exit_status") != 0 || preparation["failure"] != nil || controller.stopping() {
		return invalid("UPDATE_PREPARATION_FAILED")
	}
	raw, err := owned(filepath.Join(run, "work.raw"), unix.S_IFREG, 0600)
	if err != nil {
		return err
	}
	if _, err = hostvm.WriteNew(filepath.Join(out, "prepared-identity.json"), object{"run_directory": run, "raw_identity": hostvm.DirectoryIdentity(raw)}); err != nil {
		return err
	}
	var config object
	if m.FixtureOnly {
		bridgeSHA, writeErr := hostvm.WriteNew(filepath.Join(run, "update-bridge.json"), object{"schema": 1, "fixture_only": true, "mode": "first", "library_sha256": r.LibrarySHA256, "request": r.Restore, "output_directory": out})
		if writeErr != nil {
			return writeErr
		}
		config, _, err = runtime.PreparedFixtureConfig(filepath.Join(run, "prepared.json"), m.Proof, "freshclam-adapter")
		if err != nil {
			return err
		}
		pins := hostvm.Map(config, "helper_pins")
		delete(pins, filepath.Join(runtime.VM, ".build/filegate-bridge"))
		for name, expected := range pins {
			if m.SHA256[name] != expected {
				return invalid("UPDATE_FIXTURE_BINDING_CHANGED")
			}
		}
		pins[m.Helper] = m.SHA256[m.Helper]
		config["helper_argv"] = []string{m.Helper, "--run", run, "--update-bridge-sha256", bridgeSHA}
	} else {
		fd, err := unix.Open(filepath.Join(out, "network.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "network-lock")
		var network unix.Stat_t
		if err = file.Sync(); err == nil {
			err = unix.Fstat(fd, &network)
		}
		if err == nil {
			_, err = hostvm.WriteNew(filepath.Join(out, "network-intent.json"), object{"schema": 1, "update_id": r.AttemptID, "request_sha256": requestSHA, "device": uint64(network.Dev), "inode": network.Ino})
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		config, err = PreparedConfig(runtime, filepath.Join(run, "prepared.json"), options.manifest, options.request, m, r, requestSHA)
		if err != nil {
			return err
		}
	}
	if controller.stopping() {
		return invalid("UPDATE_INTERRUPTED")
	}
	if err = controller.event("RUNNING"); err != nil {
		return err
	}
	reported, markedStarted := false, false
	progress := func(observation object) error {
		if observation["qemu_started"] == true && !markedStarted {
			var ready object
			for _, value := range hostvm.List(observation, "broker_events") {
				event, ok := value.(map[string]any)
				if ok && hostvm.Str(event, "event") == "MONITOR_READY" {
					ready = event
					break
				}
			}
			if ready == nil {
				return invalid("UPDATE_NATIVE_MONITOR_MISSING")
			}
			if _, err := hostvm.WriteNew(filepath.Join(out, "vm-started.json"), object{"schema": 1, "job_id": r.JobID, "attempt_id": r.AttemptID, "processes": ready["processes"], "control_directory": observation["control_directory"]}); err != nil {
				return err
			}
			markedStarted = true
		}
		if !reported && exists(filepath.Join(out, "final.json")) {
			if _, _, err := hostvm.Read(filepath.Join(out, "final.json"), 1<<20); err != nil {
				return err
			}
			reported = true
			if err := controller.event("FINAL_READY"); err != nil {
				return err
			}
		}
		controller.mu.Lock()
		accepted := controller.accepted
		controller.mu.Unlock()
		acceptedPath := filepath.Join(out, "final-accepted.json")
		if accepted && m.FixtureOnly {
			controller.cancel()
			return nil
		}
		if accepted && !exists(acceptedPath) {
			finalSHA, err := hostvm.HashFile(filepath.Join(out, "final.json"))
			if err != nil {
				return err
			}
			_, err = hostvm.WriteNew(acceptedPath, object{"update_id": r.AttemptID, "final_sha256": finalSHA})
			return err
		}
		return nil
	}
	control, err := runtime.NativeControl(out, requested, hostvm.UpdateProfile, options.producerFD)
	if err != nil {
		return err
	}
	native, err := runtime.Launch(controller.ctx, config, filepath.Join(out, "watchdog"), r.Attempt.Started.ContinuousNS, control, progress)
	if err != nil {
		return err
	}
	if _, err = runtime.NativeChecks(native); err != nil {
		return err
	}
	if err = runtime.SyncStopProof(out, run, native); err != nil {
		return err
	}
	if _, err = runtime.Cleanup(out, requested, native, hostvm.UpdateProfile, allowedRunFiles(r)); err != nil {
		return err
	}
	return controller.event("FINISHED")
}

func Run(args []string) error {
	var o options
	flags := flag.NewFlagSet("filegate-update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.manifest, "manifest", "", "")
	flags.StringVar(&o.request, "request", "", "")
	flags.StringVar(&o.out, "out", "", "")
	flags.StringVar(&o.run, "run-directory", "", "")
	flags.StringVar(&o.recoverySHA, "recovery-binary-sha256", "", "")
	flags.IntVar(&o.producerFD, "startup-lock-fd", -1, "")
	flags.BoolVar(&o.recover, "recover", false, "")
	flags.BoolVar(&o.prepare, "prepare", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || o.manifest == "" || o.request == "" {
		return invalid("UPDATE_ARGUMENTS_INVALID")
	}
	if o.recoverySHA != "" && (!o.recover || !digestPattern.MatchString(o.recoverySHA)) {
		return invalid("UPDATE_RECOVERY_ARGUMENTS_INVALID")
	}
	if o.prepare {
		if o.recover || o.run == "" || o.out != "" || o.producerFD != -1 {
			return invalid("UPDATE_ARGUMENTS_INVALID")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		return Prepare(ctx, o.manifest, o.request, o.run)
	}
	if o.run != "" || !filepath.IsAbs(o.out) || filepath.Clean(o.out) != o.out || o.out != filepath.Join(filepath.Dir(o.request), "output") {
		return invalid("UPDATE_OUTPUT_SCOPE_INVALID")
	}
	loader := load
	if o.recover {
		loader = func(manifest, request string) (Manifest, Request, object, string, error) {
			return loadRecovery(manifest, request, o.recoverySHA)
		}
	}
	m, r, requested, requestSHA, err := loader(o.manifest, o.request)
	if err != nil {
		return err
	}
	runtime, err := hostvm.New(m.Workspace)
	if err != nil {
		return err
	}
	if o.recover {
		lock, err := runtime.RecoveryLock(o.out, requested, hostvm.UpdateProfile)
		if err != nil {
			return err
		}
		if lock != nil {
			defer lock.Close()
		}
		return recoverRun(o, r, requested, requestSHA, runtime)
	}
	if o.producerFD != 3 || hostvm.ValidateProducerLock(o.producerFD, o.request, false) != nil {
		return invalid("UPDATE_PRODUCER_LOCK_INVALID")
	}
	lock := os.NewFile(uintptr(o.producerFD), "producer-lock")
	defer lock.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return execute(ctx, o, r, requested, m, requestSHA, runtime)
}
