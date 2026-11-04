package hostvm

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const fixtureProfile = "filegate-vm-fixture-v1"

func fixtureAllowed(name string) bool {
	for _, known := range strings.Fields("transfer watchdog-death av-observation av-limits av-hard av-io freshclam-adapter input-hash-mismatch workspace-root-copyup workspace-tmp workspace-var-tmp workspace-run workspace-avtmp workspace-extract workspace-mixed workspace-inodes workspace-boundary workspace-reuse workspace-monitor-failure workspace-monitor-stop workspace-sync-failure format-contract product-av-normalization av-remaining av-internal av-pe-import av-regex av-icons av-parser-routes av-codec-bounds av-lzma-wrappers av-decoder-wrappers av-deflate64-wrapper av-tar-scope av-text-parsers") {
		if known == name {
			return true
		}
	}
	return false
}
func fixtureFiles() []string {
	return []string{"prepared.json", "work.raw", "channel.sock", "exchange.json", "exchange.json.pending", "fixture-observation.json", "fixture-observation.json.pending", "fixture-observation.pending"}
}
func fixtureRequest(out, fixture string, recover bool) (Object, error) {
	path := filepath.Join(out, "fixture-request.json")
	if recover {
		req, _, e := Read(path, ControlLimit)
		if e != nil {
			return nil, e
		}
		if !Fields(req, "schema_version", "profile", "fixture", "job_id", "attempt_id", "expected_sha256", "byte_size") || Int(req, "schema_version") != 1 || Str(req, "profile") != fixtureProfile || Str(req, "fixture") != fixture || !regexp.MustCompile(`^job_[0-9a-f]{32}$`).MatchString(Str(req, "job_id")) || !regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(Str(req, "attempt_id")) || Str(req, "expected_sha256") != HashBytes(nil) || Int(req, "byte_size") != 0 {
			return nil, Error("FIXTURE_REQUEST_INVALID")
		}
		return req, nil
	}
	job, e := RandomPath("")
	if e != nil {
		return nil, e
	}
	attempt, e := RandomPath("")
	if e != nil {
		return nil, e
	}
	req := Object{"schema_version": 1, "profile": fixtureProfile, "fixture": fixture, "job_id": "job_" + filepath.Base(job), "attempt_id": "attempt_" + filepath.Base(attempt), "expected_sha256": HashBytes(nil), "byte_size": 0}
	_, e = WriteNew(path, req)
	return req, e
}
func (r *Runtime) fixtureMain(o scanOptions) (int, error) {
	if !fixtureAllowed(o.fixture) || o.out == "" || o.proof == "" || o.request != "" || o.run != "" || !filepath.IsAbs(o.out) || filepath.Clean(o.out) != o.out {
		return 2, Error("FIXTURE_ARGUMENTS_INVALID")
	}
	if !o.fixtureLocked {
		if o.startupFD != -1 {
			return 2, Error("FIXTURE_ARGUMENTS_INVALID")
		}
		if !o.recover {
			if e := os.Mkdir(o.out, 0700); e != nil {
				return 2, e
			}
			if e := SyncDirectory(filepath.Dir(o.out)); e != nil {
				return 2, e
			}
		}
		if e := validateOutput(o.out); e != nil {
			return 2, e
		}
		flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if !o.recover {
			flags |= unix.O_CREAT | unix.O_EXCL
		}
		fd, e := unix.Open(filepath.Join(o.out, "fixture-producer.lock"), flags, 0600)
		if e != nil {
			return 2, e
		}
		lock := os.NewFile(uintptr(fd), "fixture-producer-lock")
		defer lock.Close()
		s, e := Owned(filepath.Join(o.out, "fixture-producer.lock"), unix.S_IFREG, 0600)
		if e != nil || s.Size != 0 {
			return 2, Error("FIXTURE_PRODUCER_LOCK_INVALID")
		}
		if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
			return 2, e
		}
		if _, e = fixtureRequest(o.out, o.fixture, o.recover); e != nil {
			return 2, e
		}
		if e = SyncDirectory(o.out); e != nil {
			return 2, e
		}
		args := []string{"--fixture", o.fixture, "--out", o.out, "--proof", o.proof, "--fixture-producer-locked", "--startup-lock-fd", "3"}
		if o.recover {
			args = append(args, "--recover")
		}
		cmd := exec.Command(r.Executable, args...)
		cmd.ExtraFiles = []*os.File{lock}
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Dir = r.Root
		if e = cmd.Start(); e != nil {
			return 2, e
		}
		forward := make(chan os.Signal, 2)
		signal.Notify(forward, syscall.SIGTERM, syscall.SIGINT)
		done := make(chan struct{})
		defer signal.Stop(forward)
		go func() {
			for {
				select {
				case value := <-forward:
					_ = cmd.Process.Signal(value)
				case <-done:
					return
				}
			}
		}()
		e = cmd.Wait()
		close(done)
		if e != nil {
			return exitStatus(e), nil
		}
		return 0, nil
	}
	if o.startupFD != 3 {
		return 2, Error("FIXTURE_PRODUCER_LOCK_INVALID")
	}
	var fdInfo, pathInfo unix.Stat_t
	if unix.Fstat(3, &fdInfo) != nil || unix.Lstat(filepath.Join(o.out, "fixture-producer.lock"), &pathInfo) != nil || fdInfo.Mode&unix.S_IFMT != unix.S_IFREG || fdInfo.Uid != uint32(os.Getuid()) || fdInfo.Mode&07777 != 0600 || fdInfo.Size != 0 || fdInfo.Dev != pathInfo.Dev || fdInfo.Ino != pathInfo.Ino || unix.Flock(3, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return 2, Error("FIXTURE_PRODUCER_LOCK_INVALID")
	}
	unix.CloseOnExec(3)
	if e := validateOutput(o.out); e != nil {
		return 2, e
	}
	req, e := fixtureRequest(o.out, o.fixture, true)
	if e != nil {
		return 2, e
	}
	runner, e := RunnerLock(o.out, o.recover)
	if e != nil {
		return 2, e
	}
	defer runner.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if o.recover {
		slot, e := r.RecoverySlot()
		if e != nil {
			return 2, e
		}
		defer slot.Close()
		evidence, kind, e := r.cleanFixture(o.out, req)
		if e != nil {
			return 1, e
		}
		value := Object{"schema": 1, "kind": "monitored_qemu_fixture_recovery", "fixture": o.fixture, "passed": false, "raw_reclaimed": true, "vm_slot_finalized": true, "reservation_charge_bytes": 0, "recovery_evidence": evidence, "stop_kind": kind, "product_enabled": false, "stage0_gate_passed": false}
		_, e = WriteOnce(filepath.Join(o.out, "recovery-results.json"), value)
		return 0, e
	}
	return r.executeFixture(ctx, o, req)
}
func (r *Runtime) cleanFixture(out string, req Object) (Object, string, error) {
	var native Object
	var e error
	if !missing(filepath.Join(out, "native-previous-boot.json")) {
		native, _, e = Read(filepath.Join(out, "native-previous-boot.json"), ControlLimit)
		if e == nil {
			e = r.ValidatePreviousBoot(out, req, native, ScanProfile)
		}
	} else if !missing(filepath.Join(out, "native-intent.json")) && missing(filepath.Join(out, "watchdog/results.json")) && missing(filepath.Join(out, "stop-proof.json")) {
		native, e = r.RecoverNative(out, req, ScanProfile)
		if e == nil {
			name := ""
			if Str(native, "kind") == "native_prelaunch" {
				name = "native-recovery.json"
			}
			if Str(native, "kind") == "native_previous_boot" {
				name = "native-previous-boot.json"
			}
			if name != "" {
				_, e = WriteOnce(filepath.Join(out, name), native)
			}
		}
	}
	if e != nil {
		return nil, "", e
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
	if missing(filepath.Join(out, "preparation-owner.json")) && native == nil {
		evidence, e = r.CleanupUnstartedResources(out, req)
	} else {
		evidence, e = r.Cleanup(out, req, native, ScanProfile, fixtureFiles())
	}
	if e != nil {
		return nil, "", e
	}
	proof, _, e := Read(filepath.Join(out, "stop-proof.json"), ControlLimit)
	return evidence, Str(proof, "kind"), e
}
func (r *Runtime) executeFixture(ctx context.Context, o scanOptions, req Object) (code int, returned error) {
	summary := Object{"schema": 1, "kind": "monitored_qemu_fixture", "fixture": o.fixture, "passed": false, "raw_reclaimed": false, "vm_slot_finalized": false, "reservation_charge_bytes": RawBytes, "product_enabled": false, "stage0_gate_passed": false}
	defer func() {
		if returned != nil {
			summary["failure"] = returned.Error()
			summary["passed"] = false
		}
		if _, e := WriteNew(filepath.Join(o.out, "results.json"), summary); e != nil {
			returned = e
			code = 2
		}
		if !Bool(summary, "passed") {
			code = 1
		}
		body, _ := Encoded(Object{"passed": Bool(summary, "passed"), "result": filepath.Join(o.out, "results.json")})
		_, _ = os.Stdout.Write(body)
	}()
	resources, e := r.ResourceIntent(o.out, req, ScanProfile)
	if e != nil {
		return 1, e
	}
	slot, e := r.AcquireSlot(o.out, req, resources)
	if e != nil {
		return 1, e
	}
	defer slot.Close()
	if e = CaptureSlot(o.out, slot, req); e != nil {
		return 1, e
	}
	started, e := r.Clock()
	if e != nil {
		return 1, e
	}
	run, e := CreateRun(resources)
	if e != nil {
		return 1, e
	}
	runInfo, e := Owned(run, unix.S_IFDIR, 0700)
	if e != nil {
		return 1, e
	}
	if _, e = WriteNew(filepath.Join(o.out, "preparation-intent.json"), Object{"schema": 1, "job_id": req["job_id"], "attempt_id": req["attempt_id"], "run_directory": run, "run_directory_identity": DirectoryIdentity(runInfo), "reservation_charge_bytes": RawBytes}); e != nil {
		return 1, e
	}
	launched := false
	defer func() {
		if !launched && !missing(filepath.Join(o.out, "preparation-owner.json")) {
			evidence, e := r.Cleanup(o.out, req, nil, ScanProfile, fixtureFiles())
			if e != nil {
				returned = e
				return
			}
			summary["raw_reclaimed"] = true
			summary["vm_slot_finalized"] = true
			summary["reservation_charge_bytes"] = 0
			summary["recovery_evidence"] = evidence
		}
	}()
	preparation, e := ControlledCommand(ctx, []string{r.Executable, "--prepare", "--run-directory", run, "--fixture", o.fixture}, 120, filepath.Join(o.out, "preparation-owner.json"), r.Root, 3, "")
	if e != nil {
		return 1, e
	}
	if _, e = WriteNew(filepath.Join(o.out, "preparation.json"), preparation); e != nil {
		return 1, e
	}
	if Int(preparation, "exit_status") != 0 || preparation["failure"] != nil || ctx.Err() != nil {
		return 1, Error("FIXTURE_PREPARATION_FAILED")
	}
	raw, e := Owned(filepath.Join(run, "work.raw"), unix.S_IFREG, 0600)
	if e != nil || raw.Size != RawBytes {
		return 1, Error("RAW_CAPACITY_INVALID")
	}
	if _, e = WriteNew(filepath.Join(o.out, "prepared-identity.json"), Object{"run_directory": run, "raw_identity": DirectoryIdentity(raw)}); e != nil {
		return 1, e
	}
	catalogFixture := o.fixture
	if o.fixture == "watchdog-death" {
		catalogFixture = "transfer"
	}
	config, prepared, e := r.PreparedFixtureConfig(filepath.Join(run, "prepared.json"), o.proof, catalogFixture)
	if e != nil {
		return 1, e
	}
	if o.fixture == "watchdog-death" {
		arguments, ok := Strings(config["helper_argv"])
		if !ok {
			return 1, Error("DEATH_FIXTURE_CONFIGURATION_INVALID")
		}
		config["helper_argv"] = append(arguments, "--hold-before-input-for-watchdog-death")
		config["watchdog_death_fixture"] = true
		summary["catalog_fixture"] = catalogFixture
		summary["ordinary_exchange_finished_permitted"] = false
	}
	control, e := r.NativeControl(o.out, req, ScanProfile, 3)
	if e != nil {
		return 1, e
	}
	launched = true
	native, e := r.Launch(ctx, config, filepath.Join(o.out, "watchdog"), started, control, nil)
	if e != nil {
		return 1, e
	}
	kind, e := r.NativeChecks(native)
	if e != nil {
		return 1, e
	}
	summary["stop_kind"] = kind
	nativeSHA, e := DigestControl(filepath.Join(o.out, "watchdog/results.json"), 16<<20)
	if e != nil {
		return 1, e
	}
	summary["native_evidence"] = Object{"path": "watchdog/results.json", "sha256": nativeSHA}
	defer func() {
		if e := r.SyncStopProof(o.out, run, native); e != nil {
			returned = e
			return
		}
		evidence, e := r.Cleanup(o.out, req, native, ScanProfile, fixtureFiles())
		if e != nil {
			returned = e
			return
		}
		summary["raw_reclaimed"] = true
		summary["vm_slot_finalized"] = true
		summary["reservation_charge_bytes"] = 0
		summary["recovery_evidence"] = evidence
	}()
	contract := Map(config, "fixture_contract")
	fixtureVerified := false
	if o.fixture == "watchdog-death" {
		_, body, e := deathHoldObservation(run)
		if e != nil || r.validateDeathFixtureProof(native) != nil {
			return 1, Error("NATIVE_WATCHDOG_DEATH_UNCONFIRMED")
		}
		fixtureVerified = true
		if e = SaveCopy(filepath.Join(o.out, "fixture-observation.json"), body); e != nil {
			return 1, e
		}
	} else if Str(contract, "expected_stop_reason") != "" {
		observation, body, e := Read(filepath.Join(run, "fixture-observation.json"), 1<<20)
		if e != nil {
			return 1, e
		}
		selection := Map(observation, "started")
		fixtureVerified = Str(observation, "fixture") == o.fixture && Bool(observation, "acknowledged") && Str(selection, "fixture") == o.fixture && Equal(selection["action"], contract["start_action"]) && Equal(selection["target_paths"], contract["start_target_paths"]) && Str(selection, "phase") == "selected_before_execution" && selection["completed"] == false && selection["ack_required_before_action"] == true && Str(Map(native, "terminal"), "reason") == Str(contract, "expected_stop_reason")
		if e = SaveCopy(filepath.Join(o.out, "fixture-observation.json"), body); e != nil {
			return 1, e
		}
	} else {
		exchange, body, e := Read(filepath.Join(run, "exchange.json"), 4<<20)
		if e != nil {
			return 1, e
		}
		fixtureVerified = Int(exchange, "schema") == 2 && Str(exchange, "fixture") == o.fixture && Equal(exchange["expected"], contract) && Str(exchange, "outcome") == "verified" && exchange["failure"] == nil && exchange["product_scan"] == false && Str(exchange, "process_stop_confirmation") == "separate_watchdog_artifact_required"
		if e = SaveCopy(filepath.Join(o.out, "exchange.json"), body); e != nil {
			return 1, e
		}
	}
	summary["fixture_verified"] = fixtureVerified
	imagesUnchanged := true
	for name, expected := range Map(prepared, "images_before") {
		actual, e := HashFile(filepath.Join(r.VM, ".build", name+".ext4"))
		if e != nil || actual != expected {
			imagesUnchanged = false
		}
	}
	summary["readonly_images_unchanged"] = imagesUnchanged
	summary["passed"] = Bool(native, "passed") && fixtureVerified && imagesUnchanged
	return 0, nil
}
