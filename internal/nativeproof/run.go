package nativeproof

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

func Run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return 2, failure("NATIVE_PROOF_COMMAND_REQUIRED")
	}
	command := args[0]
	flags := flag.NewFlagSet("filegate-native-proof "+command, flag.ContinueOnError)
	repo := flags.String("repo", "", "canonical source repository")
	out := flags.String("out", "", "external output directory")
	build := flags.String("native-build", "", "Go native monitor build directory")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *repo == "" || *out == "" || (command != "build" && *build == "") {
		return 2, failure("NATIVE_PROOF_ARGUMENTS_INVALID")
	}
	if command == "build" {
		report, err := Build(ctx, *repo, *out)
		if report != nil {
			emit(object{"passed": report["passed"], "build": filepath.Join(*out, "build.json")})
		}
		if err != nil {
			return 1, err
		}
		return 0, nil
	}
	if command == "--locked-qualify" || command == "--locked-recover" {
		return locked(ctx, *repo, *build, *out, command == "--locked-recover")
	}
	if command != "qualify" && command != "recover" {
		return 2, failure("NATIVE_PROOF_COMMAND_INVALID")
	}
	return dispatch(ctx, *repo, *build, *out, command == "recover")
}

func emit(value object) {
	body, err := hostvm.Encoded(value)
	if err == nil {
		_, _ = os.Stdout.Write(body)
	}
}

func slotBinding(r *hostvm.Runtime, out string) error {
	owner, _, err := hostvm.Read(filepath.Join(out, "global-slot-owner.json"), hostvm.ControlLimit)
	if err != nil {
		return err
	}
	intentPath := filepath.Join(r.State, "active-vm.json")
	intent, body, err := hostvm.Read(intentPath, hostvm.ControlLimit)
	if err != nil || hostvm.Int(intent, "schema") != 1 || hostvm.Str(intent, "kind") != "native_proof" || hostvm.Str(intent, "output_directory") != out || hostvm.Str(intent, "status") != "ACTIVE" ||
		hostvm.Str(owner, "output_directory") != out || hostvm.Str(owner, "intent_sha256") != hostvm.HashBytes(body) {
		return failure("NATIVE_PROOF_GLOBAL_INTENT_CHANGED")
	}
	info, err := hostvm.Owned(intentPath, unix.S_IFREG, 0600)
	if err != nil || !hostvm.Equal(hostvm.DirectoryIdentity(info), hostvm.Map(owner, "intent_identity")) {
		return failure("NATIVE_PROOF_GLOBAL_INTENT_CHANGED")
	}
	return nil
}

func dispatch(ctx context.Context, repo, build, out string, recover bool) (int, error) {
	r, _, err := buildBinding(repo, build)
	if err != nil {
		return 2, err
	}
	if !recover {
		if err = freshDirectory(out, repo); err != nil {
			return 2, err
		}
	} else if _, err = hostvm.Owned(out, unix.S_IFDIR, 0700); err != nil {
		return 2, err
	}
	runner, err := hostvm.RunnerLock(out)
	if err != nil {
		return 2, err
	}
	defer runner.Close()
	slot, err := r.RecoverySlot()
	if err != nil {
		return 2, err
	}
	defer slot.Close()
	intentPath := filepath.Join(r.State, "active-vm.json")
	if recover {
		if err = slotBinding(r, out); err != nil {
			return 2, err
		}
	} else {
		if _, err = os.Lstat(intentPath); !os.IsNotExist(err) {
			return 2, failure("RUNTIME_RECOVERY_REQUIRED")
		}
		intent := object{"schema": 1, "kind": "native_proof", "broker_pid": os.Getpid(), "output_directory": out, "status": "ACTIVE"}
		sha, err := hostvm.WriteNew(intentPath, intent)
		if err != nil {
			return 2, err
		}
		info, err := hostvm.Owned(intentPath, unix.S_IFREG, 0600)
		if err != nil {
			return 2, err
		}
		if _, err = hostvm.WriteNew(filepath.Join(out, "global-slot-owner.json"), object{"schema": 1, "kind": "native_proof", "output_directory": out, "intent_sha256": sha, "intent_identity": hostvm.DirectoryIdentity(info)}); err != nil {
			return 2, err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return 2, err
	}
	mode := "--locked-qualify"
	if recover {
		mode = "--locked-recover"
	}
	child := exec.Command(self, mode, "--repo", repo, "--native-build", build, "--out", out)
	child.ExtraFiles = []*os.File{slot}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err = child.Start(); err != nil {
		return 2, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = child.Process.Signal(syscall.SIGTERM)
		case <-done:
		}
	}()
	err = child.Wait()
	if err == nil {
		return 0, nil
	}
	if exited, ok := err.(*exec.ExitError); ok {
		return exited.ExitCode(), nil
	}
	return 2, err
}

func locked(ctx context.Context, repo, build, out string, recover bool) (int, error) {
	r, receipt, err := buildBinding(repo, build)
	if err != nil {
		return 2, err
	}
	var held, named unix.Stat_t
	if unix.Fstat(3, &held) != nil || unix.Lstat(filepath.Join(r.State, "vm-slot.lock"), &named) != nil || held.Dev != named.Dev || held.Ino != named.Ino || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&07777 != 0600 || held.Uid != uint32(os.Getuid()) || unix.Flock(3, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return 2, failure("NATIVE_PROOF_GLOBAL_LOCK_REQUIRED")
	}
	if _, err = hostvm.Owned(out, unix.S_IFDIR, 0700); err != nil {
		return 2, err
	}
	if err = slotBinding(r, out); err != nil {
		return 2, err
	}
	if recover {
		err = recoverProof(r, out)
		if err != nil {
			return 1, err
		}
		emit(object{"passed": false, "recovered": true, "result": filepath.Join(out, "recovery-results.json")})
		return 0, nil
	}
	report, err := qualify(ctx, r, receipt, build, out)
	if report != nil {
		emit(object{"passed": report["passed"], "result": filepath.Join(out, "results.json")})
	}
	if err != nil {
		return 1, err
	}
	if report["passed"] != true {
		return 1, fmt.Errorf("NATIVE_PROOF_NOT_QUALIFIED")
	}
	return 0, nil
}
