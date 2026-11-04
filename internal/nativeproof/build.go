package nativeproof

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

func Build(ctx context.Context, repo, out string) (report object, returned error) {
	if _, err := canonical(repo); err != nil {
		return nil, err
	}
	pins, err := sourcePins(repo)
	if err != nil {
		return nil, err
	}
	if err = freshDirectory(out, repo); err != nil {
		return nil, err
	}
	binary := filepath.Join(out, "integrated-watchdog")
	source := filepath.Join(repo, "experiments/host/integrated_watchdog.m")
	report = object{"schema": 1, "kind": "go_native_monitor_build", "passed": false, "source_path": source, "source_sha256": pins["experiments/host/integrated_watchdog.m"], "go_sources_sha256": pins, "binary": binary, "python_dependency": false}
	defer func() {
		if err := verifyPins(repo, pins); err != nil {
			report["passed"] = false
			returned = err
		}
		if returned != nil {
			report["error"] = returned.Error()
		}
		if _, err := hostvm.WriteNew(filepath.Join(out, "build.json"), report); err != nil {
			returned = err
		}
	}()
	arguments := []string{"/usr/bin/xcrun", "clang", "-fobjc-arc", "-fblocks", "-framework", "Foundation", "-std=gnu17", "-Wall", "-Wextra", "-Werror", "-O2", source, "-o", binary}
	report["compiler_arguments"] = arguments
	report["compiler_version"] = hostvm.CommandResult(ctx, []string{"/usr/bin/xcrun", "clang", "--version"}, 15*time.Second)
	compiled := hostvm.CommandResult(ctx, arguments, 120*time.Second)
	report["compile"] = compiled
	if hostvm.Int(compiled, "exit_status") != 0 || ctx.Err() != nil {
		return report, failure("NATIVE_MONITOR_BUILD_FAILED")
	}
	if err = os.Chmod(binary, 0500); err != nil {
		return report, err
	}
	if _, err = hostvm.Owned(binary, unix.S_IFREG, 0500); err != nil {
		return report, err
	}
	sha, err := hostvm.HashFile(binary)
	if err != nil {
		return report, err
	}
	body, err := os.ReadFile(source)
	if err != nil || len(body) > 1<<20 || hostvm.HashBytes(body) != pins["experiments/host/integrated_watchdog.m"] {
		return report, failure("NATIVE_MONITOR_SOURCE_CHANGED")
	}
	if err = saveBytes(filepath.Join(out, "integrated_watchdog.m"), body); err != nil {
		return report, err
	}
	report["binary_sha256"] = sha
	report["passed"] = true
	return report, nil
}

func buildBinding(repo, directory string) (*hostvm.Runtime, object, error) {
	if _, err := canonical(repo); err != nil {
		return nil, nil, err
	}
	if _, err := canonical(directory); err != nil {
		return nil, nil, err
	}
	receipt, _, err := hostvm.Read(filepath.Join(directory, "build.json"), 1<<20)
	if err != nil {
		return nil, nil, err
	}
	binary := filepath.Join(directory, "integrated-watchdog")
	if _, err = hostvm.Owned(binary, unix.S_IFREG, 0500); err != nil {
		return nil, nil, err
	}
	actual, err := hostvm.HashFile(binary)
	if err != nil {
		return nil, nil, err
	}
	source := filepath.Join(repo, "experiments/host/integrated_watchdog.m")
	sourceSHA, err := hostvm.HashFile(source)
	if err != nil {
		return nil, nil, err
	}
	copiedSHA, err := hostvm.HashFile(filepath.Join(directory, "integrated_watchdog.m"))
	if err != nil || hostvm.Int(receipt, "schema") != 1 || hostvm.Str(receipt, "kind") != "go_native_monitor_build" || receipt["passed"] != true || receipt["python_dependency"] != false ||
		hostvm.Str(receipt, "binary") != binary || hostvm.Str(receipt, "binary_sha256") != actual || hostvm.Str(receipt, "source_sha256") != sourceSHA || copiedSHA != sourceSHA {
		return nil, nil, failure("NATIVE_MONITOR_BUILD_BINDING_INVALID")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}
	return &hostvm.Runtime{Root: repo, NativeBinary: binary, NativeSource: source, State: filepath.Join(home, "Library/Application Support/FileGate/verification/experiments/host/.build")}, receipt, nil
}
