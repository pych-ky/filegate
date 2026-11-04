package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type diagnosticDigest struct {
	mutex   sync.Mutex
	hash    hash.Hash
	count   int64
	ioError bool
}

func (digest *diagnosticDigest) Write(value []byte) (int, error) {
	digest.mutex.Lock()
	defer digest.mutex.Unlock()
	digest.hash.Write(value)
	digest.count += int64(len(value))
	if strings.Contains(strings.ToLower(string(value)), "no space left on device") || strings.Contains(strings.ToLower(string(value)), "input/output error") {
		digest.ioError = true
	}
	return len(value), nil
}

func avWorker(name string) {
	if noNewPrivileges() != nil {
		os.Exit(2)
	}
	executable := "/filegate-fixtures"
	arguments := []string{executable, "--mode", "av", "--suite", "basic", "--work", "/job/av-parent/run", "--output", "/job/metadata/av-observation.json"}
	switch name {
	case "--format-contract-worker":
		arguments = []string{executable, "--mode", "format-contract", "--work", "/job/av-parent/formats", "--output", "/job/metadata/format-contract.json"}
	case "--av-limits-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "limits", "--work", "/job/av-parent/limits", "--output", "/job/metadata/av-limits.json"}
	case "--av-hard-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "hard", "--work", "/job/av-parent/hard", "--output", "/job/metadata/av-hard.json"}
	case "--av-io-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "io", "--work", "/job/av-parent/io", "--output", "/job/metadata/av-io.json"}
	case "--av-remaining-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "remaining", "--work", "/job/av-parent/remaining", "--output", "/job/metadata/av-remaining.json"}
	case "--av-internal-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "internal", "--work", "/job/av-parent/internal", "--output", "/job/metadata/av-internal.json"}
	case "--av-pe-import-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "pe-import", "--work", "/job/av-parent/pe-import", "--output", "/job/metadata/av-pe-import.json"}
	case "--av-regex-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "regex", "--work", "/job/av-parent/regex", "--output", "/job/metadata/av-regex.json"}
	case "--av-icons-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "icons", "--work", "/job/av-parent/icons", "--output", "/job/metadata/av-icons.json"}
	case "--av-parser-routes-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "parser-routes", "--work", "/job/av-parent/parser-routes", "--output", "/job/metadata/av-parser-routes.json"}
	case "--av-codec-bounds-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "codec-bounds", "--work", "/job/av-parent/codec-bounds", "--output", "/job/metadata/av-codec-bounds.json"}
	case "--av-lzma-wrappers-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "lzma-wrappers", "--work", "/job/av-parent/lzma-wrappers", "--output", "/job/metadata/av-lzma-wrappers.json"}
	case "--av-decoder-wrappers-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "decoder-wrappers", "--work", "/job/av-parent/decoder-wrappers", "--output", "/job/metadata/av-decoder-wrappers.json"}
	case "--av-deflate64-wrapper-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "deflate64-wrapper", "--work", "/job/av-parent/deflate64-wrapper", "--output", "/job/metadata/av-deflate64-wrapper.json"}
	case "--av-tar-scope-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "tar-scope", "--work", "/job/av-parent/tar-scope", "--output", "/job/metadata/av-tar-scope.json"}
	case "--av-text-parsers-worker":
		arguments = []string{executable, "--mode", "av", "--suite", "text-parsers", "--work", "/job/av-parent/text-parsers", "--output", "/job/metadata/av-text-parsers.json"}
	case "--freshclam-library-worker":
		arguments = []string{executable, "--mode", "freshclam-library"}
	case "--freshclam-official-worker":
		if !updateImage() {
			os.Exit(2)
		}
		executable = "/filegate-update-worker"
		arguments = []string{"/filegate-update-worker"}
	case "--freshclam-controlled-worker", "--freshclam-restored-worker":
		mode := "first"
		if name == "--freshclam-restored-worker" {
			mode = "restore"
		}
		arguments = []string{executable, "--mode", "freshclam", "--work", "/job/av-parent/freshclam", "--output", "/job/metadata/freshclam-fixtures.json", "--host-control", mode}
	case "--freshclam-fixture-worker":
		arguments = []string{executable, "--mode", "freshclam", "--work", "/job/av-parent/freshclam", "--output", "/job/metadata/freshclam-fixtures.json"}
	case "--av-worker":
	default:
		os.Exit(2)
	}
	if syscall.Exec(executable, arguments, os.Environ()) != nil {
		os.Exit(2)
	}
}

func runAVWorker(name string) (map[string]any, error) {
	command := restrictedWorker(name)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/job/av-parent", "TMPDIR=/job/adapter-tmp", "TMP=/job/adapter-tmp", "TEMP=/job/adapter-tmp"}
	diagnostic := &diagnosticDigest{hash: sha256.New()}
	command.Stdout, command.Stderr = diagnostic, diagnostic
	err := command.Run()
	exitCode := -1
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	return map[string]any{"output_bytes": diagnostic.count, "output_sha256": hex.EncodeToString(diagnostic.hash.Sum(nil)), "observed_io_error": diagnostic.ioError, "succeeded": err == nil, "exit_code": exitCode}, err
}

func controlledAVWorker(name string, send func(any), reader *bufio.Reader) (map[string]any, error) {
	command := restrictedWorker(name)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/job/av-parent", "TMPDIR=/job/adapter-tmp", "TMP=/job/adapter-tmp", "TEMP=/job/adapter-tmp"}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	diagnostic := &diagnosticDigest{hash: sha256.New()}
	command.Stderr = diagnostic
	if err = command.Start(); err != nil {
		return nil, err
	}
	defer input.Close()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 8192), 1024*1024+1)
	for scanner.Scan() {
		var message map[string]any
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			err = errors.New("invalid control frame")
			break
		}
		updateFrame := name == "--freshclam-official-worker" && (message["event"] == "update_candidate" || message["event"] == "update_chunk" || message["event"] == "update_candidate_end" || message["event"] == "update_done")
		if message["event"] != "freshclam_control_ready" && message["event"] != "freshclam_control_final" && !updateFrame {
			err = errors.New("unexpected control frame")
			break
		}
		send(message)
		reply, readErr := reader.ReadSlice('\n')
		if readErr != nil || len(reply) > 8192 {
			err = errors.New("host control ACK missing")
			break
		}
		if _, err = input.Write(reply); err != nil {
			break
		}
	}
	if err == nil {
		err = scanner.Err()
	}
	if err != nil {
		command.Process.Kill()
	}
	waitErr := command.Wait()
	if err == nil {
		err = waitErr
	}
	return map[string]any{"output_bytes": diagnostic.count, "output_sha256": hex.EncodeToString(diagnostic.hash.Sum(nil)), "observed_io_error": diagnostic.ioError, "succeeded": err == nil, "exit_code": command.ProcessState.ExitCode()}, err
}

func runAVFixture(name string, send func(any), reader *bufio.Reader) {
	started := time.Now()
	sequence := 0
	progress := func(phase, checkpoint string) {
		if name == "freshclam-adapter" {
			sequence++
			send(map[string]any{"event": "freshclam_progress", "fixture": name, "phase": phase, "checkpoint": checkpoint, "sequence": sequence, "elapsed_ms": time.Since(started).Milliseconds()})
		}
	}
	packages, _ := filepath.Glob("/.packages/*.apk")
	if len(packages) == 0 {
		send(map[string]any{"event": "av_error", "reason": "PACKAGES_MISSING"})
		return
	}
	if name == "av-hard" || name == "av-remaining" || name == "av-parser-routes" || name == "av-decoder-wrappers" {
		diagnostic, _ := filepath.Glob("/build-packages/*.apk")
		if len(diagnostic) == 0 {
			send(map[string]any{"event": "av_error", "reason": "PACKAGES_MISSING"})
			return
		}
		seen := make(map[string]bool)
		for _, path := range packages {
			seen[filepath.Base(path)] = true
		}
		for _, path := range diagnostic {
			if !seen[filepath.Base(path)] {
				packages = append(packages, path)
				seen[filepath.Base(path)] = true
			}
		}
	}
	install := exec.Command("/sbin/apk", append([]string{"add", "--no-network"}, packages...)...)
	install.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/job/adapter-tmp"}
	progress("apk", "started")
	if install.Run() != nil {
		send(map[string]any{"event": "av_error", "reason": "PACKAGE_VERIFICATION_FAILED"})
		return
	}
	progress("apk", "completed")
	if installFixtureProfile() != nil {
		send(map[string]any{"event": "av_error", "reason": "FIXTURE_PROFILE_INVALID"})
		return
	}
	progress("library", "started")
	for _, path := range []string{"/job/av-parent"} {
		if os.MkdirAll(path, 0755) != nil || os.Chown(path, 65534, 65534) != nil {
			send(map[string]any{"event": "av_error", "reason": "WORKSPACE_IO_ERROR"})
			return
		}
	}
	action, event, reportPath := "--av-worker", "av_result", "/job/metadata/av-observation.json"
	var fixedAdapter any
	if name == "av-limits" {
		action, event, reportPath = "--av-limits-worker", "av_limits_result", "/job/metadata/av-limits.json"
	}
	if name == "av-hard" {
		action, event, reportPath = "--av-hard-worker", "av_hard_result", "/job/metadata/av-hard.json"
	}
	if name == "av-io" {
		action, event, reportPath = "--av-io-worker", "av_io_result", "/job/metadata/av-io.json"
	}
	if name == "av-remaining" {
		action, event, reportPath = "--av-remaining-worker", "av_remaining_result", "/job/metadata/av-remaining.json"
	}
	if name == "av-internal" {
		action, event, reportPath = "--av-internal-worker", "av_internal_result", "/job/metadata/av-internal.json"
	}
	if name == "av-pe-import" {
		action, event, reportPath = "--av-pe-import-worker", "av_pe_import_result", "/job/metadata/av-pe-import.json"
	}
	if name == "av-regex" {
		action, event, reportPath = "--av-regex-worker", "av_regex_result", "/job/metadata/av-regex.json"
	}
	if name == "av-icons" {
		action, event, reportPath = "--av-icons-worker", "av_icons_result", "/job/metadata/av-icons.json"
	}
	if name == "av-parser-routes" {
		action, event, reportPath = "--av-parser-routes-worker", "av_parser_routes_result", "/job/metadata/av-parser-routes.json"
	}
	if name == "av-codec-bounds" {
		action, event, reportPath = "--av-codec-bounds-worker", "av_codec_bounds_result", "/job/metadata/av-codec-bounds.json"
	}
	if name == "av-lzma-wrappers" {
		action, event, reportPath = "--av-lzma-wrappers-worker", "av_lzma_wrappers_result", "/job/metadata/av-lzma-wrappers.json"
	}
	if name == "av-decoder-wrappers" {
		action, event, reportPath = "--av-decoder-wrappers-worker", "av_decoder_wrappers_result", "/job/metadata/av-decoder-wrappers.json"
	}
	if name == "av-deflate64-wrapper" {
		action, event, reportPath = "--av-deflate64-wrapper-worker", "av_deflate64_wrapper_result", "/job/metadata/av-deflate64-wrapper.json"
	}
	if name == "av-tar-scope" {
		action, event, reportPath = "--av-tar-scope-worker", "av_tar_scope_result", "/job/metadata/av-tar-scope.json"
	}
	if name == "av-text-parsers" {
		action, event, reportPath = "--av-text-parsers-worker", "av_text_parsers_result", "/job/metadata/av-text-parsers.json"
	}
	if name == "format-contract" {
		action, event, reportPath = "--format-contract-worker", "format_contract_result", "/job/metadata/format-contract.json"
	}
	if name == "freshclam-adapter" {
		var err error
		fixedAdapter, err = runAVWorker("--freshclam-library-worker")
		if err != nil {
			send(map[string]any{"event": "av_error", "reason": "FIXED_ADAPTER_VERIFICATION_FAILED", "diagnostics": fixedAdapter})
			return
		}
		progress("library", "completed")
		action, event, reportPath = "--freshclam-fixture-worker", "freshclam_result", "/job/metadata/freshclam-fixtures.json"
	}
	progress("fixture", "started")
	var diagnostics map[string]any
	var runErr error
	controlMode := ""
	if name == "freshclam-adapter" {
		input, _ := os.ReadFile("/job/input/object")
		if len(input) > 0 && input[0] == '{' {
			var request map[string]string
			if json.Unmarshal(input, &request) != nil || len(request) != 1 || (request["filegate_control_mode"] != "first" && request["filegate_control_mode"] != "restore") {
				send(map[string]any{"event": "av_error", "reason": "UPDATE_CONTROL_INVALID"})
				return
			}
			controlMode = request["filegate_control_mode"]
		}
	}
	if controlMode != "" {
		action = "--freshclam-controlled-worker"
		if controlMode == "restore" {
			action = "--freshclam-restored-worker"
		}
		diagnostics, runErr = controlledAVWorker(action, send, reader)
	} else {
		diagnostics, runErr = runAVWorker(action)
	}
	if runErr == nil {
		progress("fixture", "completed")
	}
	if diagnostics["observed_io_error"] == true {
		state := fsRecord("/job")
		state["reason"] = "WORKSPACE_IO_ERROR"
		send(state)
		select {}
	}
	file, openErr := os.OpenFile(reportPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if openErr != nil {
		send(map[string]any{"event": "av_error", "reason": "REPORT_VALIDATION_FAILED", "diagnostics": diagnostics})
		return
	}
	defer file.Close()
	bytes, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	var report any
	if readErr != nil || len(bytes) > 1024*1024 || json.Unmarshal(bytes, &report) != nil {
		send(map[string]any{"event": "av_error", "reason": "REPORT_VALIDATION_FAILED"})
		return
	}
	send(map[string]any{"event": event, "runner_success": runErr == nil, "diagnostics": diagnostics, "fixed_adapter": fixedAdapter, "report": report, "verdict": "NOT_A_PRODUCT_SCAN"})
}
