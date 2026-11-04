package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// This guest runs fixed inspection modes and never authorizes release.
func main() {
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}) != nil {
		os.Exit(2)
	}
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--worker":
			worker()
			return
		case "--product-worker":
			productWorker()
			return
		case "--freshclam-official-worker":
			avWorker(os.Args[1])
			return
		case "--isolation-probe":
			isolationWorker()
			return
		case "--workspace-monitor":
			monitorWorker(false)
			return
		case "--workspace-monitor-failure":
			monitorWorker(true)
			return
		case "--format-contract-worker", "--av-worker", "--av-limits-worker", "--av-hard-worker", "--av-io-worker", "--av-remaining-worker", "--av-internal-worker", "--av-pe-import-worker", "--av-regex-worker", "--av-icons-worker", "--av-parser-routes-worker", "--av-codec-bounds-worker", "--av-lzma-wrappers-worker", "--av-decoder-wrappers-worker", "--av-deflate64-wrapper-worker", "--av-tar-scope-worker", "--av-text-parsers-worker", "--freshclam-library-worker", "--freshclam-fixture-worker", "--freshclam-controlled-worker", "--freshclam-restored-worker":
			avWorker(os.Args[1])
			return
		}
	}
	if len(os.Args) == 3 && os.Args[1] == "--fixture-worker" {
		fixtureWorker(os.Args[2])
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--product-av-worker" {
		productAVWorker(os.Args[2])
		return
	}
	if os.Getpid() != 1 || len(os.Args) != 1 {
		panic("guest must be PID 1")
	}
	channel, err := os.OpenFile("/dev/vport0p1", os.O_RDWR, 0)
	if err != nil {
		fmt.Println("FILEGATE_CHANNEL_FAILED")
		syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
		return
	}
	defer syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	var mutex sync.Mutex
	send := func(value any) {
		mutex.Lock()
		defer mutex.Unlock()
		json.NewEncoder(channel).Encode(value)
	}
	ready, err := preflight()
	if err != nil {
		send(map[string]any{"event": "boot_error", "reason": "WORKSPACE_CONFIGURATION_ERROR", "detail": err.Error(), "diagnostics": ready})
		return
	}
	send(ready)
	monitor, err := startMonitor(send, false)
	if err != nil {
		send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "RESOURCE_MONITOR_FAILED"})
		return
	}
	defer func() { monitor.Process.Kill(); monitor.Wait() }()
	reader := bufio.NewReaderSize(channel, 16385)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		send(map[string]any{"event": "protocol_error"})
		return
	}
	var start startRequest
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&start)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	if decodeErr != nil || trailingErr != io.EOF || len(line) > 16384 || !validStart(start) {
		send(map[string]any{"event": "protocol_error"})
		return
	}
	file, err := os.OpenFile("/job/input/object", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
	if err != nil {
		send(map[string]any{"event": "input_error", "reason": "WORKSPACE_IO_ERROR"})
		return
	}
	hash := sha256.New()
	n, copyErr := io.CopyN(io.MultiWriter(file, hash), reader, start.Size)
	syncErr, closeErr := file.Sync(), file.Close()
	actual := hex.EncodeToString(hash.Sum(nil))
	if copyErr != nil || syncErr != nil || closeErr != nil || n != start.Size {
		send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "WORKSPACE_IO_ERROR"})
		select {}
	}
	if actual != start.SHA256 {
		send(map[string]any{"event": "input_error", "reason": "INPUT_HASH_MISMATCH", "sha256": actual, "byte_size": n})
		select {}
	}
	if start.Fixture == "product-inspect" {
		runProduct(start, send)
		select {}
	}
	if start.Fixture == "product-update" {
		runProductUpdate(send, reader)
		select {}
	}
	if start.Fixture == "product-av-normalization" {
		runProductAVFixture(send)
		select {}
	}
	if operation := fixtureOperation(start.Fixture); operation != nil {
		send(operation)
		ack := make([]byte, len("FIXTURE_READY\n"))
		if _, err := io.ReadFull(reader, ack); err != nil || string(ack) != "FIXTURE_READY\n" {
			send(map[string]any{"event": "protocol_error", "reason": "FIXTURE_ACK_MISSING"})
			select {}
		}
	}
	if start.Fixture == "workspace-monitor-stop" {
		time.Sleep(2 * time.Second)
		if monitor.Process.Signal(syscall.SIGSTOP) != nil {
			send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "RESOURCE_MONITOR_FAILED"})
			select {}
		}
		send(map[string]any{"event": "fixture_observation", "fixture": start.Fixture, "evidence_kind": "guest_monitor_SIGSTOP", "monitor_pid": monitor.Process.Pid, "signal_confirmed": true})
		select {}
	}
	if start.Fixture == "workspace-monitor-failure" {
		monitor.Process.Kill()
		monitor.Wait()
		monitor, err = startMonitor(send, true)
		if err != nil {
			send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "RESOURCE_MONITOR_FAILED"})
			select {}
		}
		time.Sleep(2 * time.Second)
		if os.Remove("/job/metadata/monitor-target") != nil {
			send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "WORKSPACE_IO_ERROR"})
			select {}
		}
		send(map[string]any{"event": "fixture_observation", "fixture": start.Fixture, "evidence_kind": "guest_monitor_statfs_ENOENT", "target_removed": true})
		select {}
	}
	if start.Fixture == "workspace-boundary" {
		send(map[string]any{"event": "fixture_result", "result": boundaryFixture(), "verdict": "NOT_A_PRODUCT_SCAN"})
		select {}
	}
	if start.Fixture == "format-contract" || start.Fixture == "av-observation" || start.Fixture == "av-limits" || start.Fixture == "av-hard" || start.Fixture == "av-io" || start.Fixture == "av-remaining" || start.Fixture == "av-internal" || start.Fixture == "av-pe-import" || start.Fixture == "av-regex" || start.Fixture == "av-icons" || start.Fixture == "av-parser-routes" || start.Fixture == "av-codec-bounds" || start.Fixture == "av-lzma-wrappers" || start.Fixture == "av-decoder-wrappers" || start.Fixture == "av-deflate64-wrapper" || start.Fixture == "av-tar-scope" || start.Fixture == "av-text-parsers" || start.Fixture == "freshclam-adapter" {
		runAVFixture(start.Fixture, send, reader)
		select {}
	}
	if start.Fixture != "transfer" && start.Fixture != "input-hash-mismatch" {
		result, workerErr := boundedWorker("--fixture-worker", start.Fixture)
		if workerErr != nil {
			send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "WORKSPACE_IO_ERROR"})
			select {}
		}
		if reason, _ := result["reason"].(string); reason != "" {
			send(map[string]any{"event": "fixture_observation", "result": result})
			state := fsRecord("/job")
			state["reason"] = reason
			send(state)
			select {}
		}
		send(map[string]any{"event": "fixture_result", "result": result, "verdict": "NOT_A_PRODUCT_SCAN"})
		select {}
	}
	result, err := boundedWorker("--worker")
	if err != nil {
		send(map[string]any{"event": "worker_error"})
		return
	}
	send(map[string]any{"event": "result", "job_id": start.JobID, "attempt_id": start.AttemptID, "sha256": actual, "byte_size": n, "worker": result, "verdict": "NOT_A_PRODUCT_SCAN"})
	// The host validates the report before stopping the VM; monitor heartbeats continue.
	select {}
}

func worker() {
	if noNewPrivileges() != nil {
		os.Exit(2)
	}
	file, err := os.Open("/job/input/object")
	if err != nil {
		os.Exit(2)
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, file)
	if err != nil {
		os.Exit(2)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"uid": os.Getuid(), "gid": os.Getgid(), "sha256": hex.EncodeToString(hash.Sum(nil)), "byte_size": n})
}
