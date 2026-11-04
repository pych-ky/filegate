package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const rawBytes = int64(4294967296)
const workspaceMargin = uint64(64 * 1024 * 1024)
const capacityCacheStrategy = "fsync_then_fadvise_dontneed_all_files_every_16_MiB"

var writeDirectories = []string{"/etc", "/var/log", "/var/cache", "/var/lib", "/root", "/home", "/tmp", "/var/tmp", "/run", "/job/input", "/job/extract", "/job/avtmp", "/job/adapter-tmp", "/job/metadata"}
var pressureDirectories = map[string][]string{
	"workspace-tmp":         {"/tmp/filegate-stage0"},
	"workspace-var-tmp":     {"/var/tmp/filegate-stage0"},
	"workspace-run":         {"/run/filegate-stage0"},
	"workspace-avtmp":       {"/job/avtmp"},
	"workspace-extract":     {"/job/extract"},
	"workspace-mixed":       {"/tmp/filegate-stage0", "/var/tmp/filegate-stage0", "/run/filegate-stage0", "/job/avtmp", "/job/extract"},
	"workspace-root-copyup": {"/etc"},
}

func noNewPrivileges() error {
	value, _, err := syscall.Syscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0)
	if err != 0 {
		return err
	}
	if value != 1 {
		return fmt.Errorf("inherited no-new-privs missing")
	}
	return nil
}

func fsRecord(path string) map[string]any {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return map[string]any{"event": "workspace", "free_bytes": uint64(0), "free_inodes": uint64(0), "reason": "RESOURCE_MONITOR_FAILED"}
	}
	reason := ""
	if fs.Bavail*uint64(fs.Bsize) < workspaceMargin || fs.Ffree < 128 {
		reason = "WORKSPACE_LIMIT"
	}
	return map[string]any{"event": "workspace", "free_bytes": fs.Bavail * uint64(fs.Bsize), "free_inodes": fs.Ffree, "reason": reason}
}

func monitorWorker(failure bool) {
	path := "/job"
	if failure {
		path = "/job/metadata/monitor-target"
	}
	encoder := json.NewEncoder(os.Stdout)
	for {
		record := fsRecord(path)
		if encoder.Encode(record) != nil {
			os.Exit(2)
		}
		if record["reason"] != "" {
			return
		}
		time.Sleep(time.Second)
	}
}

func startMonitor(send func(any), failure bool) (*exec.Cmd, error) {
	argument := "--workspace-monitor"
	if failure {
		argument = "--workspace-monitor-failure"
	}
	command := exec.Command("/vm-guest", argument)
	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = command.Start(); err != nil {
		return nil, err
	}
	go func() {
		defer pipe.Close()
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 4096), 4096)
		for scanner.Scan() {
			var record map[string]any
			if json.Unmarshal(scanner.Bytes(), &record) != nil || record["event"] != "workspace" {
				send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "RESOURCE_MONITOR_FAILED"})
				return
			}
			send(record)
		}
		if scanner.Err() != nil {
			send(map[string]any{"event": "workspace", "free_bytes": 0, "free_inodes": 0, "reason": "RESOURCE_MONITOR_FAILED"})
		}
	}()
	return command, nil
}

func restrictedWorker(argument string, extra ...string) *exec.Cmd {
	command := exec.Command("/bin/busybox", append([]string{"setpriv", "--no-new-privs", "/vm-guest", argument}, extra...)...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	return command
}

func boundedWorker(argument string, extra ...string) (map[string]any, error) {
	command := restrictedWorker(argument, extra...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=/job/avtmp", "TMP=/job/avtmp", "TEMP=/job/avtmp"}
	pipe, err := command.StdoutPipe()
	if err != nil {
		return map[string]any{"execution_error": "OUTPUT_PIPE_FAILED"}, err
	}
	if err = command.Start(); err != nil {
		return map[string]any{"execution_error": "WORKER_START_FAILED", "errno": errnoRecord(err)}, err
	}
	output, readErr := io.ReadAll(io.LimitReader(pipe, 65537))
	if readErr != nil || len(output) > 65536 {
		command.Process.Kill()
		command.Wait()
		return map[string]any{"execution_error": "OUTPUT_LIMIT_OR_READ_FAILED"}, fmt.Errorf("worker output limit or read failure")
	}
	waitErr := command.Wait()
	var result map[string]any
	if json.Unmarshal(output, &result) != nil || result == nil {
		return map[string]any{"execution_error": "WORKER_EXIT_OR_REPORT_INVALID", "exit_code": command.ProcessState.ExitCode()}, fmt.Errorf("worker report invalid")
	}
	result["execution"] = map[string]any{"exit_code": command.ProcessState.ExitCode(), "completed": waitErr == nil, "launcher": "fixed_busybox_setpriv_no_new_privs_before_Go_runtime"}
	return result, waitErr
}

func preflight() (map[string]any, error) {
	definitionProfile, profileSHA, err := readProductDefinitionProfile(updateImage())
	if err != nil {
		return nil, err
	}
	for _, path := range append(append([]string{}, writeDirectories...), "/tmp/filegate-stage0", "/var/tmp/filegate-stage0", "/run/filegate-stage0", "/job/adapter-tmp/mount-probe", "/job/metadata/monitor-target") {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, err
		}
	}
	for _, path := range []string{"/tmp/filegate-stage0", "/var/tmp/filegate-stage0", "/run/filegate-stage0", "/job/extract", "/job/avtmp", "/job/adapter-tmp", "/job/metadata"} {
		if err := os.Chown(path, 65534, 65534); err != nil {
			return nil, err
		}
	}
	blocks := map[string]any{}
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil || len(entries) != 3 {
		return nil, fmt.Errorf("unknown block device")
	}
	for _, entry := range entries {
		name := entry.Name()
		sectors, ok := map[string]string{"vda": "2097152", "vdb": "32768", "vdc": "8388608"}[name]
		if name == "vdb" && definitionProfile != nil {
			sectors = "2097152"
		}
		if !ok {
			return nil, fmt.Errorf("unknown block device")
		}
		size, e1 := os.ReadFile("/sys/class/block/" + name + "/size")
		readOnly, e2 := os.ReadFile("/sys/class/block/" + name + "/ro")
		ro := "1"
		if name == "vdc" {
			ro = "0"
		}
		if e1 != nil || e2 != nil || strings.TrimSpace(string(size)) != sectors || strings.TrimSpace(string(readOnly)) != ro {
			return nil, fmt.Errorf("block capacity or readonly mismatch")
		}
		blocks[name] = map[string]string{"sectors": sectors, "read_only": ro}
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || len(mounts) > 65536 {
		return nil, fmt.Errorf("mount inventory unavailable")
	}
	if err = validateMounts(string(mounts)); err != nil {
		return nil, err
	}
	networks, err := filepath.Glob("/sys/class/net/*")
	if err != nil || (len(networks) != 1 || networks[0] != "/sys/class/net/lo") && !updateNetworkDevices(networks) {
		return nil, fmt.Errorf("network device found")
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil || loopback.Flags&net.FlagUp == 0 || loopback.Flags&net.FlagLoopback == 0 {
		return nil, fmt.Errorf("loopback is not up")
	}
	addresses, err := loopback.Addrs()
	if err != nil {
		return nil, fmt.Errorf("loopback addresses unavailable")
	}
	ipv4Loopback := false
	for _, address := range addresses {
		if address.String() == "127.0.0.1/8" {
			ipv4Loopback = true
		} else if address.String() != "::1/128" {
			return nil, fmt.Errorf("unexpected loopback address")
		}
	}
	if !ipv4Loopback {
		return nil, fmt.Errorf("IPv4 loopback missing")
	}
	namespaces, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err != nil || strings.TrimSpace(string(namespaces)) != "0" {
		return nil, fmt.Errorf("user namespaces not disabled")
	}
	swaps, err := os.ReadFile("/proc/swaps")
	if err != nil || len(strings.Split(strings.TrimSpace(string(swaps)), "\n")) != 1 {
		return nil, fmt.Errorf("swap is not disabled")
	}
	writes, err := checkWriteDestinations()
	if err != nil {
		return nil, err
	}
	isolation, err := boundedWorker("--isolation-probe")
	if err != nil || isolation["all_denied"] != true {
		failed := "NONROOT_ISOLATION_CHECK_FAILED"
		if err != nil {
			failed = "NONROOT_WORKER_EXECUTION_FAILED"
		}
		return map[string]any{"schema": 1, "failed_check": failed, "isolation": isolation, "block_devices": blocks,
			"completed_checks": map[string]bool{"exact_block_inventory": true, "mount_allowlist": true, "loopback_only_up": true, "user_namespaces_limit_zero": true, "swap_disabled": true, "all_write_destinations_on_fixed_work": true, "root_copyup_lower_unchanged": true}, "write_destinations": writes}, fmt.Errorf("nonroot isolation preflight failed")
	}
	definitionProbe := "/.definitions/SYNTHETIC_ONLY"
	if definitionProfile != nil {
		definitionProbe = productDefinitionProfile
	}
	for _, path := range []string{"/.base/etc/filegate-stage0-copyup-small", definitionProbe} {
		file, openErr := os.OpenFile(path, os.O_WRONLY, 0)
		if openErr == nil {
			file.Close()
			return nil, fmt.Errorf("readonly filesystem accepted write open")
		}
		if !errors.Is(openErr, syscall.EROFS) {
			return nil, fmt.Errorf("readonly write denial not established")
		}
	}
	ready := map[string]any{"event": "ready", "schema": 2, "blocks": blocks, "mountinfo": string(mounts), "net_devices": networks,
		"write_destinations": writes, "nonroot_isolation": isolation, "swap_disabled": true, "user_namespaces_disabled": true, "loopback_up": true, "pid": 1}
	if definitionProfile != nil {
		ready["definition_profile_sha256"] = profileSHA
	}
	return ready, nil
}

func validateMounts(text string) error {
	expected := map[string]string{"/": "overlay", "/.base": "ext4", "/.definitions": "ext4", "/.work": "ext4", "/job": "ext4", "/dev": "devtmpfs", "/proc": "proc", "/sys": "sysfs", "/dev/shm": "tmpfs"}
	found := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		sections := strings.Split(line, " - ")
		if len(sections) != 2 {
			return fmt.Errorf("invalid mount inventory")
		}
		front, back := strings.Fields(sections[0]), strings.Fields(sections[1])
		if len(front) < 6 || len(back) < 3 {
			return fmt.Errorf("invalid mount inventory")
		}
		path := front[4]
		if found[path] || expected[path] == "" || expected[path] != back[0] {
			return fmt.Errorf("unknown mount")
		}
		options := "," + front[5] + ","
		if (path == "/.base" || path == "/.definitions") && !strings.Contains(options, ",ro,") {
			return fmt.Errorf("readonly mount mismatch")
		}
		if (path == "/.work" || path == "/job") && back[1] != "/dev/vdc" {
			return fmt.Errorf("unknown writable block source")
		}
		if path == "/dev/shm" && (!strings.Contains(","+back[2]+",", ",size=65536k,") || !strings.Contains(","+back[2]+",", ",nr_inodes=4096,")) {
			return fmt.Errorf("shared memory budget mismatch")
		}
		found[path] = true
	}
	if len(found) != len(expected) {
		return fmt.Errorf("mount missing")
	}
	return nil
}

func checkWriteDestinations() ([]map[string]any, error) {
	var work syscall.Statfs_t
	if syscall.Statfs("/.work", &work) != nil || work.Type != 0xef53 {
		return nil, fmt.Errorf("work is not ext4")
	}
	rows := []map[string]any{}
	for _, directory := range writeDirectories {
		path := directory + "/filegate-stage0-writecheck"
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		value := []byte("synthetic fixed write-destination probe\n")
		_, writeErr := file.Write(value)
		syncErr, closeErr := file.Sync(), file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return nil, fmt.Errorf("write/sync probe failed")
		}
		physical := "/.work/upper" + path
		if strings.HasPrefix(directory, "/job/") {
			physical = "/.work/job/" + strings.TrimPrefix(path, "/job/")
		}
		actual, err := os.ReadFile(physical)
		var fs syscall.Statfs_t
		if err != nil || !bytes.Equal(actual, value) || syscall.Statfs(physical, &fs) != nil || fs.Fsid != work.Fsid {
			return nil, fmt.Errorf("write escaped work filesystem")
		}
		rows = append(rows, map[string]any{"path": directory, "physical": physical, "work_fsid_match": true, "write_sync_confirmed": true})
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	seed := "/etc/filegate-stage0-copyup-small"
	lower := "/.base" + seed
	original, err := os.ReadFile(lower)
	if err != nil || len(original) != 1024*1024 {
		return nil, fmt.Errorf("copyup seed missing")
	}
	file, err := os.OpenFile(seed, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	_, err = file.WriteAt([]byte("C"), 0)
	syncErr, closeErr := file.Sync(), file.Close()
	upper, upperErr := os.ReadFile("/.work/upper" + seed)
	unchanged, lowerErr := os.ReadFile(lower)
	if err != nil || syncErr != nil || closeErr != nil || upperErr != nil || lowerErr != nil || len(upper) != len(original) || upper[0] != 'C' || !bytes.Equal(original, unchanged) {
		return nil, fmt.Errorf("root copyup not established")
	}
	sum := sha256.Sum256(original)
	rows = append(rows, map[string]any{"path": seed, "copyup_bytes": len(upper), "lower_unchanged": true, "lower_sha256": hex.EncodeToString(sum[:])})
	return rows, nil
}

func errnoRecord(err error) map[string]any {
	var code syscall.Errno
	if err == nil {
		return map[string]any{"operation_succeeded": true, "number": 0, "name": "NONE"}
	}
	name := "OTHER"
	if errors.As(err, &code) {
		if known, ok := map[syscall.Errno]string{syscall.EPERM: "EPERM", syscall.EACCES: "EACCES", syscall.ENOSPC: "ENOSPC", syscall.EINVAL: "EINVAL", syscall.ENOSYS: "ENOSYS", syscall.ENOENT: "ENOENT"}[code]; ok {
			name = known
		}
	}
	return map[string]any{"operation_succeeded": false, "number": uint64(code), "name": name}
}

type probeOutput struct{ data []byte }

func (output *probeOutput) Write(value []byte) (int, error) {
	if len(output.data)+len(value) > 4096 {
		return 0, fmt.Errorf("fixed probe output limit")
	}
	output.data = append(output.data, value...)
	return len(value), nil
}

func userNamespaceProbe() map[string]any {
	command := exec.Command("/bin/busybox", "unshare", "-U", "/bin/busybox", "true")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output := &probeOutput{}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	exit := -1
	if command.ProcessState != nil {
		exit = command.ProcessState.ExitCode()
	}
	name, number := "UNRECOGNIZED", 0
	if exit == 1 {
		switch string(output.data) {
		case "unshare: unshare(0x10000000): Operation not permitted\n":
			name, number = "EPERM", int(syscall.EPERM)
		case "unshare: unshare(0x10000000): No space left on device\n":
			name, number = "ENOSPC", int(syscall.ENOSPC)
		}
	}
	return map[string]any{"passed": err != nil && exit == 1 && number != 0, "exit_code": exit, "reported_errno_name": name, "reported_errno_number": number,
		"evidence_kind": "fixed_single_thread_busybox_unshare_exit_and_errno_text", "flags": "CLONE_NEWUSER", "output_bytes": len(output.data)}
}

func statusFlags(status []byte) (bool, bool) {
	capabilitiesZero, nnp := false, false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			capabilitiesZero = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")) == "0000000000000000"
		}
		if strings.HasPrefix(line, "NoNewPrivs:") {
			nnp = strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:")) == "1"
		}
	}
	return capabilitiesZero, nnp
}

func isolationWorker() {
	if noNewPrivileges() != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "all_denied": false, "startup_error": "INHERITED_NO_NEW_PRIVS_MISSING"})
		os.Exit(2)
	}
	mountErr := syscall.Mount("tmpfs", "/job/adapter-tmp/mount-probe", "tmpfs", syscall.MS_NODEV|syscall.MS_NOSUID, "size=1m,nr_inodes=16")
	namespace := userNamespaceProbe()
	block, blockErr := os.OpenFile("/dev/vdc", os.O_RDWR, 0)
	if blockErr == nil {
		block.Close()
	}
	status, statusErr := os.ReadFile("/proc/self/status")
	capabilitiesZero, nnp := statusFlags(status)
	threads, threadErr := filepath.Glob("/proc/self/task/*/status")
	allThreads := threadErr == nil && len(threads) > 0 && len(threads) <= 128
	if allThreads {
		for _, path := range threads {
			data, readErr := os.ReadFile(path)
			caps, restricted := statusFlags(data)
			if readErr != nil || !caps || !restricted {
				allThreads = false
			}
		}
	}
	var core syscall.Rlimit
	coreErr := syscall.Getrlimit(syscall.RLIMIT_CORE, &core)
	checks := map[string]bool{"uid_gid": os.Getuid() == 65534 && os.Getgid() == 65534 && os.Geteuid() == 65534 && os.Getegid() == 65534,
		"capabilities_zero": statusErr == nil && capabilitiesZero, "no_new_privs": statusErr == nil && nnp,
		"all_observed_threads_restricted": allThreads, "core_dump_disabled": coreErr == nil && core.Cur == 0 && core.Max == 0,
		"mount_denied": errors.Is(mountErr, syscall.EPERM), "user_namespace_denied": namespace["passed"] == true,
		"block_open_denied": errors.Is(blockErr, syscall.EACCES) || errors.Is(blockErr, syscall.EPERM)}
	denied := true
	for _, passed := range checks {
		denied = denied && passed
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "uid": os.Getuid(), "gid": os.Getgid(), "all_denied": denied, "checks": checks,
		"mount": errnoRecord(mountErr), "user_namespace": namespace, "block_open": errnoRecord(blockErr), "status_read": errnoRecord(statusErr),
		"threads_checked": len(threads), "core": map[string]any{"cur": core.Cur, "max": core.Max, "read": errnoRecord(coreErr)}})
}

func fixtureWorker(name string) {
	if noNewPrivileges() != nil {
		os.Exit(2)
	}
	result := map[string]any{"fixture": name, "uid": os.Getuid(), "evidence_kind": "target_guest_syscalls", "bytes_written": int64(0)}
	if name == "workspace-block-io" {
		file, err := os.OpenFile("/job/extract/block-io-probe", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, err = file.Write([]byte("synthetic block error probe\n"))
			if err == nil {
				err = file.Sync()
			}
			file.Close()
		}
		result["reason"] = "WORKSPACE_IO_ERROR"
		result["observed_error"] = fmt.Sprint(err)
		result["unexpected_guest_completion"] = true
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}
	if name == "workspace-sync-failure" {
		file, err := os.OpenFile("/job/extract/sync-injection", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, err = file.Write([]byte("synthetic sync-fault input\n"))
			if err == nil {
				err = syscall.EIO
			}
			file.Close()
		}
		result["reason"] = "WORKSPACE_IO_ERROR"
		result["evidence_kind"] = "explicit_sync_error_fault_injection_NOT_media_failure"
		result["observed_error"] = fmt.Sprint(err)
		result["workspace_after_error"] = fsRecord("/job")
		result["error_latched_despite_available_space"] = true
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}
	if name == "workspace-inodes" {
		created := 0
		for {
			state := fsRecord("/job")
			if state["reason"] != "" {
				result["reason"], result["files_created"], result["last_workspace"] = state["reason"], created, state
				break
			}
			file, err := os.OpenFile("/job/extract/inode-"+strconv.Itoa(created), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				result["reason"], result["observed_error"] = "WORKSPACE_IO_ERROR", fmt.Sprint(err)
				break
			}
			if closeErr := file.Close(); closeErr != nil {
				result["reason"], result["observed_error"] = "WORKSPACE_IO_ERROR", fmt.Sprint(closeErr)
				break
			}
			created++
		}
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}
	directories, capacityFixture := pressureDirectories[name]
	if name == "workspace-reuse" {
		directories = []string{"/job/extract"}
	}
	if len(directories) == 0 {
		os.Exit(2)
	}
	buffer := bytes.Repeat([]byte{0x47}, 1024*1024)
	var written int64
	cacheAdviceSucceeded := 0
	if capacityFixture {
		result["cache_strategy"] = capacityCacheStrategy
	}
	files := make([]*os.File, len(directories))
	for index, directory := range directories {
		path := directory + "/synthetic-pressure"
		flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY
		if name == "workspace-root-copyup" {
			path, flags = "/etc/filegate-stage0-copyup.seed", os.O_WRONLY|os.O_APPEND
		}
		file, err := os.OpenFile(path, flags, 0600)
		if err != nil {
			result["reason"], result["observed_error"] = "WORKSPACE_IO_ERROR", fmt.Sprint(err)
			json.NewEncoder(os.Stdout).Encode(result)
			return
		}
		files[index] = file
		defer file.Close()
	}
	for index := 0; ; index++ {
		state := fsRecord("/job")
		if state["reason"] != "" {
			result["reason"], result["last_workspace"] = state["reason"], state
			break
		}
		file := files[index%len(files)]
		n, err := file.Write(buffer)
		written += int64(n)
		if err == nil && index%16 == 15 {
			if capacityFixture {
				// Request clean guest cache release while preserving disk contents and allocation.
				for _, target := range files {
					if err = target.Sync(); err != nil {
						break
					}
					const posixFadvDontNeed = 4
					_, _, adviceErr := syscall.Syscall6(syscall.SYS_FADVISE64, target.Fd(), 0, 0, posixFadvDontNeed, 0, 0)
					if adviceErr != 0 {
						err = fmt.Errorf("fadvise DONTNEED: %w", adviceErr)
						break
					}
					cacheAdviceSucceeded++
				}
			} else {
				err = file.Sync()
			}
		}
		if err != nil {
			result["reason"], result["observed_error"] = "WORKSPACE_IO_ERROR", fmt.Sprint(err)
			break
		}
		if name == "workspace-reuse" && (index+1)%1024 == 0 {
			if err = file.Sync(); err != nil {
				result["reason"], result["observed_error"] = "WORKSPACE_IO_ERROR", fmt.Sprint(err)
				break
			}
			if err = file.Truncate(0); err != nil {
				result["reason"], result["observed_error"] = "WORKSPACE_IO_ERROR", fmt.Sprint(err)
				break
			}
			if _, err = file.Seek(0, io.SeekStart); err != nil || file.Sync() != nil {
				result["reason"] = "WORKSPACE_IO_ERROR"
				break
			}
			if written == 5*1024*1024*1024 {
				result["reason"], result["cumulative_exceeds_fixed_capacity"] = "", written > rawBytes
				break
			}
		}
	}
	if capacityFixture {
		result["cache_advice_successes"] = cacheAdviceSucceeded
	}
	result["bytes_written"], result["payload_generator"] = written, "repeat byte 0x47 in 1 MiB writes"
	json.NewEncoder(os.Stdout).Encode(result)
}

func boundaryFixture() map[string]any {
	file, err := os.OpenFile("/dev/vdc", os.O_RDWR, 0)
	if err != nil {
		return map[string]any{"fixture": "workspace-boundary", "expectation_met": false, "open_error": fmt.Sprint(err)}
	}
	defer file.Close()
	n, writeErr := syscall.Pwrite(int(file.Fd()), make([]byte, 512), rawBytes)
	size, sizeErr := os.ReadFile("/sys/class/block/vdc/size")
	return map[string]any{"fixture": "workspace-boundary", "evidence_kind": "trusted_guest_block_syscall", "offset": rawBytes, "requested_bytes": 512, "written_bytes": n, "errno": fmt.Sprint(writeErr), "sectors_after": strings.TrimSpace(string(size)), "expectation_met": n <= 0 && (errors.Is(writeErr, syscall.ENOSPC) || errors.Is(writeErr, syscall.EIO)) && sizeErr == nil && strings.TrimSpace(string(size)) == "8388608"}
}

func fixtureOperation(name string) map[string]any {
	var action string
	var targets []string
	if directories, ok := pressureDirectories[name]; ok {
		action = "write_and_fsync_until_work_limit"
		for _, directory := range directories {
			targets = append(targets, directory+"/synthetic-pressure")
		}
		if name == "workspace-root-copyup" {
			targets = []string{"/etc/filegate-stage0-copyup.seed"}
		}
	} else {
		switch name {
		case "workspace-inodes":
			action, targets = "create_files_until_inode_limit", []string{"/job/extract/inode-*"}
		case "workspace-block-io":
			action, targets = "write_and_fsync_after_host_block_EIO_arm", []string{"/job/extract/block-io-probe"}
		case "workspace-sync-failure":
			action, targets = "inject_sync_EIO_after_synthetic_write", []string{"/job/extract/sync-injection"}
		case "workspace-monitor-stop":
			action, targets = "SIGSTOP_guest_workspace_monitor", []string{"/job"}
		case "workspace-monitor-failure":
			action, targets = "replace_monitor_and_remove_statfs_target", []string{"/job/metadata/monitor-target"}
		default:
			return nil
		}
	}
	operation := map[string]any{"event": "fixture_started", "fixture": name, "action": action, "target_paths": targets,
		"phase": "selected_before_execution", "completed": false, "ack_required_before_action": true}
	if _, ok := pressureDirectories[name]; ok {
		operation["cache_strategy"] = capacityCacheStrategy
	}
	return operation
}

func isFixture(name string) bool {
	if name == "product-av-normalization" {
		return true
	}
	if _, ok := pressureDirectories[name]; ok {
		return true
	}
	switch name {
	case "transfer", "format-contract", "av-observation", "av-limits", "av-hard", "av-io", "av-remaining", "av-internal", "av-pe-import", "av-regex", "av-icons", "av-parser-routes", "av-codec-bounds", "av-lzma-wrappers", "av-decoder-wrappers", "av-deflate64-wrapper", "av-tar-scope", "av-text-parsers", "freshclam-adapter", "input-hash-mismatch", "workspace-inodes", "workspace-boundary", "workspace-sync-failure", "workspace-monitor-stop", "workspace-monitor-failure", "workspace-reuse", "workspace-block-io":
		return true
	}
	return false
}
