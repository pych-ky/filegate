package verification

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func init() { Register("idle", runIdle) }
func cpuSeconds(text string) float64 {
	days := 0
	if index := strings.LastIndexByte(text, '-'); index >= 0 {
		value, err := strconv.Atoi(text[:index])
		Must(err)
		days = value
		text = text[index+1:]
	}
	total := float64(0)
	for _, part := range strings.Split(text, ":") {
		value, err := strconv.ParseFloat(part, 64)
		Must(err)
		total = total*60 + value
	}
	return total + float64(days*86400)
}
func processTable(h *Harness) map[int]Object {
	result := Execute(h.Root, []string{"/bin/ps", "-axo", "pid=,ppid=,rss=,time=,comm="}, nil, 10*time.Second)
	h.Check("process_inventory_available", result.ExitCode == 0)
	rows := map[int]Object{}
	for _, line := range strings.Split(strings.TrimSpace(string(result.Stdout)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			panic(Failure{"process_inventory_invalid"})
		}
		pid, err := strconv.Atoi(fields[0])
		Must(err)
		parent, err := strconv.Atoi(fields[1])
		Must(err)
		rss, err := strconv.ParseInt(fields[2], 10, 64)
		Must(err)
		rows[pid] = Object{"pid": pid, "parent": parent, "rss_bytes": rss * 1024, "cpu_seconds": cpuSeconds(fields[3]), "name": filepath.Base(strings.Join(fields[4:], " "))}
	}
	return rows
}
func auxiliary(rows map[int]Object) []int {
	values := []int{}
	for pid, row := range rows {
		for _, prefix := range []string{"qemu-system-", "clamscan", "clamd", "freshclam", "filegate-watchdog", "integrated-watchdog"} {
			if strings.HasPrefix(Str(row, "name"), prefix) {
				values = append(values, pid)
				break
			}
		}
	}
	return values
}
func descendants(rows map[int]Object, owners []int) []int {
	found := map[int]bool{}
	for _, pid := range owners {
		found[pid] = true
	}
	for {
		added := false
		for pid, row := range rows {
			if found[int(Int(row, "parent"))] && !found[pid] {
				found[pid] = true
				added = true
			}
		}
		if !added {
			break
		}
	}
	for _, pid := range owners {
		delete(found, pid)
	}
	result := []int{}
	for pid := range found {
		result = append(result, pid)
	}
	return result
}
func loadAverage(h *Harness) []float64 {
	r := Execute(h.Root, []string{"/usr/sbin/sysctl", "-n", "vm.loadavg"}, nil, 5*time.Second)
	h.Check("load_average_available", r.ExitCode == 0)
	fields := strings.Fields(strings.Trim(string(r.Stdout), "{} \t\r\n"))
	if len(fields) != 3 {
		panic(Failure{"load_average_invalid"})
	}
	values := []float64{}
	for _, field := range fields {
		value, err := strconv.ParseFloat(field, 64)
		Must(err)
		values = append(values, value)
	}
	return values
}
func runIdle(h *Harness) {
	h.Check("macos_idle_measurement", runtime.GOOS == "darwin")
	h.Record["scope"] = "single 10-minute UI-closed idle measurement of broker plus initialized stdio MCP"
	h.Record["not_demonstrated"] = []string{"UI-visible browser increment", "scan/update load and peaks", "sleep or OS restart"}
	h.Record["hardware"] = Object{"machine": runtime.GOARCH, "logical_cpus": runtime.NumCPU()}
	for _, name := range []string{"hw.model", "hw.memsize"} {
		r := Execute(h.Root, []string{"/usr/sbin/sysctl", "-n", name}, nil, 5*time.Second)
		h.Check("hardware_"+name, r.ExitCode == 0)
		Map(h.Record, "hardware")[name] = strings.TrimSpace(string(r.Stdout))
	}
	r := Execute(h.Root, []string{"/usr/bin/sw_vers"}, nil, 5*time.Second)
	h.Record["os"] = string(r.Stdout)
	r = Execute(h.Root, []string{"go", "version"}, nil, 5*time.Second)
	h.Record["go"] = strings.TrimSpace(string(r.Stdout))
	h.Check("no_scan_or_update_process_before_measurement", len(auxiliary(processTable(h))) == 0)
	extra := []string{}
	configured := false
	for _, name := range []string{"vm-runner", "vm-workspace", "vm-proof"} {
		if h.Paths[name] != "" {
			configured = true
		}
	}
	for _, name := range []string{"vm-runner", "vm-workspace", "vm-proof"} {
		if configured {
			h.Check("idle_"+name+"_provided", h.Paths[name] != "")
			extra = append(extra, "--"+name, h.Paths[name])
		}
	}
	h.Record["vm_configured"] = configured
	health := h.Start(extra...)
	h.Check("acceptance_and_release_gates_closed", GatesClosed(health))
	cmd := exec.Command(h.Binary, "--data-dir", h.Data, "mcp")
	stdin, err := cmd.StdinPipe()
	Must(err)
	stdout, err := cmd.StdoutPipe()
	Must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	Must(cmd.Start())
	stopped := false
	var mcpOutput []byte
	defer func() {
		if stopped {
			return
		}
		_ = stdin.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			stopped = true
			h.Check("mcp_stopped", err == nil && stderr.Len() == 0)
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			stopped = true
			panic(Failure{"mcp_stop_timeout"})
		}
		h.Record["all_processes_stopped"] = h.Process == nil && stopped
		h.Record["mcp_output_sha256"] = Digest(append(mcpOutput, stderr.Bytes()...))
	}()
	_, err = stdin.Write(append(Encoded(MCPInit()[0]), '\n'))
	Must(err)
	reader := bufio.NewReader(stdout)
	response := make(chan []byte, 1)
	go func() {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			response <- nil
		} else {
			response <- line
		}
	}()
	select {
	case raw := <-response:
		if raw == nil {
			panic(Failure{"mcp_initialize_failed"})
		}
		mcpOutput = append(mcpOutput, raw...)
		reply := Decode(raw)
		h.Check("mcp_initialized", Int(reply, "id") == 1 && reply["result"] != nil)
	case <-time.After(5 * time.Second):
		panic(Failure{"mcp_initialize_timeout"})
	}
	_, err = stdin.Write(append(Encoded(MCPInit()[1]), '\n'))
	Must(err)
	owners := []int{h.Process.Process.Pid, cmd.Process.Pid}
	time.Sleep(5 * time.Second)
	started := time.Now()
	samples := []Object{}
	stream, err := os.OpenFile(filepath.Join(h.Out, "samples.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	Must(err)
	defer stream.Close()
	nextProgress := 60.0
	for {
		rows := processTable(h)
		own := []Object{}
		rss := int64(0)
		cpu := 0.0
		for _, pid := range owners {
			row := rows[pid]
			if row == nil {
				panic(Failure{"owned_process_missing_from_measurement"})
			}
			own = append(own, row)
			rss += Int(row, "rss_bytes")
			cpu += row["cpu_seconds"].(float64)
		}
		elapsed := time.Since(started).Seconds()
		row := Object{"elapsed_seconds": elapsed, "processes": own, "rss_total_bytes": rss, "cpu_total_seconds": cpu, "load_average": loadAverage(h), "descendants": descendants(rows, owners), "scan_update_processes": auxiliary(rows)}
		samples = append(samples, row)
		_, err = stream.Write(append(Encoded(row), '\n'))
		Must(err)
		Must(stream.Sync())
		if len(row["descendants"].([]int)) > 0 || len(row["scan_update_processes"].([]int)) > 0 {
			panic(Failure{"idle_auxiliary_process_present"})
		}
		if elapsed >= nextProgress {
			fmt.Println(string(Encoded(Object{"mode": "idle", "elapsed_seconds": int64(elapsed), "rss_bytes": rss})))
			nextProgress += 60
		}
		remaining := 600 - (elapsed - samples[0]["elapsed_seconds"].(float64))
		if remaining <= 0 {
			break
		}
		sleep := time.Second
		if remaining < 1 {
			sleep = time.Duration(remaining * float64(time.Second))
		}
		time.Sleep(sleep)
	}
	first, last := samples[0], samples[len(samples)-1]
	elapsed := last["elapsed_seconds"].(float64) - first["elapsed_seconds"].(float64)
	cpu := last["cpu_total_seconds"].(float64) - first["cpu_total_seconds"].(float64)
	maxRSS, totalRSS := int64(0), int64(0)
	for _, row := range samples {
		rss := Int(row, "rss_total_bytes")
		totalRSS += rss
		if rss > maxRSS {
			maxRSS = rss
		}
	}
	measurement := Object{"elapsed_seconds": elapsed, "cpu_seconds": cpu, "cpu_percent_one_core": 100 * cpu / elapsed, "rss_max_bytes": maxRSS, "rss_mean_bytes": float64(totalRSS) / float64(len(samples)), "samples": len(samples), "warmup_seconds": 5, "cpu_counter_resolution_seconds": 0.01, "ui_open": false}
	h.Record["measurement"] = measurement
	h.Check("ten_minute_measurement", elapsed >= 600)
	h.Check("idle_cpu_below_one_percent", cpu >= 0 && 100*cpu/elapsed < 1)
	h.Check("idle_rss_within_100_mib", maxRSS <= 100*1024*1024)
	status, jobs := h.Request("GET", "/v1/jobs", nil, nil, nil)
	h.Check("no_jobs_created", status == 200 && len(List(jobs, "jobs")) == 0)
	Must(stdin.Close())
	type remainingResult struct {
		body []byte
		err  error
	}
	readDone := make(chan remainingResult, 1)
	go func() { body, err := io.ReadAll(reader); readDone <- remainingResult{body, err} }()
	select {
	case result := <-readDone:
		Must(result.err)
		mcpOutput = append(mcpOutput, result.body...)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-readDone
		panic(Failure{"mcp_stop_timeout"})
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		stopped = true
		h.Check("mcp_stopped", err == nil && stderr.Len() == 0)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		stopped = true
		panic(Failure{"mcp_stop_timeout"})
	}
	h.Stop(false)
	h.Record["all_processes_stopped"] = true
	h.Record["mcp_output_sha256"] = Digest(append(mcpOutput, stderr.Bytes()...))
}
