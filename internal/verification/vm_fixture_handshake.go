package verification

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func vmHandshakeReady() Object {
	mounts := []string{}
	for index, entry := range []struct{ path, kind string }{{"/", "overlay"}, {"/.base", "ext4"}, {"/.definitions", "ext4"}, {"/.work", "ext4"}, {"/job", "ext4"}, {"/dev", "devtmpfs"}, {"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev/shm", "tmpfs"}} {
		source, front := entry.kind, "rw"
		if entry.path == "/.work" || entry.path == "/job" {
			source = "/dev/vdc"
		}
		if entry.path == "/.base" || entry.path == "/.definitions" {
			front = "ro"
		}
		options := front
		if entry.path == "/dev/shm" {
			options = "rw,size=65536k,nr_inodes=4096"
		}
		mounts = append(mounts, fmt.Sprintf("%d 0 0:0 / %s %s - %s %s %s", index+1, entry.path, front, entry.kind, source, options))
	}
	return Object{"event": "ready", "blocks": Object{"vda": Object{"sectors": "2097152", "read_only": "1"}, "vdb": Object{"sectors": "32768", "read_only": "1"}, "vdc": Object{"sectors": "8388608", "read_only": "0"}}, "net_devices": []string{"/sys/class/net/lo"}, "loopback_up": true, "mountinfo": strings.Join(mounts, "\n")}
}

func vmHandshakeCase(h *Harness, index int, kind string, contract Object) Object {
	run := filepath.Join(h.Temporary, fmt.Sprintf("handshake-%d", index))
	Must(os.Mkdir(run, 0700))
	artifact := filepath.Join(h.Out, "cases", kind)
	Must(os.MkdirAll(artifact, 0700))
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(run, "channel.sock"), Net: "unix"})
	Must(err)
	defer listener.Close()
	Must(listener.SetDeadline(time.Now().Add(5 * time.Second)))
	fixture := "workspace-sync-failure"
	arguments := []string{h.Binary, run, "--fixture", fixture, "--watchdog-relay"}
	if kind == "watchdog_death_hold" {
		fixture = "transfer"
		arguments[3] = fixture
		arguments = append(arguments, "--hold-before-input-for-watchdog-death")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	stdin, err := command.StdinPipe()
	Must(err)
	stdout, err := command.StdoutPipe()
	Must(err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	Must(command.Start())
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	connection, err := listener.AcceptUnix()
	Must(err)
	defer connection.Close()
	Must(connection.SetDeadline(time.Now().Add(5 * time.Second)))
	stream := bufio.NewReader(connection)
	relay := bufio.NewReader(stdout)
	frames, relays := []Object{}, []Object{}
	var sent bytes.Buffer
	send := func(value Object) {
		body := append(Encoded(value), '\n')
		frames = append(frames, Object{"event": value["event"], "bytes": len(body), "sha256": Digest(body)})
		_, err := sent.Write(body)
		Must(err)
		_, err = connection.Write(body)
		Must(err)
	}
	readRelay := func() Object {
		body, err := relay.ReadBytes('\n')
		Must(err)
		h.Check(kind+"_relay_line_bound", len(body) <= 65536)
		value := Decode(body)
		relays = append(relays, value)
		return value
	}
	workspace := Object{"event": "workspace", "free_bytes": 3000000000, "free_inodes": 200000, "reason": nil}
	send(vmHandshakeReady())
	send(workspace)
	h.Check(kind+"_workspace_relay", Str(readRelay(), "event") == "workspace")
	h.Check(kind+"_ready_relay", Str(readRelay(), "event") == "validated_ready")
	_, err = stdin.Write([]byte("READY\n"))
	Must(err)
	started := Object{"event": "fixture_started", "fixture": "workspace-sync-failure", "action": contract["start_action"], "target_paths": contract["start_target_paths"], "phase": "selected_before_execution", "completed": false, "ack_required_before_action": true}
	ack := []byte{}
	heldNoInput, heldNoTerminal := false, false
	heldRelays := 0
	var inputHeader Object
	var inputSHA string
	var initialSidecar Object
	pending := filepath.Join(run, "fixture-observation.json.pending")
	if kind == "watchdog_death_hold" {
		noInput := func() bool {
			Must(connection.SetReadDeadline(time.Now().Add(150 * time.Millisecond)))
			one := make([]byte, 1)
			n, err := connection.Read(one)
			deadline, ok := err.(net.Error)
			Must(connection.SetReadDeadline(time.Now().Add(5 * time.Second)))
			return n == 0 && ok && deadline.Timeout()
		}
		heldNoInput = noInput()
		for count := 0; count < 3; count++ {
			send(workspace)
			if Str(readRelay(), "event") == "workspace" {
				heldRelays++
			}
		}
		heldNoInput = noInput() && heldNoInput
		heldNoTerminal = heldNoInput && heldRelays == 3
	} else {
		body, err := stream.ReadBytes('\n')
		Must(err)
		inputHeader = Decode(body)
		size := Int(inputHeader, "byte_size")
		h.Check(kind+"_synthetic_input_bound", size > 0 && size <= 4096)
		input := make([]byte, size)
		_, err = io.ReadFull(stream, input)
		Must(err)
		inputSHA = Digest(input)
		h.Check(kind+"_input_binding", string(input) == "FileGate stage 0 synthetic transfer\n" && inputSHA == Str(inputHeader, "sha256") && Str(inputHeader, "fixture") == fixture)
		if kind == "observation_before_start" {
			send(Object{"event": "fixture_observation", "fixture": fixture})
		} else {
			if kind == "wrong_target" {
				started["target_paths"] = []string{"/job/extract/wrong-target"}
			}
			if kind == "persistence_refused" {
				Write(pending, []byte("synthetic occupied pending name\n"))
			}
			send(started)
		}
		ack, err = stream.ReadBytes('\n')
		h.Check(kind+"_ack_read_result", err == nil || err == io.EOF)
		if string(ack) == "FIXTURE_READY\n" {
			initialSidecar = ReadJSON(filepath.Join(run, "fixture-observation.json"))
			h.Check(kind+"_start_persisted_before_ack", Int(initialSidecar, "schema") == 2 && Equal(initialSidecar["started"], started) && initialSidecar["last_observation"] == nil)
			if kind == "artifact_overflow" {
				large := make([]string, 17)
				for index := range large {
					large[index] = strings.Repeat("x", 65536)
				}
				send(Object{"event": "fixture_observation", "result": Object{"fixture": fixture, "synthetic_large_fields": large}})
			} else {
				for step := 1; step <= 2; step++ {
					send(Object{"event": "fixture_observation", "result": Object{"fixture": fixture, "synthetic_step": step}})
				}
				send(Object{"event": "protocol_error", "reason": "synthetic_test_end"})
			}
		}
	}
	_ = connection.CloseWrite()
	Must(stdin.Close())
	remaining := make(chan []byte, 1)
	go func() { body, _ := io.ReadAll(io.LimitReader(relay, (1<<20)+1)); remaining <- body }()
	output := <-remaining
	err = command.Wait()
	finished = true
	h.Check(kind+"_process_bounded", ctx.Err() == nil)
	code := 0
	if err != nil {
		status, ok := err.(*exec.ExitError)
		h.Check(kind+"_exit_status", ok)
		code = status.ExitCode()
	}
	Write(filepath.Join(artifact, "guest-frames.jsonl"), sent.Bytes())
	Write(filepath.Join(artifact, "remaining-stdout.jsonl"), output)
	WriteJSON(filepath.Join(artifact, "relay.json"), relays)
	var exchange, sidecar Object
	for _, entry := range []struct {
		name  string
		value *Object
	}{{"exchange.json", &exchange}, {"fixture-observation.json", &sidecar}} {
		path := filepath.Join(run, entry.name)
		if Exists(path) {
			*entry.value = ReadJSON(path)
			Write(filepath.Join(artifact, entry.name), Read(path))
		}
	}
	expectedACK := kind == "preserved_start_and_latest" || kind == "artifact_overflow"
	row := Object{"id": kind, "argv": arguments, "exit_code": code, "expected_fixture_ack": expectedACK, "received_fixture_ack": string(ack), "frames": frames, "input_header": inputHeader, "input_sha256": inputSHA, "initial_sidecar": initialSidecar, "sidecar": sidecar, "exchange": exchange, "remaining_stdout_bytes": len(output), "stderr_bytes": stderr.Len(), "held_no_input": heldNoInput, "held_workspace_relays": heldRelays, "held_no_terminal_before_disconnect": heldNoTerminal}
	WriteJSON(filepath.Join(artifact, "case.json"), row)
	h.Check(kind+"_safe_failure", code == 2 && stderr.Len() == 0 && (string(ack) == "FIXTURE_READY\n") == expectedACK, row)
	if kind == "watchdog_death_hold" {
		h.Check(kind+"_input_and_terminal_held", heldNoInput && heldNoTerminal && heldRelays == 3 && len(output) == 0 && exchange == nil)
		h.Check(kind+"_hold_evidence", sidecar != nil && Int(sidecar, "schema") == 2 && Bool(sidecar, "death_test") && !Bool(sidecar, "input_transfer_started") && !Bool(sidecar, "ordinary_exchange_finished_permitted") && Bool(sidecar, "workspace_relay_continues") && Bool(sidecar, "ready_acknowledged"))
	} else {
		h.Check(kind+"_failed_exchange_record", Int(exchange, "schema") == 2 && Str(exchange, "fixture") == fixture && Str(exchange, "outcome") == "failed" && Str(exchange, "failure") == "FIXTURE_EXCHANGE_INVALID")
		switch kind {
		case "preserved_start_and_latest":
			h.Check(kind+"_latest_observation", sidecar != nil && Equal(sidecar["started"], started) && Bool(sidecar, "acknowledged") && Int(sidecar, "last_observation", "result", "synthetic_step") == 2)
		case "artifact_overflow":
			h.Check(kind+"_previous_sidecar_preserved", sidecar != nil && Equal(sidecar["started"], started) && Bool(sidecar, "acknowledged") && sidecar["last_observation"] == nil && len(Read(filepath.Join(run, "fixture-observation.json"))) <= 65536)
		case "persistence_refused":
			h.Check(kind+"_occupied_pending_preserved", sidecar == nil && string(Read(pending)) == "synthetic occupied pending name\n")
		default:
			h.Check(kind+"_no_sidecar", sidecar == nil)
		}
	}
	return row
}

func runVMFixtureHandshake(h *Harness) {
	h.Check("actual_go_helper_required", filepath.Base(h.Binary) == "filegate-bridge" && filepath.Base(filepath.Dir(h.Binary)) == ".build")
	catalogPath := filepath.Join(filepath.Dir(filepath.Dir(h.Binary)), "fixtures.json")
	catalog := ReadJSON(catalogPath)
	contract := Map(catalog, "fixtures", "workspace-sync-failure")
	h.Check("fixture_catalog_contract", Int(catalog, "schema") == 1 && contract != nil && Str(contract, "expected_stop_reason") != "" && contract["start_action"] != nil && contract["start_target_paths"] != nil)
	h.Record["fixture_catalog_sha256"] = FileDigest(catalogPath)
	Write(filepath.Join(h.Out, "fixtures.json"), Read(catalogPath))
	h.Record["evidence_kind"] = "synthetic_guest_real_Go_host_helper_IPC_process_E2E_only"
	h.Record["vm_started"], h.Record["guest_runtime_executed"] = false, false
	h.Record["contract_changes"] = []string{"fixture observation pending path is fixture-observation.json.pending", "the sidecar is bounded to 65536 bytes", "watchdog-death hold records its readiness sidecar and never publishes an ordinary exchange terminal", "failure text is a finite code without guest payloads"}
	rows := []Object{}
	for index, kind := range []string{"preserved_start_and_latest", "wrong_target", "observation_before_start", "persistence_refused", "artifact_overflow", "watchdog_death_hold"} {
		row := vmHandshakeCase(h, index, kind, contract)
		rows = append(rows, row)
		h.Record["cases"] = rows
		WriteJSON(filepath.Join(h.Out, "handshake-cases.json"), rows)
	}
	arguments := []string{h.Binary, h.Temporary, "--fixture", "workspace-sync-failure", "--watchdog-relay", "--hold-before-input-for-watchdog-death"}
	refused := Execute(h.Root, arguments, nil, 5*time.Second)
	row := Object{"id": "hold_nontransfer_refused", "argv": arguments, "exit_code": refused.ExitCode, "stdout_bytes": len(refused.Stdout), "stderr_bytes": len(refused.Stderr)}
	rows = append(rows, row)
	h.Record["cases"] = rows
	WriteJSON(filepath.Join(h.Out, "handshake-cases.json"), rows)
	h.Check("hold_nontransfer_refused", refused.ExitCode == 2 && len(refused.Stdout) == 0 && len(refused.Stderr) == 0, row)
	h.Record["unproven"] = []string{"guest blocks each operation until ACK in actual ARM64 VM", "missing native readiness ACK", "invalid nonworkspace hold frames", "actual 300-second hold timeout and stream budget exhaustion", "actual LaunchAgent watchdog death cleanup"}
}

func init() { Register("fixture-handshake", runVMFixtureHandshake) }
