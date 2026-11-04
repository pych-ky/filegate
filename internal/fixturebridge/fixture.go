package fixturebridge

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"filegate.local/filegate/internal/vmbridge"
	"golang.org/x/sys/unix"
)

func RunFixture(directory, fixture string, hold bool, input io.Reader, output io.Writer) (returned error) {
	if hold && fixture != "transfer" {
		return invalid
	}
	run, err := filepath.EvalSymlinks(directory)
	if err != nil || run != directory || !filepath.IsAbs(run) {
		return invalid
	}
	if _, err = hostvm.Owned(run, unix.S_IFDIR, 0700); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil || filepath.Base(executable) != "filegate-bridge" || filepath.Base(filepath.Dir(executable)) != ".build" {
		return invalid
	}
	catalog, _, err := hostvm.ReadAsset(filepath.Join(filepath.Dir(filepath.Dir(executable)), "fixtures.json"), 1<<20)
	contract := hostvm.Map(hostvm.Map(catalog, "fixtures"), fixture)
	if err != nil || hostvm.Int(catalog, "schema") != 1 || contract == nil || fixture == "product-inspect" || fixture == "workspace-block-io" {
		return invalid
	}
	channel := filepath.Join(run, "channel.sock")
	until := time.Now().Add(10 * time.Second)
	var socket unix.Stat_t
	for time.Now().Before(until) {
		if unix.Lstat(channel, &socket) == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Uid != uint32(os.Getuid()) || socket.Nlink != 1 || os.Chmod(channel, 0600) != nil {
		return invalid
	}
	connection, err := net.DialTimeout("unix", channel, 10*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	received, relayed := 0, 0
	var records []object
	relay := func(value object) error {
		body, err := encoded(value)
		relayed += len(body)
		if err != nil || len(body) > 65536 || relayed > 1<<20 {
			return invalid
		}
		_, err = output.Write(body)
		return err
	}
	receive := func() (object, error) {
		if connection.SetReadDeadline(time.Now().Add(60*time.Second)) != nil {
			return nil, invalid
		}
		body, err := line(reader, 2<<20)
		received += len(body)
		if err != nil || received > 4<<20 || len(records) >= 1024 {
			return nil, invalid
		}
		record, err := vmbridge.DecodeObject(body)
		if err == nil {
			records = append(records, record)
		}
		return record, err
	}
	var final object
	defer func() {
		if hold {
			return
		}
		outcome := "verified"
		var failure any
		if returned != nil {
			outcome, failure = "failed", "FIXTURE_EXCHANGE_INVALID"
		}
		artifact := filepath.Join(run, "exchange.json")
		_, err := hostvm.WriteNew(artifact, object{"schema": 2, "fixture": fixture, "expected": contract, "events": records, "outcome": outcome,
			"failure": failure, "product_scan": false, "received_bytes": received, "relay_bytes": relayed, "process_stop_confirmation": "separate_watchdog_artifact_required"})
		if err != nil {
			returned = err
			return
		}
		var terminal any
		if final != nil {
			terminal = final["event"]
		}
		if err := relay(object{"event": "exchange_finished", "guest_final_event": terminal, "outcome": outcome, "artifact": artifact}); err != nil {
			returned = err
		}
	}()
	ready, err := receive()
	if err != nil || !vmbridge.ValidateFixturePreflight(ready) {
		return invalid
	}
	first, err := receive()
	if err != nil {
		return err
	}
	workspace, err := vmbridge.NormalizeWorkspace(first)
	if err != nil || workspace["reason"] != nil || relay(workspace) != nil || relay(object{"event": "validated_ready"}) != nil {
		return invalid
	}
	ack, err := line(bufio.NewReader(input), 64)
	if err != nil || string(ack) != "READY\n" {
		return invalid
	}
	if hold {
		if err = saveProgress(filepath.Join(run, "fixture-observation.json"), object{"schema": 2, "fixture": fixture, "death_test": true, "input_transfer_started": false,
			"ordinary_exchange_finished_permitted": false, "workspace_relay_continues": true, "ready_acknowledged": true}); err != nil {
			return err
		}
		started := time.Now()
		for time.Since(started) < 300*time.Second {
			record, err := receive()
			if err != nil {
				return err
			}
			workspace, err := vmbridge.NormalizeWorkspace(record)
			if err != nil || relay(workspace) != nil || workspace["reason"] != nil {
				return invalid
			}
		}
		return invalid
	}
	data := []byte("FileGate stage 0 synthetic transfer\n")
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])
	if fixture == "input-hash-mismatch" {
		expected = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	header, err := encoded(object{"job_id": "probe-job", "attempt_id": "probe-attempt", "sha256": expected, "byte_size": len(data), "policy_digest": "stage0-synthetic-only", "fixture": fixture})
	if err != nil || connection.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		return invalid
	}
	if _, err = connection.Write(append(header, data...)); err != nil {
		return err
	}
	var selected object
	checkpoints := [][2]string{{"apk", "started"}, {"apk", "completed"}, {"library", "started"}, {"library", "completed"}, {"fixture", "started"}, {"fixture", "completed"}}
	progress, lastElapsed := 0, int64(-1)
	started := time.Now()
	for time.Since(started) < 300*time.Second {
		record, err := receive()
		if err != nil {
			return err
		}
		switch record["event"] {
		case "workspace":
			workspace, err := vmbridge.NormalizeWorkspace(record)
			if err != nil || relay(workspace) != nil {
				return invalid
			}
			if workspace["reason"] != nil {
				for {
					time.Sleep(100 * time.Millisecond)
				}
			}
		case "fixture_started":
			if selected != nil || contract["expected_stop_reason"] == nil || record["fixture"] != fixture || record["action"] != contract["start_action"] ||
				!hostvm.Equal(record["target_paths"], contract["start_target_paths"]) || record["phase"] != "selected_before_execution" || record["completed"] != false || record["ack_required_before_action"] != true {
				return invalid
			}
			selected = record
			if err = saveProgress(filepath.Join(run, "fixture-observation.json"), object{"schema": 2, "fixture": fixture, "started": selected, "acknowledged": false, "last_observation": nil}); err != nil {
				return err
			}
			if connection.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
				return invalid
			}
			if _, err = connection.Write([]byte("FIXTURE_READY\n")); err != nil {
				return err
			}
			if err = saveProgress(filepath.Join(run, "fixture-observation.json"), object{"schema": 2, "fixture": fixture, "started": selected, "acknowledged": true, "last_observation": nil}); err != nil {
				return err
			}
		case "fixture_observation":
			if selected == nil || record["fixture"] != fixture && hostvm.Str(hostvm.Map(record, "result"), "fixture") != fixture {
				return invalid
			}
			if err = saveProgress(filepath.Join(run, "fixture-observation.json"), object{"schema": 2, "fixture": fixture, "started": selected, "acknowledged": true, "last_observation": record}); err != nil {
				return err
			}
		case "freshclam_progress":
			elapsed := integer(record["elapsed_ms"])
			if fixture != "freshclam-adapter" || !fields(record, "event", "fixture", "phase", "checkpoint", "sequence", "elapsed_ms") || record["fixture"] != fixture ||
				progress >= len(checkpoints) || record["phase"] != checkpoints[progress][0] || record["checkpoint"] != checkpoints[progress][1] || integer(record["sequence"]) != int64(progress+1) ||
				elapsed < lastElapsed || elapsed < 0 || elapsed > 300000 {
				return invalid
			}
			progress++
			lastElapsed = elapsed
		default:
			if contract["expected_stop_reason"] != nil || record["event"] != contract["expected_terminal"] {
				return invalid
			}
			final = record
			switch fixture {
			case "transfer":
				worker := hostvm.Map(record, "worker")
				if record["sha256"] != expected || integer(record["byte_size"]) != int64(len(data)) || record["job_id"] != "probe-job" || record["attempt_id"] != "probe-attempt" || worker["sha256"] != expected || integer(worker["byte_size"]) != int64(len(data)) || integer(worker["uid"]) != 65534 {
					return invalid
				}
			case "input-hash-mismatch":
				if record["reason"] != "INPUT_HASH_MISMATCH" || record["sha256"] != hex.EncodeToString(sum[:]) {
					return invalid
				}
			case "workspace-boundary":
				if hostvm.Map(record, "result")["expectation_met"] != true {
					return invalid
				}
			case "workspace-reuse":
				value := hostvm.Map(record, "result")
				if integer(value["uid"]) != 65534 || integer(value["bytes_written"]) != 5368709120 || value["cumulative_exceeds_fixed_capacity"] != true || value["reason"] != "" {
					return invalid
				}
			default:
				if record["runner_success"] != true || fixture == "freshclam-adapter" && progress != len(checkpoints) {
					return invalid
				}
			}
			return nil
		}
	}
	return invalid
}
