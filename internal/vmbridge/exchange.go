package vmbridge

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type exchange struct {
	run          string
	request      object
	output       io.Writer
	received     int
	relayed      int
	reportDigest any
}

// Run requires the native watchdog's READY acknowledgement before input transfer.
func Run(directory, requestPath, requestSHA string, input io.Reader, output io.Writer) error {
	run, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	run, err = filepath.Abs(run)
	if err != nil {
		return err
	}
	requested, err := request(requestPath, requestSHA)
	if err != nil {
		return err
	}
	source, before, err := openOwned(requested["input_path"].(string), 0400)
	if err != nil {
		return err
	}
	defer source.Close()
	if before.Size != number(requested["byte_size"]) {
		return errInvalid
	}
	header := object{"job_id": requested["job_id"], "attempt_id": requested["attempt_id"], "policy_digest": requested["policy_digest"], "byte_size": requested["byte_size"], "metadata": requested["metadata"], "sha256": requested["expected_sha256"], "fixture": "product-inspect"}
	body, err := encoded(header)
	if err != nil || len(body) > requestLimit {
		return errInvalid
	}
	x := exchange{run: run, request: requested, output: output}
	err = x.transfer(source, before, body, input)
	outcome := "failed"
	if err == nil {
		outcome = "verified"
	}
	_, saveErr := writeControl(filepath.Join(run, "exchange.json"), object{"schema": 1, "fixture": "product-inspect", "job_id": requested["job_id"], "attempt_id": requested["attempt_id"], "input": object{"sha256": requested["expected_sha256"], "byte_size": requested["byte_size"]}, "report_sha256": x.reportDigest, "report_accepted": err == nil, "outcome": outcome, "received_bytes": x.received, "relay_bytes": x.relayed})
	if saveErr != nil {
		return saveErr
	}
	var finalEvent any
	if x.reportDigest != nil {
		finalEvent = "product_result"
	}
	if relayErr := x.relay(object{"event": "exchange_finished", "guest_final_event": finalEvent, "outcome": outcome, "artifact": filepath.Join(run, "exchange.json")}); relayErr != nil {
		return relayErr
	}
	return err
}

func (x *exchange) relay(value any) error {
	body, err := encoded(value)
	if err != nil {
		return err
	}
	x.relayed += len(body)
	if len(body) > 65536 || x.relayed > 1<<20 {
		return errInvalid
	}
	_, err = x.output.Write(body)
	return err
}

func boundedLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > limit {
			return nil, errInvalid
		}
		line = append(line, part...)
		if err == nil {
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, errInvalid
		}
	}
}

func (x *exchange) receive(connection net.Conn, reader *bufio.Reader) (object, error) {
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	body, err := boundedLine(reader, reportLimit)
	x.received += len(body)
	if err != nil || x.received > reportLimit+(1<<20) {
		return nil, errInvalid
	}
	value, err := decode(body)
	if err != nil {
		return nil, err
	}
	m, ok := value.(object)
	if !ok {
		return nil, errInvalid
	}
	return m, nil
}

func (x *exchange) transfer(source *os.File, before unix.Stat_t, header []byte, input io.Reader) error {
	channel := filepath.Join(x.run, "channel.sock")
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		if _, err := os.Stat(channel); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.Chmod(channel, 0600); err != nil {
		return err
	}
	connection, err := net.DialTimeout("unix", channel, 10*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	ready, err := x.receive(connection, reader)
	if err != nil || !preflight(ready, x.request) {
		return errInvalid
	}
	first, err := x.receive(connection, reader)
	if err != nil {
		return err
	}
	w, err := workspace(first)
	if err != nil {
		return err
	}
	if err = x.relay(w); err != nil {
		return err
	}
	if err = x.relay(object{"event": "validated_ready"}); err != nil {
		return err
	}
	ack, err := boundedLine(bufio.NewReader(input), 64)
	if err != nil || string(ack) != "READY\n" {
		return errInvalid
	}
	done := make(chan error, 1)
	go func() {
		sendErr := sendInput(connection, source, before, header, x.request["expected_sha256"].(string))
		done <- sendErr
		if sendErr != nil {
			connection.Close()
		}
	}()
	var sendErr error
	finished := false
	defer func() {
		connection.Close()
		if !finished {
			<-done
		}
	}()
	complete := func() bool {
		if !finished {
			select {
			case sendErr = <-done:
				finished = true
			case <-time.After(time.Second):
				return false
			}
		}
		return sendErr == nil
	}
	lastProgress := int64(0)
	until = time.Now().Add(300 * time.Second)
	for i := 0; i < 1024; i++ {
		if !time.Now().Before(until) {
			return errInvalid
		}
		record, err := x.receive(connection, reader)
		if err != nil {
			return err
		}
		switch record["event"] {
		case "workspace":
			w, err := workspace(record)
			if err != nil {
				return err
			}
			if err = x.relay(w); err != nil {
				return err
			}
		case "product_progress":
			if x.reportDigest != nil || !fields(record, "event job_id attempt_id input_sha256 progress") || record["job_id"] != x.request["job_id"] || record["attempt_id"] != x.request["attempt_id"] || record["input_sha256"] != x.request["expected_sha256"] {
				return errInvalid
			}
			p, err := progress(record["progress"])
			if err != nil || number(p["sequence"]) != lastProgress+1 {
				return errInvalid
			}
			if _, err = writeControl(filepath.Join(x.run, fmt.Sprintf("product-progress-%d.json", number(p["sequence"]))), p); err != nil {
				return err
			}
			lastProgress = number(p["sequence"])
		case "product_error":
			if x.reportDigest != nil || !complete() || !x.workspaceError(record) {
				return errInvalid
			}
			w, _ := workspace(record["workspace"])
			if err = x.relay(w); err != nil {
				return err
			}
			return errInvalid
		case "product_result":
			if x.reportDigest != nil || !complete() || report(record, x.request) != nil {
				return errInvalid
			}
			digest, err := writeControl(filepath.Join(x.run, "product-report.json"), record)
			if err != nil {
				return err
			}
			x.reportDigest = digest
		default:
			return errInvalid
		}
		ackPath := filepath.Join(x.run, "product-accepted.json")
		if x.reportDigest != nil {
			if _, err := os.Stat(ackPath); err == nil {
				accepted, _, err := readControl(ackPath, 1024)
				if err != nil || !same(accepted, object{"job_id": x.request["job_id"], "attempt_id": x.request["attempt_id"], "report_sha256": x.reportDigest}) {
					return errInvalid
				}
				return nil
			}
		}
	}
	return errInvalid
}

func (x *exchange) workspaceError(m object) bool {
	if !fields(m, "event reason job_id attempt_id input_sha256 byte_size policy_digest workspace") || m["reason"] != "WORKSPACE_IO_ERROR" || m["job_id"] != x.request["job_id"] || m["attempt_id"] != x.request["attempt_id"] || m["input_sha256"] != x.request["expected_sha256"] || !integer(m["byte_size"], 0, inputLimit) || m["byte_size"] != x.request["byte_size"] || m["policy_digest"] != x.request["policy_digest"] {
		return false
	}
	w, ok := m["workspace"].(object)
	if !ok || !fields(w, "event free_bytes free_inodes reason") || !oneOf(w["reason"], "WORKSPACE_IO_ERROR", "WORKSPACE_LIMIT", "RESOURCE_MONITOR_FAILED") {
		return false
	}
	_, err := workspace(w)
	return err == nil
}

func sendInput(connection net.Conn, source *os.File, before unix.Stat_t, header []byte, expected string) error {
	write := func(body []byte) error {
		if err := connection.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		for len(body) > 0 {
			n, err := connection.Write(body)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			body = body[n:]
		}
		return nil
	}
	if err := write(header); err != nil {
		return err
	}
	hash := sha256.New()
	buffer := make([]byte, 65536)
	remaining := before.Size
	for remaining > 0 {
		n, err := source.Read(buffer[:min(int64(len(buffer)), remaining)])
		if err != nil || n == 0 {
			return errInvalid
		}
		hash.Write(buffer[:n])
		if err = write(buffer[:n]); err != nil {
			return err
		}
		remaining -= int64(n)
	}
	after, err := fileStat(source)
	n, readErr := source.Read(buffer[:1])
	if err != nil || n != 0 || readErr != io.EOF || !unchanged(before, after) || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errInvalid
	}
	return nil
}
