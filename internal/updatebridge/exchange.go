package updatebridge

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var updateID = regexp.MustCompile(`^update_[0-9a-f]{32}$`)
var definitionName = regexp.MustCompile(`^(main|daily|bytecode)\.(cvd|cld)$`)

type exchange struct {
	run, out, requestPath, requestSHA string
	requested, manifest               object
	output                            io.Writer
	writeMu                           sync.Mutex
}

func Run(directory, requestPath, requestSHA string, input io.Reader, output io.Writer) error {
	v, body, err := readControl(requestPath, 16384)
	r, ok := v.(object)
	if err != nil || !ok || !fields(r, "schema profile fixture_only attempt restore library_sha256 manifest_sha256 job_id attempt_id expected_sha256 byte_size definition_cache") ||
		!integer(r["schema"], 2, 2) || !validDigest(requestSHA) || digest(body) != requestSHA || r["profile"] != updateProfile || r["fixture_only"] != false {
		return errInvalid
	}
	id, ok := r["attempt_id"].(string)
	if !ok || !updateID.MatchString(id) {
		return errInvalid
	}
	if _, ok := r["restore"].(object); !ok {
		return errInvalid
	}
	if !validDigest(r["manifest_sha256"]) || !validDigest(r["library_sha256"]) {
		return errInvalid
	}
	registration := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(requestPath))), "update-runtime.json")
	v, body, err = readControl(registration, 1<<20)
	m, ok := v.(object)
	if err != nil || !ok || digest(body) != r["manifest_sha256"] || m["profile"] != updateProfile || m["fixture_only"] != false {
		return errInvalid
	}
	attempt, ok := r["attempt"].(object)
	if !ok || !definitionCache(r["definition_cache"], filepath.Dir(registration), m, attempt) {
		return errInvalid
	}
	run, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	run, err = filepath.Abs(run)
	if err != nil {
		return err
	}
	x := exchange{run: run, out: filepath.Join(filepath.Dir(requestPath), "output"), requestPath: requestPath, requestSHA: requestSHA, requested: r, manifest: m, output: output}
	err = x.transfer(input)
	outcome := "failed"
	if err == nil {
		outcome = "verified"
	}
	path := filepath.Join(run, "normal-exchange.json")
	if _, saveErr := writeControl(path, object{"schema": 1, "outcome": outcome, "update_id": id}); saveErr != nil {
		return saveErr
	}
	if relayErr := x.relay(object{"event": "exchange_finished", "guest_final_event": "update_done", "outcome": outcome, "artifact": path}); relayErr != nil {
		return relayErr
	}
	return err
}

func (x *exchange) relay(value any) error {
	body, err := encoded(value)
	if err != nil || len(body) > 65536 {
		return errInvalid
	}
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
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

func receive(connection net.Conn, reader *bufio.Reader) (object, error) {
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	body, err := boundedLine(reader, 1<<20)
	if err != nil {
		return nil, err
	}
	v, err := decode(body)
	m, ok := v.(object)
	if err != nil || !ok {
		return nil, errInvalid
	}
	return m, nil
}

func send(connection net.Conn, value any) error {
	body, err := encoded(value)
	if err != nil {
		return err
	}
	if err = connection.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
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

type candidate struct {
	file   *os.File
	path   string
	row    object
	digest hash.Hash
	size   int64
}

func (x *exchange) transfer(input io.Reader) error {
	channel := filepath.Join(x.run, "channel.sock")
	until := time.Now().Add(10 * time.Second)
	for absent(channel) && time.Now().Before(until) {
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
	ready, err := receive(connection, reader)
	if err != nil || !preflight(ready) || !cachePreflight(ready, x.requested["definition_cache"]) {
		return errInvalid
	}
	first, err := receive(connection, reader)
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
	values := make(chan object, 4)
	failure := make(chan error, 1)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			value, e := receive(connection, reader)
			if e != nil {
				failure <- e
				return
			}
			if value["event"] == "workspace" {
				v, e := workspace(value)
				if e == nil {
					e = x.relay(v)
				}
				if e != nil {
					failure <- e
					return
				}
				continue
			}
			select {
			case values <- value:
			case <-done:
				return
			}
		}
	}()
	defer func() { close(done); connection.Close(); <-stopped }()
	id := x.requested["attempt_id"].(string)
	if err = send(connection, object{"job_id": "update_" + id, "attempt_id": id, "sha256": digest(nil), "byte_size": 0, "policy_digest": updateProfile, "fixture": "product-update"}); err != nil {
		return err
	}
	var report object
	var network *os.File
	var active *candidate
	defer func() {
		if network != nil {
			network.Close()
		}
		if active != nil && active.file != nil {
			active.file.Close()
		}
	}()
	candidates := []object{}
	issued := false
	var total int64
	finalSHA := ""
	for i := 0; i < 50000; i++ {
		var value object
		select {
		case err = <-failure:
			return err
		default:
		}
		select {
		case value = <-values:
		case err = <-failure:
			return err
		}
		reply := object{"event": "accepted"}
		switch value["event"] {
		case "freshclam_control_ready":
			if !fields(value, "event library_sha256") || issued || value["library_sha256"] != x.requested["library_sha256"] {
				return errInvalid
			}
			issued = true
			reply = object{"event": "freshclam_control_request", "request": x.requested["restore"], "definition_cache": x.requested["definition_cache"]}
		case "freshclam_control_final":
			if !fields(value, "event report") || !issued || report != nil {
				return errInvalid
			}
			var ok bool
			report, ok = value["report"].(object)
			if !ok {
				return errInvalid
			}
			// final.json re-encodes the report, which can outgrow the received line: U+2028 and U+2029 become 6-byte escapes.
			if body, e := encoded(report); e != nil || len(body) > 1<<20 {
				return errInvalid
			}
			var networkOut string
			var networkRequest object
			network, networkOut, networkRequest, err = networkLock(x.requestPath, x.requestSHA)
			if err != nil || networkOut != x.out || networkRequest["attempt_id"] != id {
				return errInvalid
			}
			if _, err = writeControl(filepath.Join(x.out, "network-closed.json"), object{"schema": 1, "update_id": id, "request_sha256": x.requestSHA}); err != nil {
				return err
			}
			if err = unix.Flock(int(network.Fd()), unix.LOCK_EX); err != nil {
				return err
			}
			finalSHA, err = writeControl(filepath.Join(x.out, "final.json"), report)
			if err != nil {
				return err
			}
			acceptedPath := filepath.Join(x.out, "final-accepted.json")
			for absent(acceptedPath) {
				select {
				case err = <-failure:
					return err
				case <-time.After(50 * time.Millisecond):
				}
			}
			accepted, _, err := readControl(acceptedPath, 1024)
			if err != nil || !same(accepted, object{"update_id": id, "final_sha256": finalSHA}) {
				return errInvalid
			}
			reply = object{"event": "freshclam_control_committed"}
		case "update_candidate":
			if !fields(value, "event name sha256 bytes") || report == nil || active != nil || !integer(value["bytes"], 1, candidateLimit) || !validDigest(value["sha256"]) {
				return errInvalid
			}
			name, ok := value["name"].(string)
			if !ok || !definitionName.MatchString(name) {
				return errInvalid
			}
			stem := strings.SplitN(name, ".", 2)[0]
			for _, row := range candidates {
				if strings.SplitN(row["name"].(string), ".", 2)[0] == stem {
					return errInvalid
				}
			}
			rows, ok := report["definitions"].([]any)
			if !ok {
				return errInvalid
			}
			matched := false
			for _, v := range rows {
				row, ok := v.(object)
				if ok && row["definition"] == stem {
					matched = same(row["artifact"], object{"sha256": value["sha256"], "bytes": value["bytes"]})
					break
				}
			}
			if report["fixture_only"] != false || report["all_required_origin_confirmations"] != true || report["all_required_artifacts_verified"] != true || !matched {
				return errInvalid
			}
			total += number(value["bytes"])
			if total > candidateLimit {
				return errInvalid
			}
			directory := filepath.Join(x.out, "candidates")
			if len(candidates) == 0 {
				if !absent(directory) {
					return errInvalid
				}
				info, e := statPath(x.out)
				if e != nil {
					return e
				}
				if _, err = writeControl(filepath.Join(x.out, "candidate-directory-intent.json"), object{"schema": 1, "update_id": id, "device": info.Dev, "inode": info.Ino}); err != nil {
					return err
				}
				if err = os.Mkdir(directory, 0700); err != nil {
					return err
				}
				if err = syncDirectory(x.out); err != nil {
					return err
				}
				info, e = statPath(directory)
				if e != nil {
					return e
				}
				if _, err = writeControl(filepath.Join(x.out, "candidate-directory.json"), object{"schema": 1, "update_id": id, "device": info.Dev, "inode": info.Ino}); err != nil {
					return err
				}
			}
			path := filepath.Join(directory, name+".pending")
			if !absent(path) || !absent(filepath.Join(directory, name)) {
				return errInvalid
			}
			info, e := statPath(directory)
			if e != nil {
				return e
			}
			plan := object{"schema": 1, "update_id": id, "name": name, "sha256": value["sha256"], "bytes": value["bytes"], "device": info.Dev, "inode": info.Ino}
			if _, err = writeControl(filepath.Join(x.out, "candidate-plan-"+stem+".json"), plan); err != nil {
				return err
			}
			fd, e := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
			if e != nil {
				return e
			}
			active = &candidate{file: os.NewFile(uintptr(fd), path), path: path, row: object{"name": name, "sha256": value["sha256"], "bytes": value["bytes"]}, digest: sha256.New()}
			info, err = fileStat(active.file)
			if err != nil {
				return err
			}
			if err = active.file.Sync(); err != nil {
				return err
			}
			if err = syncDirectory(directory); err != nil {
				return err
			}
			plan["device"], plan["inode"] = info.Dev, info.Ino
			if _, err = writeControl(filepath.Join(x.out, "candidate-owner-"+stem+".json"), plan); err != nil {
				return err
			}
		case "update_chunk":
			data, ok := value["data"].(string)
			if !fields(value, "event data") || active == nil || !ok {
				return errInvalid
			}
			chunk, e := base64.StdEncoding.Strict().DecodeString(data)
			if e != nil || len(chunk) == 0 || len(chunk) > 49152 || active.size+int64(len(chunk)) > number(active.row["bytes"]) {
				return errInvalid
			}
			if _, err = active.file.Write(chunk); err != nil {
				return err
			}
			active.digest.Write(chunk)
			active.size += int64(len(chunk))
		case "update_candidate_end":
			if !fields(value, "event") || active == nil || active.size != number(active.row["bytes"]) || hex.EncodeToString(active.digest.Sum(nil)) != active.row["sha256"] {
				return errInvalid
			}
			if err = active.file.Sync(); err != nil {
				return err
			}
			if err = active.file.Close(); err != nil {
				return err
			}
			active.file = nil
			if err = os.Rename(active.path, filepath.Join(filepath.Dir(active.path), active.row["name"].(string))); err != nil {
				return err
			}
			if err = syncDirectory(filepath.Dir(active.path)); err != nil {
				return err
			}
			candidates = append(candidates, active.row)
			active = nil
		case "update_done":
			if !fields(value, "event") || report == nil || active != nil {
				return errInvalid
			}
			for _, row := range candidates {
				if err = verifyCandidate(filepath.Join(x.out, "candidates", row["name"].(string)), row); err != nil {
					return err
				}
			}
			if len(candidates) > 0 {
				if err = syncDirectory(filepath.Join(x.out, "candidates")); err != nil {
					return err
				}
			}
			if _, err = writeControl(filepath.Join(x.out, "candidates.json"), object{"schema": 1, "update_id": id, "base_generation": x.requested["restore"].(object)["base_generation"], "final_sha256": finalSHA, "files": candidates}); err != nil {
				return err
			}
			if len(candidates) > 0 {
				if err = buildImage(x.out, x.requested, x.manifest, candidates); err != nil {
					return err
				}
			}
			return send(connection, reply)
		default:
			return errInvalid
		}
		if err = send(connection, reply); err != nil {
			return err
		}
	}
	return errInvalid
}

func verifyCandidate(path string, row object) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	before, err := fileStat(f)
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Getuid()) || before.Nlink != 1 || before.Size != number(row["bytes"]) {
		return errInvalid
	}
	actual, err := hashFile(f, before.Size)
	if err != nil || actual != row["sha256"] {
		return errInvalid
	}
	after, err := fileStat(f)
	if err != nil || !sameIdentity(before, after) {
		return errInvalid
	}
	row["device"], row["inode"], row["modified_ns"], row["changed_ns"] = after.Dev, after.Ino, after.Mtim.Nano(), after.Ctim.Nano()
	return nil
}
