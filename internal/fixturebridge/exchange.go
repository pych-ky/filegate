package fixturebridge

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"filegate.local/filegate/internal/vmbridge"
	"golang.org/x/sys/unix"
)

var invalid = errors.New("UPDATE_FIXTURE_BRIDGE_INVALID")

type object = map[string]any

func integer(value any) int64 {
	n, ok := value.(json.Number)
	if !ok {
		return -1
	}
	i, err := n.Int64()
	if err != nil {
		return -1
	}
	return i
}

func fields(value object, names ...string) bool {
	if len(value) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	return true
}

func encoded(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	return append(body, '\n'), err
}

func saveProgress(path string, value object) error {
	return saveBounded(path, value, 65536)
}

// saveBounded replaces a record through a synced pending file; limit bounds both the new and the existing record.
func saveBounded(path string, value object, limit int) error {
	body, err := encoded(value)
	if err != nil || len(body) > limit {
		return invalid
	}
	if _, err = os.Lstat(path); err == nil {
		if _, _, err = hostvm.Read(path, int64(limit)); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	pending := path + ".pending"
	f, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(body)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil {
		return invalid
	}
	if err = os.Rename(pending, path); err != nil {
		return err
	}
	return hostvm.SyncDirectory(filepath.Dir(path))
}

func line(reader *bufio.Reader, limit int) ([]byte, error) {
	var result []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(result)+len(part) > limit {
			return nil, invalid
		}
		result = append(result, part...)
		if err == nil {
			return result, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, invalid
		}
	}
}

func Run(directory, expected string, input io.Reader, output io.Writer) error {
	run, err := filepath.EvalSymlinks(directory)
	if err != nil || !filepath.IsAbs(run) || run != directory {
		return invalid
	}
	info, err := os.Lstat(run)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return invalid
	}
	if _, err = hostvm.Owned(run, unix.S_IFDIR, 0700); err != nil {
		return err
	}
	config, body, err := hostvm.Read(filepath.Join(run, "update-bridge.json"), 65536)
	if err != nil || hostvm.HashBytes(body) != expected || !fields(config, "schema", "fixture_only", "mode", "library_sha256", "request", "output_directory") ||
		integer(config["schema"]) != 1 || config["fixture_only"] != true || config["mode"] != "first" {
		return invalid
	}
	library, ok := config["library_sha256"].(string)
	if !ok || len(library) != 64 {
		return invalid
	}
	decoded, err := hex.DecodeString(library)
	if err != nil || hex.EncodeToString(decoded) != library {
		return invalid
	}
	request, ok := config["request"].(object)
	if !ok {
		return invalid
	}
	out, ok := config["output_directory"].(string)
	canonical, err := filepath.EvalSymlinks(out)
	if !ok || err != nil || !filepath.IsAbs(out) || canonical != out {
		return invalid
	}
	info, err = os.Lstat(out)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return invalid
	}
	if _, err = hostvm.Owned(out, unix.S_IFDIR, 0700); err != nil {
		return err
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
	if socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Uid != uint32(os.Geteuid()) || socket.Nlink != 1 || os.Chmod(channel, 0600) != nil {
		return invalid
	}
	connection, err := net.DialTimeout("unix", channel, 10*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	received, relayed, records := 0, 0, 0
	receive := func() (object, error) {
		if connection.SetReadDeadline(time.Now().Add(60*time.Second)) != nil {
			return nil, invalid
		}
		body, err := line(reader, 2<<20)
		received += len(body)
		records++
		if err != nil || received > 4<<20 || records > 1024 {
			return nil, invalid
		}
		return vmbridge.DecodeObject(body)
	}
	relay := func(value object) error {
		body, err := encoded(value)
		relayed += len(body)
		if err != nil || len(body) > 65536 || relayed > 1<<20 {
			return invalid
		}
		_, err = output.Write(body)
		return err
	}
	ready, err := receive()
	if err != nil || !vmbridge.ValidateFixturePreflight(ready) {
		return invalid
	}
	first, err := receive()
	if err != nil {
		return err
	}
	workspace, err := vmbridge.NormalizeWorkspace(first)
	if err != nil || relay(workspace) != nil || relay(object{"event": "validated_ready"}) != nil {
		return invalid
	}
	ack, err := line(bufio.NewReader(input), 64)
	if err != nil || string(ack) != "READY\n" {
		return invalid
	}
	data := []byte(`{"filegate_control_mode":"first"}`)
	sum := sha256.Sum256(data)
	header, err := encoded(object{"job_id": "probe-job", "attempt_id": "probe-attempt", "sha256": hex.EncodeToString(sum[:]), "byte_size": len(data), "policy_digest": "stage0-synthetic-only", "fixture": "freshclam-adapter"})
	if err != nil || connection.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		return invalid
	}
	if _, err = connection.Write(append(header, data...)); err != nil {
		return err
	}
	checkpoints := [][2]string{{"apk", "started"}, {"apk", "completed"}, {"library", "started"}, {"library", "completed"}, {"fixture", "started"}, {"fixture", "completed"}}
	progress, previous, issued := 0, int64(-1), false
	started := time.Now()
	var buildProgress []object
	for time.Since(started) < 300*time.Second {
		record, err := receive()
		if err != nil {
			return err
		}
		switch record["event"] {
		case "workspace":
			workspace, err := vmbridge.NormalizeWorkspace(record)
			if err != nil || relay(workspace) != nil || workspace["reason"] != nil {
				return invalid
			}
		case "freshclam_progress":
			elapsed := integer(record["elapsed_ms"])
			if !fields(record, "event", "fixture", "phase", "checkpoint", "sequence", "elapsed_ms") || record["fixture"] != "freshclam-adapter" || progress >= len(checkpoints) ||
				record["phase"] != checkpoints[progress][0] || record["checkpoint"] != checkpoints[progress][1] || integer(record["sequence"]) != int64(progress+1) || elapsed < previous || elapsed < 0 || elapsed > 300000 {
				return invalid
			}
			progress++
			previous = elapsed
			record["host_elapsed_ms"] = time.Since(started).Milliseconds()
			buildProgress = append(buildProgress, record)
			if err = saveProgress(filepath.Join(run, "fixture-observation.json"), object{"schema": 1, "fixture": "freshclam-adapter", "build_progress": buildProgress}); err != nil {
				return err
			}
		case "freshclam_control_ready":
			if !fields(record, "event", "id", "library_sha256") || record["id"] != "429-delta" || record["library_sha256"] != library || progress != 5 || issued {
				return invalid
			}
			issued = true
			reply, err := encoded(object{"event": "freshclam_control_request", "id": "429-delta", "request": request})
			if err != nil || connection.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
				return invalid
			}
			if _, err = connection.Write(reply); err != nil {
				return err
			}
		case "freshclam_control_final":
			report, ok := record["report"].(object)
			if !fields(record, "event", "id", "report") || record["id"] != "429-delta" || progress != 5 || !issued || !ok {
				return invalid
			}
			if _, err = hostvm.WriteNew(filepath.Join(out, "final.json"), report); err != nil {
				return err
			}
			for {
				time.Sleep(100 * time.Millisecond)
			}
		default:
			return invalid
		}
	}
	return invalid
}
