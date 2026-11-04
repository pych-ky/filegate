package hostvm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Object = map[string]any

type Profile struct {
	OwnerKind      string
	TimeoutSeconds int
}

var ScanProfile = Profile{"scan", 300}
var UpdateProfile = Profile{"update", 600}

const RawBytes int64 = 4294967296
const RequestLimit int64 = 16384
const ControlLimit int64 = 65536
const ReportLimit int64 = 32 << 20

type Runtime struct{ Root, VM, NativeBinary, NativeSource, State, Executable string }

func New(root string) (*Runtime, error) {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(root) || canonical != root || filepath.Clean(root) != root {
		return nil, Error("RUNTIME_WORKSPACE_INVALID")
	}
	if _, err = Owned(root, unix.S_IFDIR, 0700); err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	return &Runtime{Root: root, VM: filepath.Join(root, "experiments/vm"), NativeBinary: filepath.Join(root, "experiments/host/.build/integrated-watchdog"), NativeSource: filepath.Join(root, "experiments/host/integrated_watchdog.m"), State: filepath.Join(home, "Library/Application Support/FileGate/verification/experiments/host/.build"), Executable: executable}, nil
}
func Error(code string) error       { return errors.New(code) }
func Str(m Object, k string) string { v, _ := m[k].(string); return v }
func Bool(m Object, k string) bool  { v, _ := m[k].(bool); return v }
func Map(m Object, k string) Object { v, _ := m[k].(map[string]any); return v }
func List(m Object, k string) []any { v, _ := m[k].([]any); return v }
func Num(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, e := n.Int64()
		return i, e == nil
	case int:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		if n <= 1<<63-1 {
			return int64(n), true
		}
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	}
	return 0, false
}
func Int(m Object, k string) int64 {
	v, ok := Num(m[k])
	if !ok {
		return -1
	}
	return v
}
func Uint(m Object, k string) (uint64, bool) {
	switch n := m[k].(type) {
	case json.Number:
		v, e := strconv.ParseUint(string(n), 10, 64)
		return v, e == nil
	case uint64:
		return n, true
	default:
		v, ok := Num(n)
		return uint64(v), ok && v >= 0
	}
}
func Fields(m Object, names ...string) bool {
	if m == nil || len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}
func Equal(a, b any) bool {
	x, e := Canonical(a)
	y, f := Canonical(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func Clone(m Object) Object { body, _ := Canonical(m); v, _ := Decode(body); return v }
func Canonical(value any) ([]byte, error) {
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}
func Encoded(value any) ([]byte, error) {
	b, e := Canonical(value)
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}
func Decode(body []byte) (Object, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 64 {
			return nil, Error("JSON_DEPTH_LIMIT")
		}
		token, e := d.Token()
		if e != nil {
			return nil, e
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				m := Object{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, e
					}
					key, ok := k.(string)
					if !ok {
						return nil, Error("JSON_FIELD_INVALID")
					}
					if _, ok = m[key]; ok {
						return nil, Error("DUPLICATE_JSON_FIELD")
					}
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					m[key] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, Error("JSON_OBJECT_INVALID")
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, Error("JSON_ARRAY_INVALID")
				}
				return a, nil
			default:
				return nil, Error("JSON_DELIMITER_INVALID")
			}
		}
		return token, nil
	}
	v, e := value(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, Error("JSON_TRAILING_DATA")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, Error("JSON_OBJECT_REQUIRED")
	}
	return m, nil
}
func HashBytes(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func HashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func Owned(path string, kind uint32, mode uint32) (unix.Stat_t, error) {
	var s unix.Stat_t
	e := unix.Lstat(path, &s)
	if e != nil {
		return s, e
	}
	if s.Uid != uint32(os.Getuid()) || uint32(s.Mode)&unix.S_IFMT != kind || uint32(s.Mode)&07777 != mode {
		return s, Error("OWNED_PATH_INVALID")
	}
	return s, nil
}
func SameIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim
}
func ReadBytes(path string, maximum int64) ([]byte, error) {
	return readBytesModes(path, maximum, false)
}
func ReadAsset(path string, maximum int64) (Object, []byte, error) {
	b, e := readBytesModes(path, maximum, true)
	if e != nil {
		return nil, nil, e
	}
	v, e := Decode(b)
	return v, b, e
}
func readBytesModes(path string, maximum int64, asset bool) ([]byte, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, current unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Getuid()) || before.Size < 0 || before.Size > maximum || (before.Mode&07777 != 0600 && (!asset || before.Mode&07777 != 0644 && before.Mode&07777 != 0444)) {
		return nil, Error("CONTROL_FILE_INVALID")
	}
	body, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil {
		return nil, e
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(path, &current) != nil || int64(len(body)) != before.Size || !SameIdentity(before, after) || !SameIdentity(after, current) {
		return nil, Error("CONTROL_FILE_CHANGED")
	}
	return body, nil
}
func Read(path string, maximum int64) (Object, []byte, error) {
	b, e := ReadBytes(path, maximum)
	if e != nil {
		return nil, nil, e
	}
	v, e := Decode(b)
	return v, b, e
}
func SyncDirectory(path string) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}
func create(path string, body []byte, mode uint32) error {
	fd, e := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	n, e := f.Write(body)
	if e == nil && n != len(body) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
func WriteNew(path string, value any) (string, error) {
	body, e := Encoded(value)
	if e != nil {
		return "", e
	}
	pending := path + ".pending"
	if e = create(pending, body, 0600); e != nil {
		return "", e
	}
	if e = os.Link(pending, path); e != nil {
		return "", e
	}
	if e = SyncDirectory(filepath.Dir(path)); e != nil {
		return "", e
	}
	if e = os.Remove(pending); e != nil {
		return "", e
	}
	if e = SyncDirectory(filepath.Dir(path)); e != nil {
		return "", e
	}
	return HashBytes(body), nil
}
func WriteOnce(path string, value any) (string, error) {
	if _, e := os.Lstat(path); e == nil {
		current, b, e := Read(path, 16<<20)
		if e != nil {
			return "", e
		}
		if !Equal(current, value) {
			return "", Error("RECOVERY_RECORD_CHANGED")
		}
		if e = SyncDirectory(filepath.Dir(path)); e != nil {
			return "", e
		}
		return HashBytes(b), nil
	} else if !os.IsNotExist(e) {
		return "", e
	}
	if _, e := os.Lstat(path + ".pending"); e == nil {
		if _, e = ReadBytes(path+".pending", 16<<20); e != nil {
			return "", e
		}
		if e = os.Remove(path + ".pending"); e != nil {
			return "", e
		}
		if e = SyncDirectory(filepath.Dir(path)); e != nil {
			return "", e
		}
	} else if !os.IsNotExist(e) {
		return "", e
	}
	return WriteNew(path, value)
}
func SaveCopy(path string, body []byte) error {
	existing, e := ReadBytes(path, int64(len(body)))
	if e == nil {
		if bytes.Equal(existing, body) {
			return nil
		}
		if !bytes.HasPrefix(body, existing) {
			return Error("NATIVE_PROOF_COPY_CHANGED")
		}
		var before unix.Stat_t
		if e = unix.Lstat(path, &before); e != nil {
			return e
		}
		fd, e := unix.Open(path, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(fd), path)
		defer f.Close()
		var now unix.Stat_t
		if unix.Fstat(fd, &now) != nil || !SameIdentity(before, now) {
			return Error("NATIVE_PROOF_COPY_CHANGED")
		}
		if e = f.Truncate(0); e != nil {
			return e
		}
		if _, e = f.Write(body); e != nil {
			return e
		}
		return f.Sync()
	}
	if !os.IsNotExist(e) {
		return e
	}
	return create(path, body, 0600)
}
func RandomPath(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return filepath.Join("/private/tmp", prefix+hex.EncodeToString(b[:])), nil
}
func Binding(req Object) Object {
	return Object{"schema": 1, "job_id": req["job_id"], "attempt_id": req["attempt_id"], "input_sha256": req["expected_sha256"], "byte_size": req["byte_size"]}
}
func Bound(value, req Object) error {
	for k, v := range Binding(req) {
		if !Equal(value[k], v) {
			return Error("RECOVERY_REQUEST_MISMATCH")
		}
	}
	return nil
}
func Merge(a, b Object) Object {
	m := Object{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}
func DigestControl(path string, limit int64) (string, error) {
	_, b, e := Read(path, limit)
	if e != nil {
		return "", e
	}
	return HashBytes(b), nil
}
func Strings(value any) ([]string, bool) {
	switch a := value.(type) {
	case []string:
		return a, true
	case []any:
		r := make([]string, len(a))
		for i, v := range a {
			var ok bool
			r[i], ok = v.(string)
			if !ok || strings.ContainsRune(r[i], 0) {
				return nil, false
			}
		}
		return r, true
	}
	return nil, false
}
func DirectoryIdentity(s unix.Stat_t) Object { return Object{"device": uint64(s.Dev), "inode": s.Ino} }
func SameDirectory(s unix.Stat_t, m Object) bool {
	dev, ok := Uint(m, "device")
	ino, ok2 := Uint(m, "inode")
	return ok && ok2 && uint64(s.Dev) == dev && s.Ino == ino
}
func Required(value any, kind reflect.Kind) bool {
	return value != nil && reflect.TypeOf(value).Kind() == kind
}
func missing(path string) bool { _, e := os.Lstat(path); return os.IsNotExist(e) }
func objectError(scope string, e error) error {
	if e == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", scope, e)
}
