// Package updatebridge transports a fixed official update within native supervision.
package updatebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const candidateLimit int64 = (1 << 30) - (64 << 20)
const imageBytes int64 = 1 << 30
const updateProfile = "filegate-official-update-v1"

var errInvalid = errors.New("UPDATE_BRIDGE_INVALID")

type object = map[string]any

func decode(data []byte) (any, error) {
	if !utf8.Valid(data) || !validEscapes(data) {
		return nil, errInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := tokenValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errInvalid
	}
	return value, nil
}

// encoding/json replaces unpaired surrogates; the bridge must reject them.
func validEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' || i+1 == len(data) {
			continue
		}
		if data[i+1] != 'u' || i+6 > len(data) {
			i++
			continue
		}
		code, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil {
			return false
		}
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+12 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
		i += 5
	}
	return true
}

func tokenValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errInvalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		m := object{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errInvalid
			}
			if _, exists := m[name]; exists {
				return nil, errInvalid
			}
			v, err := tokenValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			m[name] = v
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return nil, errInvalid
		}
		return m, nil
	case json.Delim('['):
		items := []any{}
		for d.More() {
			v, err := tokenValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return nil, errInvalid
		}
		return items, nil
	case json.Delim('}'), json.Delim(']'):
		return nil, errInvalid
	default:
		return t, nil
	}
}

func encoded(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func validDigest(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}
func fields(m object, names string) bool {
	keys := strings.Fields(names)
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func integer(v any, min, max int64) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64()
	return err == nil && i >= min && i <= max
}
func number(v any) int64        { n, _ := v.(json.Number); i, _ := n.Int64(); return i }
func boolean(v any) bool        { _, ok := v.(bool); return ok }
func array(v any, max int) bool { a, ok := v.([]any); return ok && len(a) <= max }
func oneOf(v any, values ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, item := range values {
		if s == item {
			return true
		}
	}
	return false
}
func same(a, b any) bool {
	left, e1 := encoded(a)
	right, e2 := encoded(b)
	return e1 == nil && e2 == nil && bytes.Equal(left, right)
}

func fileStat(f *os.File) (unix.Stat_t, error) {
	var s unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &s)
	return s, err
}
func unchanged(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim
}
func openOwned(path string, mode uint32) (*os.File, unix.Stat_t, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	s, err := fileStat(f)
	if err != nil || s.Mode&unix.S_IFMT != unix.S_IFREG || uint32(s.Mode)&07777 != mode || s.Uid != uint32(os.Getuid()) {
		f.Close()
		return nil, s, errInvalid
	}
	return f, s, nil
}
func readControl(path string, limit int64) (any, []byte, error) {
	f, before, err := openOwned(path, 0600)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if before.Size > limit {
		return nil, nil, errInvalid
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := fileStat(f)
	if err != nil || statErr != nil || int64(len(body)) != before.Size || int64(len(body)) > limit || !unchanged(before, after) {
		return nil, nil, errInvalid
	}
	v, err := decode(body)
	return v, body, err
}

func writeControl(path string, value any) (string, error) {
	body, err := encoded(value)
	if err != nil {
		return "", err
	}
	fd, err := unix.Open(path+".pending", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path+".pending")
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		return "", errInvalid
	}
	if err = os.Rename(path+".pending", path); err != nil {
		return "", err
	}
	dirfd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(dirfd)
	if err = unix.Fsync(dirfd); err != nil {
		return "", err
	}
	return digest(body), nil
}

func syncDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}
func sameIdentity(a, b unix.Stat_t) bool {
	return unchanged(a, b) && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Ctim == b.Ctim
}
func statPath(path string) (unix.Stat_t, error) {
	var s unix.Stat_t
	err := unix.Lstat(path, &s)
	return s, err
}
func absent(path string) bool { _, err := os.Lstat(path); return errors.Is(err, os.ErrNotExist) }
func canonical(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.IsAbs(path) && resolved == path
}
