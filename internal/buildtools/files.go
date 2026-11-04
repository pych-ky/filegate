package buildtools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func SHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digest(body []byte) string {
	value := sha256.Sum256(body)
	return hex.EncodeToString(value[:])
}

func validSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func jsonBytes(value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	return append(body, '\n'), err
}

func readJSON(path string, value any) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func privateFile(path string) error {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Getuid()) || st.Mode&07777 != 0600 {
		return fmt.Errorf("owner-only regular file required: %s", path)
	}
	return nil
}

func checked(base, name string) (string, error) {
	if filepath.IsAbs(name) || name == "" {
		return "", errors.New("relative path required")
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return "", errors.New("relative path escaped")
		}
	}
	path := base
	for _, part := range strings.Split(filepath.Clean(name), string(filepath.Separator)) {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink rejected: %s", path)
		}
	}
	return path, nil
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func atomicFile(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".workspace-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(body); err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func saveNewJSON(path string, value any) error {
	body, err := jsonBytes(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return syncDirectory(filepath.Dir(path))
}

func canonical(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if errors.Is(err, os.ErrNotExist) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(absolute))
		if parentErr != nil {
			return "", parentErr
		}
		resolved = filepath.Join(parent, filepath.Base(absolute))
	} else if err != nil {
		return "", err
	}
	return resolved, nil
}

func permissionBits(mode os.FileMode) uint32 {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		bits |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 02000
	}
	if mode&os.ModeSticky != 0 {
		bits |= 01000
	}
	return bits
}

func fileMode(bits uint32) os.FileMode {
	mode := os.FileMode(bits & 0777)
	if bits&04000 != 0 {
		mode |= os.ModeSetuid
	}
	if bits&02000 != 0 {
		mode |= os.ModeSetgid
	}
	if bits&01000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}
