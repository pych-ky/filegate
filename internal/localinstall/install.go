package localinstall

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filegate.local/filegate/internal/acceptance"
	"golang.org/x/sys/unix"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The accepted product digest is fixed when building the installer.
var acceptedBinarySHA256 string

func stage3Completed(expected string) bool {
	return acceptance.Stage3Completed && expected == acceptedBinarySHA256
}

type Result struct {
	Schema                    int     `json:"schema"`
	Installed                 bool    `json:"installed"`
	BinarySHA256              string  `json:"binary_sha256"`
	PreviousSHA256            *string `json:"previous_sha256"`
	Stage3Completed           bool    `json:"stage3_completed"`
	RunningProcessesRestarted bool    `json:"running_processes_restarted"`
}

type manifest struct {
	Schema          int    `json:"schema"`
	BinarySHA256    string `json:"binary_sha256"`
	Distribution    string `json:"distribution"`
	Stage3Completed bool   `json:"stage3_completed"`
}

type installError string

func (e installError) Error() string { return string(e) }

func ErrorCode(err error) string {
	var known installError
	if errors.As(err, &known) {
		return string(known)
	}
	return "LOCAL_INSTALL_FAILED"
}

func openAt(directory int, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(directory, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func privateAt(directory int, name string) (*os.File, error) {
	file, err := openAt(directory, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, installError("PRIVATE_DIRECTORY_REQUIRED")
	}
	var info unix.Stat_t
	if unix.Fstat(int(file.Fd()), &info) != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&07777 != 0700 {
		file.Close()
		return nil, installError("PRIVATE_DIRECTORY_REQUIRED")
	}
	return file, nil
}

func makePrivateAt(directory *os.File, name string) (*os.File, error) {
	err := unix.Mkdirat(int(directory.Fd()), name, 0700)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	if err == nil {
		if err = directory.Sync(); err != nil {
			return nil, err
		}
	}
	return privateAt(int(directory.Fd()), name)
}

func regular(file *os.File) (unix.Stat_t, error) {
	var info unix.Stat_t
	if unix.Fstat(int(file.Fd()), &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size < 0 {
		return info, installError("REGULAR_BINARY_REQUIRED")
	}
	return info, nil
}

func sameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func hashFile(file *os.File, before unix.Stat_t) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, before.Size); err != nil {
		return "", err
	}
	after, err := regular(file)
	if err != nil || !sameFile(before, after) {
		return "", installError("SOURCE_CHANGED_DURING_COPY")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func manifestFields(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		switch key {
		case "schema", "binary_sha256", "distribution", "stage3_completed":
		default:
			return false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
		seen[key] = true
	}
	last, err := decoder.Token()
	var extra any
	return err == nil && last == json.Delim('}') && len(seen) == 4 && decoder.Decode(&extra) == io.EOF
}

func validateVersion(versions *os.File, expected string, newTarget bool) error {
	directory, err := privateAt(int(versions.Fd()), expected)
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := openAt(int(directory.Fd()), "filegate", unix.O_RDONLY, 0)
	if err != nil {
		return installError("INSTALLED_BINARY_INVALID")
	}
	info, err := regular(file)
	if err != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&07777 != 0500 || info.Nlink != 1 {
		file.Close()
		return installError("INSTALLED_BINARY_INVALID")
	}
	actual, err := hashFile(file, info)
	closeErr := file.Close()
	if err != nil || closeErr != nil || actual != expected {
		return installError("INSTALLED_BINARY_INVALID")
	}
	file, err = openAt(int(directory.Fd()), "manifest.json", unix.O_RDONLY, 0)
	if err != nil {
		return installError("INSTALLED_MANIFEST_INVALID")
	}
	defer file.Close()
	info, err = regular(file)
	if err != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&07777 != 0600 || info.Nlink != 1 || info.Size > 4096 {
		return installError("INSTALLED_MANIFEST_INVALID")
	}
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	var value manifest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	after, statErr := regular(file)
	decodeErr := decoder.Decode(&value)
	expectedStage3 := value.Stage3Completed
	if newTarget {
		expectedStage3 = stage3Completed(expected)
	}
	if err != nil || len(body) > 4096 || statErr != nil || !sameFile(info, after) || !manifestFields(body) || decodeErr != nil || value != (manifest{Schema: 1, BinarySHA256: expected, Distribution: "local-development", Stage3Completed: expectedStage3}) {
		return installError("INSTALLED_MANIFEST_INVALID")
	}
	return nil
}

func openParent(prefix string) (*os.File, string, error) {
	abs, err := filepath.Abs(prefix)
	if err != nil {
		return nil, "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, "", err
	}
	canonical := filepath.Join(parent, filepath.Base(abs))
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", err
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil || canonical == "/" || canonical == home {
		return nil, "", installError("INVALID_INSTALL_PREFIX")
	}
	for at := canonical; ; at = filepath.Dir(at) {
		if _, err := os.Lstat(filepath.Join(at, ".git")); err == nil {
			return nil, "", installError("INVALID_INSTALL_PREFIX")
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOTDIR) {
			return nil, "", err
		}
		if at == "/" {
			break
		}
	}
	directory, err := os.Open("/")
	if err != nil {
		return nil, "", err
	}
	for _, part := range strings.Split(strings.TrimPrefix(parent, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := openAt(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		directory.Close()
		if e != nil {
			return nil, "", e
		}
		directory = next
	}
	return directory, filepath.Base(canonical), nil
}

func randomName(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func stageVersion(source, versions *os.File, original unix.Stat_t, expected string) (err error) {
	name, err := randomName(".install-")
	if err != nil {
		return err
	}
	if err = unix.Mkdirat(int(versions.Fd()), name, 0700); err != nil {
		return err
	}
	directory, err := privateAt(int(versions.Fd()), name)
	if err != nil {
		return err
	}
	defer directory.Close()
	published := false
	var directoryInfo unix.Stat_t
	if err = unix.Fstat(int(directory.Fd()), &directoryInfo); err != nil {
		return err
	}
	created := map[string]unix.Stat_t{}
	defer func() {
		if published {
			return
		}
		// Only this invocation's two known files are eligible for temporary cleanup.
		for child, owned := range created {
			var named unix.Stat_t
			e := unix.Fstatat(int(directory.Fd()), child, &named, unix.AT_SYMLINK_NOFOLLOW)
			if errors.Is(e, unix.ENOENT) {
				continue
			}
			if e != nil || named.Dev != owned.Dev || named.Ino != owned.Ino || named.Nlink != 1 || named.Uid != owned.Uid || named.Mode&unix.S_IFMT != unix.S_IFREG {
				err = installError("LOCAL_INSTALL_FAILED")
				continue
			}
			if e = unix.Unlinkat(int(directory.Fd()), child, 0); e != nil {
				err = e
			}
		}
		if e := directory.Sync(); e != nil {
			err = e
		}
		var named unix.Stat_t
		if e := unix.Fstatat(int(versions.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); e != nil || named.Dev != directoryInfo.Dev || named.Ino != directoryInfo.Ino || named.Mode&unix.S_IFMT != unix.S_IFDIR {
			err = installError("LOCAL_INSTALL_FAILED")
			return
		}
		if e := unix.Unlinkat(int(versions.Fd()), name, unix.AT_REMOVEDIR); e != nil {
			err = e
		} else if e = versions.Sync(); e != nil {
			err = e
		}
	}()
	target, err := openAt(int(directory.Fd()), "filegate", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return err
	}
	var owned unix.Stat_t
	if err = unix.Fstat(int(target.Fd()), &owned); err != nil {
		target.Close()
		return err
	}
	created["filegate"] = owned
	if _, err = source.Seek(0, io.SeekStart); err == nil {
		_, err = io.CopyN(target, source, original.Size)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = installError("SOURCE_CHANGED_DURING_COPY")
	}
	after, statErr := regular(source)
	if err == nil && (statErr != nil || !sameFile(original, after)) {
		err = installError("SOURCE_CHANGED_DURING_COPY")
	}
	if err == nil {
		err = target.Chmod(0500)
	}
	if err == nil {
		err = syncFile(target)
	}
	closeErr := target.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	target, err = openAt(int(directory.Fd()), "filegate", unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	info, err := regular(target)
	actual := ""
	if err == nil {
		actual, err = hashFile(target, info)
	}
	closeErr = target.Close()
	if err != nil || closeErr != nil || actual != expected {
		return installError("SOURCE_CHANGED_DURING_COPY")
	}
	body, err := json.Marshal(manifest{Schema: 1, BinarySHA256: expected, Distribution: "local-development", Stage3Completed: stage3Completed(expected)})
	if err != nil {
		return err
	}
	target, err = openAt(int(directory.Fd()), "manifest.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = unix.Fstat(int(target.Fd()), &owned); err != nil {
		target.Close()
		return err
	}
	created["manifest.json"] = owned
	if _, err = target.Write(append(body, '\n')); err == nil {
		err = syncFile(target)
	}
	closeErr = target.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = directory.Sync(); err != nil {
		return err
	}
	if err = renameExclusive(int(versions.Fd()), name, expected); err != nil {
		return err
	}
	published = true
	return versions.Sync()
}

func Install(source, prefix, expected string) (Result, error) {
	var result Result
	if !digestPattern.MatchString(expected) {
		return result, installError("EXPECTED_SHA256_REQUIRED")
	}
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return result, installError("REGULAR_BINARY_REQUIRED")
		}
		return result, err
	}
	original := os.NewFile(uintptr(fd), "source")
	defer original.Close()
	info, err := regular(original)
	if err != nil {
		return result, err
	}
	actual, err := hashFile(original, info)
	if err != nil {
		return result, err
	}
	if actual != expected {
		return result, installError("SOURCE_HASH_MISMATCH")
	}
	parent, name, err := openParent(prefix)
	if err != nil {
		return result, err
	}
	defer parent.Close()
	root, err := makePrivateAt(parent, name)
	if err != nil {
		return result, err
	}
	defer root.Close()
	lock, err := openAt(int(root.Fd()), ".install.lock", unix.O_RDWR|unix.O_CREAT, 0600)
	if err != nil {
		return result, installError("INSTALL_LOCK_INVALID")
	}
	defer lock.Close()
	lockInfo, err := regular(lock)
	if err != nil || lockInfo.Uid != uint32(os.Geteuid()) || lockInfo.Mode&07777 != 0600 || lockInfo.Nlink != 1 {
		return result, installError("INSTALL_LOCK_INVALID")
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return result, err
	}
	versions, err := makePrivateAt(root, "versions")
	if err != nil {
		return result, err
	}
	defer versions.Close()
	var previous *string
	var link [256]byte
	n, err := unix.Readlinkat(int(root.Fd()), "current", link[:])
	if err == nil {
		value := string(link[:n])
		if n == len(link) || !strings.HasPrefix(value, "versions/") || !digestPattern.MatchString(strings.TrimPrefix(value, "versions/")) {
			return result, installError("CURRENT_VERSION_INVALID")
		}
		hash := strings.TrimPrefix(value, "versions/")
		if err = validateVersion(versions, hash, false); err != nil {
			return result, err
		}
		previous = &hash
	} else if !errors.Is(err, unix.ENOENT) {
		return result, installError("CURRENT_VERSION_INVALID")
	}
	var existing unix.Stat_t
	err = unix.Fstatat(int(versions.Fd()), expected, &existing, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		if err = stageVersion(original, versions, info, expected); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	if err = validateVersion(versions, expected, true); err != nil {
		return result, err
	}
	pointer, err := randomName(".current-")
	if err != nil {
		return result, err
	}
	if err = unix.Symlinkat("versions/"+expected, int(root.Fd()), pointer); err != nil {
		return result, err
	}
	defer unix.Unlinkat(int(root.Fd()), pointer, 0)
	if err = unix.Renameat(int(root.Fd()), pointer, int(root.Fd()), "current"); err != nil {
		return result, err
	}
	if err = root.Sync(); err != nil {
		return result, err
	}
	return Result{Schema: 1, Installed: true, BinarySHA256: expected, PreviousSHA256: previous, Stage3Completed: stage3Completed(expected)}, nil
}
