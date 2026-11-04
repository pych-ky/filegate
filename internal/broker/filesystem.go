package broker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return storageError()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return failure("INVALID_STORE_PERMISSIONS", 503)
	}
	var stat unix.Stat_t
	if unix.Lstat(path, &stat) != nil || stat.Uid != uint32(os.Geteuid()) {
		return failure("INVALID_STORE_PERMISSIONS", 503)
	}
	return nil
}
func openPrivate(path string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(perm))
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, errors.New("invalid file")
	}
	return f, nil
}
func (b *Broker) openLocal(r Request) (*os.File, error) {
	root, ok := b.config.InputRoots[r.RootID]
	if !ok {
		return nil, failure("INPUT_ROOT_NOT_ALLOWED", 403)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, failure("INPUT_MISSING", 400)
	}
	parts := strings.Split(r.Source, string(filepath.Separator))
	for _, name := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, failure("INVALID_INPUT_PATH", 400)
		}
		fd = next
	}
	last, e := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	unix.Close(fd)
	if e != nil {
		return nil, failure("INPUT_MISSING", 400)
	}
	f := os.NewFile(uintptr(last), "input")
	var st unix.Stat_t
	if unix.Fstat(last, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return nil, failure("INVALID_INPUT_PATH", 400)
	}
	if st.Size > MaxInputBytes {
		f.Close()
		return nil, failure("LIMIT_EXCEEDED", 413)
	}
	return f, nil
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func checkFree(path string, remaining int64) error {
	var st unix.Statfs_t
	if unix.Statfs(path, &st) != nil {
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	available := uint64(st.Bavail) * uint64(st.Bsize)
	// The broker reserves the management pools before accepting another object.
	if available < uint64(SafetyMargin+remaining+((128+64+1+128+128)<<20)) {
		return failure("DISK_PRESSURE", 507)
	}
	return nil
}
