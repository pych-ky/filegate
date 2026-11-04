package update

import (
	"golang.org/x/sys/unix"
	"os"
)

func runtimeSyncFile(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	_, err := unix.FcntlInt(file.Fd(), unix.F_FULLFSYNC, 0)
	return err
}

func runtimeRename(source, target string) error {
	return unix.RenameatxNp(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_EXCL)
}
