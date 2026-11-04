package localinstall

import (
	"os"

	"golang.org/x/sys/unix"
)

func syncFile(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	_, err := unix.FcntlInt(file.Fd(), unix.F_FULLFSYNC, 0)
	return err
}

func renameExclusive(directory int, source, target string) error {
	return unix.RenameatxNp(directory, source, directory, target, unix.RENAME_EXCL)
}
