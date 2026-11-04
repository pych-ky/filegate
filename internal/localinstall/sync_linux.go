package localinstall

import (
	"os"

	"golang.org/x/sys/unix"
)

func syncFile(file *os.File) error { return file.Sync() }

func renameExclusive(directory int, source, target string) error {
	return unix.Renameat2(directory, source, directory, target, unix.RENAME_NOREPLACE)
}
