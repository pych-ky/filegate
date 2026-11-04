package update

import (
	"golang.org/x/sys/unix"
	"os"
)

func runtimeSyncFile(file *os.File) error { return file.Sync() }

func runtimeRename(source, target string) error {
	return unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
}
