//go:build darwin

package verification

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// releaseUnknownStat returns the identity the broker records for a release temp plus the fields a move must keep.
func releaseUnknownStat(path string) (Object, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return nil, err
	}
	return Object{"device": fmt.Sprint(st.Dev), "inode": st.Ino, "birth": fmt.Sprintf("%d:%d", st.Btim.Sec, st.Btim.Nsec), "uid": st.Uid, "nlink": uint64(st.Nlink), "mode": uint32(st.Mode), "regular": st.Mode&unix.S_IFMT == unix.S_IFREG, "size": st.Size}, nil
}

// releaseUnknownMove renames one file exclusively between two directories, then synchronizes both parents.
func releaseUnknownMove(fromDir, from, toDir, to string) error {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	source, err := unix.Open(fromDir, flags, 0)
	if err != nil {
		return err
	}
	defer unix.Close(source)
	target, err := unix.Open(toDir, flags, 0)
	if err != nil {
		return err
	}
	defer unix.Close(target)
	if err = unix.RenameatxNp(source, from, target, to, unix.RENAME_EXCL); err != nil {
		return err
	}
	if err = unix.Fsync(source); err != nil {
		return err
	}
	return unix.Fsync(target)
}
