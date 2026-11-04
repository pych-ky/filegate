package broker

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

func releaseStatIdentity(st unix.Stat_t) releaseIdentity {
	return releaseIdentity{Device: fmt.Sprint(st.Dev), Inode: st.Ino, Birth: fmt.Sprintf("%d:%d", st.Btim.Sec, st.Btim.Nsec)}
}

func releaseFilesystemSupported(fd int) bool {
	var st unix.Statfs_t
	return unix.Fstatfs(fd, &st) == nil && st.Flags&unix.MNT_LOCAL != 0 && unix.ByteSliceToString(st.Fstypename[:]) == "apfs"
}

func releaseBootID() (string, error) {
	boot, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil || strings.TrimSpace(boot) == "" {
		return "", failure("RECOVERY_REQUIRED", 409)
	}
	return boot, nil
}

func releaseRename(staging int, source string, root int, final string) error {
	return unix.RenameatxNp(staging, source, root, final, unix.RENAME_EXCL)
}
