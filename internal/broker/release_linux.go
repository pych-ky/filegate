package broker

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func releaseStatIdentity(st unix.Stat_t) releaseIdentity {
	return releaseIdentity{Device: fmt.Sprint(st.Dev), Inode: st.Ino, Birth: "unsupported"}
}

func releaseFilesystemSupported(fd int) bool { return false }
func releaseBootID() (string, error)         { return "", failure("DESTINATION_UNSUPPORTED", 409) }
func releaseRename(staging int, source string, root int, final string) error {
	return failure("DESTINATION_UNSUPPORTED", 409)
}
