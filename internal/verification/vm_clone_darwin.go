//go:build darwin

package verification

import "golang.org/x/sys/unix"

func vmCloneFile(source, target string) error { return unix.Clonefile(source, target, 0) }
