package main

import "golang.org/x/sys/unix"

func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	var actual unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &actual); err != nil {
		return err
	}
	if actual.Cur != 0 || actual.Max != 0 {
		return unix.EPERM
	}
	return nil
}
