//go:build !darwin

package hostvm

import "syscall"

func NativeIdentity(pid int) (Object, error)                   { return nil, Error("UNSUPPORTED_HOST") }
func GroupEmpty(group int) (bool, error)                       { return false, Error("UNSUPPORTED_HOST") }
func signalOwned(identity Object, signal syscall.Signal) error { return Error("UNSUPPORTED_HOST") }
