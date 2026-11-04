package hostvm

import (
	"context"
	"os/exec"
	"syscall"
)

func execCommandContext(ctx context.Context, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, args[0], args[1:]...)
}
func exitStatus(err error) int {
	if e, ok := err.(*exec.ExitError); ok {
		if s, ok := e.Sys().(syscall.WaitStatus); ok && s.Signaled() {
			return -int(s.Signal())
		}
		return e.ExitCode()
	}
	return 1
}
