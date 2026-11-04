package main

import (
	"os"

	"filegate.local/filegate/internal/updateworker"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	var core unix.Rlimit
	if len(os.Args) != 1 || unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil || unix.Getrlimit(unix.RLIMIT_CORE, &core) != nil || core.Cur != 0 || core.Max != 0 {
		os.Exit(2)
	}
	if updateworker.Run(os.Stdin, os.Stdout) != nil {
		os.Exit(2)
	}
}
