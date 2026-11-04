package main

import (
	"fmt"
	"os"

	"filegate.local/filegate/internal/hostvm"
	"filegate.local/filegate/internal/updaterunner"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	if handled, code := hostvm.GateMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	if err := updaterunner.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "UPDATE_RUN_FAILED")
		os.Exit(2)
	}
}
