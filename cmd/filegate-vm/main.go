package main

import (
	"fmt"
	"os"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	if handled, code := hostvm.GateMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	code, err := hostvm.RunScan(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "PRODUCT_RUN_FAILED")
		code = 2
	}
	os.Exit(code)
}
