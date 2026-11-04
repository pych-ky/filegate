package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"filegate.local/filegate/internal/hostvm"
	"filegate.local/filegate/internal/nativeproof"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	if handled, code := hostvm.GateMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	code, err := nativeproof.Run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}
