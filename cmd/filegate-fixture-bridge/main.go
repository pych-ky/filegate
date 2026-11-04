package main

import (
	"flag"
	"io"
	"os"

	"filegate.local/filegate/internal/fixturebridge"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	flags := flag.NewFlagSet("filegate-fixture-bridge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	run := flags.String("run", "", "")
	digest := flags.String("update-bridge-sha256", "", "")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || *run == "" || *digest == "" || fixturebridge.Run(*run, *digest, os.Stdin, os.Stdout) != nil {
		os.Exit(2)
	}
}
