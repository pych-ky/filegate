package main

import (
	"flag"
	"io"
	"os"

	"filegate.local/filegate/internal/updatebridge"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	args := os.Args[1:]
	forward, run := false, ""
	if len(args) > 0 && args[0] == "--forward" {
		forward, args = true, args[1:]
	} else if len(args) > 0 {
		run, args = args[0], args[1:]
	} else {
		os.Exit(2)
	}
	flags := flag.NewFlagSet("filegate-update-bridge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := flags.String("request", "", "")
	digest := flags.String("request-sha256", "", "")
	relay := flags.Bool("watchdog-relay", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *request == "" || *digest == "" || forward == *relay {
		os.Exit(2)
	}
	var err error
	if forward {
		err = updatebridge.Forward(*request, *digest)
	} else {
		err = updatebridge.Run(run, *request, *digest, os.Stdin, os.Stdout)
	}
	if err != nil {
		os.Exit(2)
	}
}
