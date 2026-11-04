package main

import (
	"flag"
	"io"
	"os"

	"filegate.local/filegate/internal/fixturebridge"
	"filegate.local/filegate/internal/vmbridge"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	flags := flag.NewFlagSet("filegate-bridge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	fixture := flags.String("fixture", "", "")
	relay := flags.Bool("watchdog-relay", false, "")
	request := flags.String("product-request", "", "")
	digest := flags.String("product-request-sha256", "", "")
	hold := flags.Bool("hold-before-input-for-watchdog-death", false, "")
	if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || !*relay {
		os.Exit(2)
	}
	if *fixture != "product-inspect" {
		if *fixture == "" || *request != "" || *digest != "" || fixturebridge.RunFixture(os.Args[1], *fixture, *hold, os.Stdin, os.Stdout) != nil {
			os.Exit(2)
		}
		return
	}
	if *request == "" || *digest == "" || *hold {
		os.Exit(2)
	}
	if vmbridge.Run(os.Args[1], *request, *digest, os.Stdin, os.Stdout) != nil {
		os.Exit(2)
	}
}
