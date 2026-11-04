package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"

	"filegate.local/filegate/internal/localinstall"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Umask(0077)
	var limit unix.Rlimit
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil || unix.Getrlimit(unix.RLIMIT_CORE, &limit) != nil || limit.Cur != 0 || limit.Max != 0 {
		os.Exit(fail("CORE_DUMP_POLICY_FAILED"))
	}
	os.Exit(run(os.Args[1:]))
}

func fail(code string) int {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "installed": false, "error": code})
	return 1
}

func run(args []string) int {
	flags := flag.NewFlagSet("filegate-install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "")
	expected := flags.String("sha256", "", "")
	prefix := flags.String("prefix", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *source == "" || *prefix == "" || *expected == "" {
		return fail("INVALID_ARGUMENT")
	}
	result, err := localinstall.Install(*source, *prefix, *expected)
	if err != nil {
		return fail(localinstall.ErrorCode(err))
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 1
	}
	return 0
}
