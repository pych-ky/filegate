package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"

	"filegate.local/filegate/internal/update"
)

func replaceRuntime(data string, args []string) int {
	flags := flag.NewFlagSet("runtime-replace", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidate := flags.String("candidate", "", "")
	expected := flags.String("expected-current-sha256", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *candidate == "" || *expected == "" {
		return failure("INVALID_ARGUMENT")
	}
	result, err := update.ReplaceRuntime(data, *candidate, *expected)
	if err != nil {
		return failure("UPDATE_RUNTIME_REPLACEMENT_FAILED")
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return failure("OUTPUT_FAILED")
	}
	return 0
}
