package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// A separate descriptor keeps names and URLs out of argv without consuming upload bytes.
func metadataArguments(ctx context.Context, args []string) ([]string, bool, error) {
	found := false
	for _, value := range args {
		if value == "--" {
			break
		}
		if value == "--metadata-fd" || strings.HasPrefix(value, "--metadata-fd=") {
			found = true
		}
	}
	if !found {
		return args, false, nil
	}
	invalid := errors.New("INVALID_ARGUMENT")
	if len(args) != 4 || args[0] != "submit" || args[2] != "--metadata-fd" ||
		(args[1] != "file" && args[1] != "url" && args[1] != "upload") {
		return nil, false, invalid
	}
	fd, err := strconv.Atoi(args[3])
	if err != nil || fd < 0 || fd > 1024 || fd == 1 || fd == 2 || (fd == 0 && args[1] == "upload") {
		return nil, false, invalid
	}
	input := os.NewFile(uintptr(fd), "metadata")
	if input == nil {
		return nil, false, invalid
	}
	defer input.Close()
	type result struct {
		body []byte
		err  error
	}
	received := make(chan result, 1)
	go func() {
		body, err := io.ReadAll(io.LimitReader(input, (16<<10)+1))
		received <- result{body, err}
	}()
	var value result
	select {
	case <-ctx.Done():
		return nil, false, errors.New("INPUT_INTERRUPTED")
	case value = <-received:
	}
	var metadata struct {
		Source       string  `json:"source"`
		Key          string  `json:"idempotency_key"`
		ExpectedType *string `json:"expected_type,omitempty"`
		ExpectedHash *string `json:"expected_sha256,omitempty"`
	}
	if value.err != nil || len(value.body) > 16<<10 || strictDecode(value.body, &metadata) != nil || metadata.Source == "" || metadata.Key == "" {
		return nil, false, invalid
	}
	resultArgs := []string{"submit", "--idempotency-key", metadata.Key}
	if metadata.ExpectedType != nil {
		resultArgs = append(resultArgs, "--expected-type", *metadata.ExpectedType)
	}
	if metadata.ExpectedHash != nil {
		resultArgs = append(resultArgs, "--expected-sha256", *metadata.ExpectedHash)
	}
	return append(resultArgs, "--", args[1], metadata.Source), true, nil
}
