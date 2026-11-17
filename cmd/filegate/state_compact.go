package main

import (
	"encoding/json"
	"errors"
	"os"

	"filegate.local/filegate/internal/update"
)

func compactState(data string, args []string) int {
	if len(args) != 0 {
		return failure("INVALID_ARGUMENT")
	}
	result, err := update.CompactState(data)
	if err != nil {
		var code update.Error
		if errors.As(err, &code) {
			return failure(string(code))
		}
		return failure("STATE_COMPACTION_FAILED")
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return failure("OUTPUT_FAILED")
	}
	return 0
}
