package hostvm

import (
	"runtime"
	"strconv"
)

func itoa(n int) string { return strconv.Itoa(n) }
func hostMachine() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return runtime.GOARCH
}
