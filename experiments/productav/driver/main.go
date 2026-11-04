package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"filegate.local/filegate/internal/av"
	"filegate.local/filegate/internal/inspect"
)

func environment() bool {
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || os.Geteuid() != 65534 || os.Getegid() != 65534 {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		return false
	}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 16385))
	return err == nil && len(body) <= 16384 && strings.Contains(string(body), "NoNewPrivs:\t1\n") && strings.Contains(string(body), "CapEff:\t0000000000000000\n")
}

func main() {
	if !environment() {
		os.Exit(2)
	}
	expected := flag.String("expected-type", "", "fixed fixture type")
	flag.Parse()
	if flag.NArg() != 0 || (*expected != "txt" && *expected != "zip") {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	format := inspect.Inspect(ctx, "/job/input/object", inspect.Metadata{ExpectedType: *expected}, "/job/extract")
	result := av.Run(ctx, format)
	if result.Binding == nil || !result.Binding.FixtureDefinitionsOnly {
		os.Exit(2)
	}
	if json.NewEncoder(os.Stdout).Encode(struct {
		SchemaVersion int            `json:"schema_version"`
		Result        inspect.Result `json:"result"`
		AV            av.Result      `json:"av"`
	}{1, format, result}) != nil {
		os.Exit(2)
	}
}
