package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"filegate.local/filegate/internal/av"
	"filegate.local/filegate/internal/inspect"
	"golang.org/x/sys/unix"
)

func environment() bool {
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getgid() == 0 {
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
	status, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(status) > 16384 {
		return false
	}
	return strings.Contains(string(status), "NoNewPrivs:\t1\n") && strings.Contains(string(status), "CapEff:\t0000000000000000\n")
}

func main() {
	if !environment() {
		fmt.Fprintln(os.Stderr, "WORKER_ENVIRONMENT_INVALID")
		os.Exit(2)
	}
	mode := flag.String("mode", "inspect", "scan, inspect, zip-contract, or txt-contract")
	input := flag.String("input", "/job/input/object", "guest input path")
	work := flag.String("work", "/job/extract", "guest extraction directory")
	metadata := flag.String("metadata", "{}", "format metadata JSON")
	metadataFile := flag.String("metadata-file", "", "fixed guest metadata file")
	flag.Parse()
	if flag.NArg() != 0 || len(*metadata) > 16384 {
		os.Exit(2)
	}
	var meta inspect.Metadata
	metadataBody := []byte(*metadata)
	if *metadataFile != "" {
		if *metadataFile != "/job/input/metadata.json" || *metadata != "{}" {
			os.Exit(2)
		}
		f, err := os.Open(*metadataFile)
		if err != nil {
			os.Exit(2)
		}
		metadataBody, err = io.ReadAll(io.LimitReader(f, 16385))
		closeErr := f.Close()
		if err != nil || closeErr != nil || len(metadataBody) > 16384 {
			os.Exit(2)
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(metadataBody)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&meta) != nil || decoder.Decode(new(any)) != io.EOF {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	var progress *os.File
	if *mode == "scan" {
		if _, err := unix.FcntlInt(3, unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			os.Exit(2)
		}
		progress = os.NewFile(3, "scan-progress")
		defer progress.Close()
	}
	emit := func(sequence int, stage string, result *inspect.Result, normal int) {
		if progress == nil {
			return
		}
		var target, completed, inputs, results *int
		if result != nil {
			count := len(result.Manifest)
			target, completed, inputs, results = &count, &count, &result.RequiredAVInputCount, &normal
		}
		value := map[string]any{"schema_version": 1, "sequence": sequence, "stage": stage, "manifest_complete": result != nil, "format_target_count": target, "format_completed_count": completed, "av_input_count": inputs, "av_normal_result_count": results}
		if json.NewEncoder(progress).Encode(value) != nil {
			os.Exit(2)
		}
	}
	var result inspect.Result
	switch *mode {
	case "scan", "inspect":
		if *mode == "scan" && (*input != "/job/input/object" || *work != "/job/extract" || *metadataFile != "/job/input/metadata.json") {
			os.Exit(2)
		}
		emit(1, "format", nil, 0)
		result = inspect.Inspect(ctx, *input, meta, *work)
	case "zip-contract", "txt-contract":
		f, err := os.Open(*input)
		if err != nil {
			os.Exit(2)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			os.Exit(2)
		}
		if *mode == "zip-contract" {
			result = inspect.ValidateZIP(ctx, f, st.Size(), *work)
		} else {
			result = inspect.ValidateTXT(ctx, f, st.Size(), meta)
		}
	default:
		os.Exit(2)
	}
	var output any = result
	if *mode == "scan" {
		complete := result.StructureStatus == "ACCEPT_FORMAT_STRUCTURE" && result.StructureChecksComplete && result.FormatChecksComplete
		if complete {
			emit(2, "av", &result, 0)
		}
		avResult := av.Run(ctx, result)
		if complete {
			emit(3, "finalizing", &result, avResult.NormalResultCount)
		}
		output = struct {
			SchemaVersion int            `json:"schema_version"`
			Result        inspect.Result `json:"result"`
			AV            av.Result      `json:"av"`
		}{1, result, avResult}
	}
	if json.NewEncoder(os.Stdout).Encode(output) != nil {
		os.Exit(2)
	}
}
