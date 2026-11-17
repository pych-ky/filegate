package verification

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func external(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
func sources(root string) map[string]string {
	files := map[string]string{}
	for _, name := range []string{"go.mod", "go.sum"} {
		files[name] = FileDigest(filepath.Join(root, name))
	}
	for _, directory := range []string{"cmd", "internal", "experiments"} {
		Must(filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if strings.HasPrefix(entry.Name(), ".") || entry.Name() == "secrets" || entry.Name() == "credentials" {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".go" && ext != ".html" && ext != ".js" && ext != ".css" {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files[relative] = FileDigest(path)
			return nil
		}))
	}
	return files
}
func parse(args []string) (Options, error) {
	var options Options
	options.Paths = map[string]string{}
	flags := flag.NewFlagSet("filegate-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		options.Suite, args = args[0], args[1:]
	}
	flags.StringVar(&options.Suite, "suite", options.Suite, "")
	flags.StringVar(&options.Root, "root", "", "")
	flags.StringVar(&options.Out, "out", "", "")
	flags.StringVar(&options.Binary, "binary", "", "")
	flags.StringVar(&options.Driver, "driver", "", "")
	flags.StringVar(&options.Proof, "proof", "", "")
	flags.StringVar(&options.Runner, "runner", "", "")
	flags.StringVar(&options.Workspace, "workspace", "", "")
	flags.StringVar(&options.DefinitionManifest, "definition-manifest", "", "")
	flags.StringVar(&options.BinaryProof, "binary-proof", "", "")
	flags.StringVar(&options.Inputs, "inputs", "", "")
	flags.StringVar(&options.Mode, "mode", "", "")
	flags.BoolVar(&options.PrepareOnly, "prepare-only", false, "")
	flags.BoolVar(&options.IntakeOnly, "intake-only", false, "")
	var cases string
	flags.StringVar(&cases, "cases", "", "")
	flags.StringVar(&cases, "case", "", "")
	pathFlags := map[string]*string{}
	for _, name := range []string{"vm-runner", "vm-workspace", "vm-proof", "fixture-proof", "supplement-from", "observation", "baseline", "candidate", "source", "prefix", "registration-candidate", "scan-workspace", "scan-proof", "state-directory", "library-sha256"} {
		pathFlags[name] = flags.String(name, "", "")
	}
	normalized := []string{}
	for index := 0; index < len(args); index++ {
		if args[index] == "--cases" {
			values := []string{}
			for index+1 < len(args) && !strings.HasPrefix(args[index+1], "--") {
				index++
				values = append(values, args[index])
			}
			normalized = append(normalized, "--cases", strings.Join(values, ","))
		} else {
			normalized = append(normalized, args[index])
		}
	}
	if flags.Parse(normalized) != nil || flags.NArg() != 0 {
		return options, errors.New("VERIFICATION_ARGUMENTS_INVALID")
	}
	for name, value := range pathFlags {
		options.Paths[name] = *value
	}
	if cases != "" {
		options.Cases = strings.FieldsFunc(cases, func(r rune) bool { return r == ',' || r == ' ' })
	}
	if options.Suite == "basic" && options.Mode == "intake-capacity" {
		options.Suite = "intake-capacity"
	}
	if options.Root == "" {
		var err error
		options.Root, err = os.Getwd()
		if err != nil {
			return options, err
		}
	}
	var err error
	options.Root, err = filepath.EvalSymlinks(options.Root)
	if err != nil {
		return options, err
	}
	options.Root, err = filepath.Abs(options.Root)
	if err != nil {
		return options, err
	}
	if options.Suite == "" || suites[options.Suite] == nil || options.Out == "" {
		return options, errors.New("VERIFICATION_SUITE_OR_OUTPUT_REQUIRED")
	}
	options.Out, err = filepath.Abs(options.Out)
	if err != nil {
		return options, err
	}
	if Exists(options.Out) || external(options.Root, options.Out) {
		return options, errors.New("VERIFICATION_REQUIRES_NEW_EXTERNAL_OUTPUT")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(options.Out))
	if err != nil {
		if err = os.MkdirAll(filepath.Dir(options.Out), 0700); err != nil {
			return options, err
		}
		parent, err = filepath.EvalSymlinks(filepath.Dir(options.Out))
	}
	if err != nil {
		return options, err
	}
	options.Out = filepath.Join(parent, filepath.Base(options.Out))
	if external(options.Root, options.Out) {
		return options, errors.New("VERIFICATION_REQUIRES_NEW_EXTERNAL_OUTPUT")
	}
	if options.Binary != "" {
		options.Binary, err = filepath.Abs(options.Binary)
		if err != nil {
			return options, err
		}
		if external(options.Root, options.Binary) {
			return options, errors.New("VERIFICATION_BINARY_MUST_BE_EXTERNAL")
		}
		if Exists(options.Binary) {
			actual, resolveErr := filepath.EvalSymlinks(options.Binary)
			if resolveErr != nil || external(options.Root, actual) {
				return options, errors.New("VERIFICATION_BINARY_MUST_BE_EXTERNAL")
			}
			options.Binary = actual
		}
	}
	return options, nil
}
func Run(args []string) (code int) {
	options, err := parse(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	if err = os.Mkdir(options.Out, 0700); err != nil {
		fmt.Fprintln(os.Stderr, "VERIFICATION_OUTPUT_CREATE_FAILED")
		return 2
	}
	h := &Harness{Options: options, Record: Object{"schema": 1, "suite": options.Suite, "passed": false, "stage0_passed": false, "stage3_completed": false, "customer_operation_enabled": false}}
	defer func() {
		if failure := recover(); failure != nil {
			h.Record["failure"] = failureRecord(failure)
		}
		func() {
			defer func() {
				if failure := recover(); failure != nil {
					h.Record["cleanup_failure"] = failureRecord(failure)
				}
			}()
			h.Stop(false)
			for _, c := range h.Connections {
				_ = c.Close()
			}
		}()
		if before, ok := h.Record["source_sha256"]; ok {
			after := sources(options.Root)
			h.Record["source_sha256_after"] = after
			h.Record["source_unchanged"] = Equal(before, after)
		}
		h.Record["checks"] = h.Checks
		h.Record["cli_commands"] = h.Commands
		h.Record["all_service_processes_stopped"] = h.Process == nil
		outputBytes := 0
		for _, body := range h.Logs {
			outputBytes += len(body)
		}
		h.Record["raw_service_output_bytes"] = outputBytes
		passed := h.Record["failure"] == nil && h.Record["cleanup_failure"] == nil && h.Record["source_unchanged"] == true && h.Process == nil && len(h.Checks) > 0
		for _, check := range h.Checks {
			passed = passed && check["passed"] == true
		}
		h.Record["passed"] = passed
		if h.Temporary != "" {
			if passed && h.Record["retain_state"] != true {
				_ = os.RemoveAll(h.Temporary)
			} else if passed {
				h.Record["retained_state_directory"] = h.Temporary
			} else {
				h.Record["state_retained_for_recovery"] = h.Temporary
			}
		}
		WriteJSON(filepath.Join(options.Out, "results.json"), h.Record)
		summary := Object{"passed": passed, "checks": len(h.Checks), "artifact": filepath.Join(options.Out, "results.json"), "failure": h.Record["failure"]}
		fmt.Println(string(Encoded(summary)))
		if passed {
			code = 0
		} else {
			code = 1
		}
	}()
	before := sources(options.Root)
	h.Record["source_sha256"] = before
	names := make([]string, 0, len(before))
	for name := range before {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		Write(filepath.Join(options.Out, "sources", name), Read(filepath.Join(options.Root, name)))
		h.Check("source_snapshot_"+name, FileDigest(filepath.Join(options.Out, "sources", name)) == before[name])
	}
	h.Checks = nil
	overlaySuite := options.Suite == "pressure" || options.Suite == "intake-capacity" || options.Suite == "intake-recovery"
	if h.Binary == "" && options.Suite != "update-control" && options.Suite != "update-fixture" && options.Suite != "update-network-state" && options.Suite != "acquire" && options.Suite != "release-boundary" && options.Suite != "release-replay" && options.Suite != "release-prepublish" && options.Suite != "release-unknown" && options.Suite != "release-unknown-abort" && !overlaySuite {
		h.Binary = filepath.Join(options.Out, "filegate")
		command := []string{"go", "build", "-trimpath", "-buildvcs=false", "-o", h.Binary, "./cmd/filegate"}
		built := Execute(options.Root, command, nil, 3*time.Minute)
		h.Record["build"] = Object{"argv": command, "exit_code": built.ExitCode}
		Write(filepath.Join(options.Out, "build.log"), append(built.Stdout, built.Stderr...))
		h.Check("build", built.ExitCode == 0)
	}
	if h.Binary != "" && !overlaySuite {
		h.Record["binary_sha256"] = FileDigest(h.Binary)
	}
	h.Temporary, err = os.MkdirTemp("/private/tmp", "fg-verify-")
	Must(err)
	Must(os.Chmod(h.Temporary, 0700))
	h.Data = filepath.Join(h.Temporary, "data")
	h.InputDirectory = filepath.Join(h.Temporary, "inputs")
	h.Socket = filepath.Join(h.Data, "filegate.sock")
	Must(os.Mkdir(h.InputDirectory, 0700))
	suites[options.Suite](h)
	return 0
}
func failureRecord(failure any) Object {
	switch value := failure.(type) {
	case Failure:
		return Object{"type": "AssertionError", "check": value.Name}
	case error:
		return Object{"type": "execution_error", "check": "execution_failed", "message": value.Error()}
	default:
		return Object{"type": "panic", "check": "execution_failed"}
	}
}

func VerifyMain(args []string) int {
	unix.Umask(0077)
	if len(args) == 1 && args[0] == "--list" {
		names := make([]string, 0, len(suites))
		for name := range suites {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Println(string(Encoded(Object{"schema": 1, "suites": names, "python_dependency": false})))
		return 0
	}
	return Run(args)
}
