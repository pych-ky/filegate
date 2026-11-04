package main

import (
	"flag"
	"io"
	"os"
	"runtime"

	"filegate.local/filegate/internal/freshclamadapter"
	"golang.org/x/sys/unix"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(arguments []string) int {
	unix.Umask(0077)
	report := freshclamadapter.Unknown(nil)
	fail := func() int { freshclamadapter.WriteReport(os.Stdout, report); return 1 }
	var core unix.Rlimit
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil || unix.Getrlimit(unix.RLIMIT_CORE, &core) != nil || core.Cur != 0 || core.Max != 0 {
		return fail()
	}
	flags := flag.NewFlagSet("filegate-freshclam", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	library := flags.String("library", "", "")
	database := flags.String("database-dir", "", "")
	temporary := flags.String("temp-dir", "", "")
	fixture := flags.Bool("fixture", false, "")
	verify := flags.Bool("verify-only", false, "")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *library == "" || runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || !*verify && (*database == "" || *temporary == "") {
		return fail()
	}
	if *verify {
		if *fixture || *database != "" || *temporary != "" {
			return fail()
		}
		sum, err := freshclamadapter.VerifyLibrary(*library)
		if err != nil || freshclamadapter.WriteReport(os.Stdout, map[string]any{"fixed_adapter_verified": true, "library_sha256": sum}) != nil {
			return fail()
		}
		return 0
	}
	os.Clearenv()
	for key, value := range map[string]string{"PATH": "/bin:/usr/bin", "LC_ALL": "C", "HOME": *database, "TMPDIR": *temporary, "TMP": *temporary, "TEMP": *temporary} {
		if os.Setenv(key, value) != nil {
			return fail()
		}
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, freshclamadapter.Limit+1))
	if err != nil {
		return fail()
	}
	request, err := freshclamadapter.ParseRequest(body, *fixture)
	if err != nil {
		return fail()
	}
	report = freshclamadapter.Unknown(&request)
	result, err := freshclamadapter.Run(request, freshclamadapter.Options{Library: *library, DatabaseDirectory: *database, TemporaryDirectory: *temporary, Fixture: *fixture})
	if err != nil {
		return fail()
	}
	if freshclamadapter.WriteReport(os.Stdout, result) != nil {
		return 1
	}
	if result["control_complete"] == true {
		return 0
	}
	return 1
}
