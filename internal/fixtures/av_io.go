package fixtures

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func avCheckIO(input, temp string) map[string]any {
	checks := map[string]any{}
	complete := true
	for _, id := range []string{"input_read", "temp_create_write_sync"} {
		err := func() error {
			if id == "input_read" {
				fd, err := unix.Open(input, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				f := os.NewFile(uintptr(fd), input)
				defer f.Close()
				_, err = io.Copy(io.Discard, f)
				return err
			}
			directory, err := os.MkdirTemp(temp, "filegate-io-")
			if err != nil {
				return err
			}
			defer os.Remove(directory)
			path := filepath.Join(directory, "probe")
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			defer os.Remove(path)
			defer f.Close()
			if _, err = f.Write([]byte("FileGate mandatory IO probe\n")); err != nil {
				return err
			}
			return f.Sync()
		}()
		row := map[string]any{"complete": err == nil, "errno": 0}
		if err != nil {
			complete = false
			var number unix.Errno
			if errors.As(err, &number) {
				row["errno"] = int(number)
				name := "UNKNOWN"
				switch number {
				case unix.EACCES:
					name = "EACCES"
				case unix.EPERM:
					name = "EPERM"
				case unix.ENOSPC:
					name = "ENOSPC"
				case unix.EIO:
					name = "EIO"
				}
				row["error_name"] = name
			} else {
				row["error_name"] = "UNKNOWN"
			}
		}
		checks[id] = row
	}
	return map[string]any{"checks": checks, "required_checks_complete": complete}
}
func runAVIO(root, binary string) ([]map[string]any, error) {
	deniedTemp := filepath.Join(root, "denied-temp")
	if err := os.Mkdir(deniedTemp, 0500); err != nil {
		return nil, err
	}
	defer os.Chmod(deniedTemp, 0700)
	unreadable := filepath.Join(root, "inputs/unreadable.txt")
	body, err := os.ReadFile(filepath.Join(root, "inputs/clean.txt"))
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(unreadable, body, 0600); err != nil {
		return nil, err
	}
	if err = os.Chmod(unreadable, 0); err != nil {
		return nil, err
	}
	defer os.Chmod(unreadable, 0600)
	rows := []map[string]any{}
	for _, test := range []struct{ id, name, temp, failed string }{{"read-denied", "unreadable.txt", filepath.Join(root, "avtmp"), "input_read"}, {"temp-create-denied", "clean.txt", deniedTemp, "temp_create_write_sync"}} {
		args, err := avArguments(binary, root, test.temp, avCase{database: "marker.ndb", input: test.name})
		if err != nil {
			return nil, err
		}
		required := avCheckIO(filepath.Join(root, "inputs", test.name), test.temp)
		actual := observeAV(args, root, nil, "", 64<<20)
		complete := required["required_checks_complete"] == true
		reasons := []string{}
		if !complete {
			reasons = append(reasons, "INCOMPLETE_REQUIRED_CHECKS")
		}
		if !actual.Valid || actual.ExitCode != 0 || actual.Denied > 0 || actual.Warnings > 0 || actual.Errors > 0 || actual.Diagnostics["temp-create-denied"] > 0 {
			reasons = append(reasons, "SCANNER_ERROR")
		}
		status := "failed"
		if actual.Valid && actual.ExitCode == 0 {
			status = "completed"
		}
		result, verdict := "no_detection_reported", "UNDECIDED"
		if len(reasons) > 0 {
			result = "inconclusive"
			verdict = "HOLD"
		}
		normalized := map[string]any{"required_checks_complete": complete, "av_process_status": status, "av_result": result, "acceptance_blocked": len(reasons) > 0, "reason_codes": reasons, "verdict_without_confirmed_rejection": verdict}
		witness := actual.Denied == 1
		if test.id == "temp-create-denied" {
			witness = actual.Diagnostics[test.id] > 0
		}
		failed := required["checks"].(map[string]any)[test.failed].(map[string]any)
		permission := failed["error_name"] == "EACCES" || failed["error_name"] == "EPERM"
		rows = append(rows, map[string]any{"id": test.id, "original_engine_expectation": map[string]any{"exit_code": 2, "normal_ok_count": 0}, "original_engine_expectation_met": actual.ExitCode == 2 && actual.Normal == 0, "arguments": args[1:], "actual": actual, "mandatory_io": required, "normalized": normalized, "unreadable_input_sha256": digest(body), "engine_launched_despite_preflight_failure_for_observation_only": true, "expectation_met": actual.Valid && witness && permission && !complete && len(reasons) > 0 && verdict == "HOLD", "filegate_required_response": "HOLD; preserve independently confirmed BLOCK"})
	}
	return rows, nil
}
