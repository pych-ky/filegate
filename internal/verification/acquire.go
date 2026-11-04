package verification

import (
	"path/filepath"
	"time"
)

func init() { Register("acquire", runAcquire) }
func runAcquire(h *Harness) {
	selection := "all"
	if len(h.Cases) > 0 {
		selection = h.Cases[0]
	}
	pattern := map[string]string{"all": "^Test(Acquisition|TotalDeadline|IdleBodyDeadline)E2E$", "total-deadline": "^TestTotalDeadlineE2E$", "idle-deadline": "^TestIdleBodyDeadlineE2E$"}[selection]
	h.Check("known_acquisition_case", pattern != "")
	fixtures := filepath.Join(h.Out, "fixtures")
	if selection == "all" {
		command := []string{"go", "run", "-trimpath", "-buildvcs=false", ".", "--out", fixtures}
		result := Execute(filepath.Join(h.Root, "experiments/http"), command, nil, 4*time.Minute)
		Write(filepath.Join(h.Out, "fixture.log"), append(result.Stdout, result.Stderr...))
		h.Check("http_fixture", result.ExitCode == 0)
		h.Record["fixture_manifest_sha256"] = FileDigest(filepath.Join(fixtures, "results.json"))
	}
	overlay := filepath.Join(h.Out, "acquire-overlay.json")
	WriteJSON(overlay, Object{"Replace": Object{filepath.Join(h.Root, "internal/acquire/acquire_e2e_test.go"): filepath.Join(h.Root, "experiments/product/acquire_e2e_test.go")}})
	resultOut := filepath.Join(h.Out, "acquisition")
	command := []string{"go", "test", "-overlay", overlay, "-tags=filegate_e2e", "-count=1", "-timeout=4m", "./internal/acquire", "-run", pattern, "-args", "-fixture-root", fixtures, "-acquisition-out", resultOut}
	result := Execute(h.Root, command, nil, 5*time.Minute)
	Write(filepath.Join(h.Out, "acquisition.log"), append(result.Stdout, result.Stderr...))
	h.Record["command"] = command
	h.Record["exit_code"] = result.ExitCode
	if Exists(filepath.Join(resultOut, "results.json")) {
		record := ReadJSON(filepath.Join(resultOut, "results.json"))
		h.Record["acquisition"] = record
		h.Check("acquisition_report", Bool(record, "passed"))
	} else {
		h.Check("acquisition_report_exists", false)
	}
	h.Check("go_acquisition_e2e", result.ExitCode == 0)
}
