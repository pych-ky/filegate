package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
)

func productAVWorker(kind string) {
	if (kind != "txt" && kind != "zip") || noNewPrivileges() != nil {
		os.Exit(2)
	}
	if syscall.Exec("/filegate-av-fixture", []string{"filegate-av-fixture", "--expected-type", kind}, os.Environ()) != nil {
		os.Exit(2)
	}
}

func fixtureAsset(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm() != 0444 || owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 1 {
		return nil, errors.New("fixture asset invalid")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != info.Size() {
		return nil, errors.New("fixture asset changed")
	}
	return body, nil
}

func fixtureInput(body []byte) error {
	const path = "/job/input/object"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("fixture input identity invalid")
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0444)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(body)
	syncErr, closeErr := f.Sync(), f.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func installFixtureProfile() error {
	profile, err := fixtureAsset("/av/product-profile-fixture.json", 65536)
	if err != nil {
		return err
	}
	f, err := os.OpenFile("/av/product-profile.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0444)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(profile)
	if writeErr == nil && n != len(profile) {
		writeErr = io.ErrShortWrite
	}
	syncErr, closeErr := f.Sync(), f.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

// Only the selected harmless fixture boot installs a scanner profile.
func runProductAVFixture(send func(any)) {
	phase, caseID := "PACKAGES", ""
	detail := map[string]any{}
	reject := func() {
		value := map[string]any{"event": "av_error", "reason": "PRODUCT_AV_FIXTURE_FAILED", "phase": phase}
		if caseID != "" {
			value["case_id"] = caseID
		}
		for key, item := range detail {
			value[key] = item
		}
		send(value)
	}
	packages, err := filepath.Glob("/.packages/*.apk")
	if err != nil || len(packages) == 0 {
		reject()
		return
	}
	install := exec.Command("/sbin/apk", append([]string{"add", "--no-network"}, packages...)...)
	install.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/job/adapter-tmp"}
	phase = "PACKAGE_VERIFICATION"
	if install.Run() != nil {
		reject()
		return
	}
	phase = "PROFILE_INSTALL"
	if installFixtureProfile() != nil {
		reject()
		return
	}
	phase = "MANIFEST_ASSET"
	manifestBody, err := fixtureAsset("/av/product-fixtures/manifest.json", 65536)
	if err != nil {
		reject()
		return
	}
	var manifest struct {
		SchemaVersion int `json:"schema_version"`
		Cases         []struct {
			ID                       string `json:"id"`
			Input                    string `json:"input"`
			ExpectedType             string `json:"expected_type"`
			SHA256                   string `json:"sha256"`
			ByteSize                 int64  `json:"byte_size"`
			ExpectedAVResult         string `json:"expected_av_result"`
			ExpectedRequiredCount    int    `json:"expected_required_count"`
			ExpectedDetectedCount    int    `json:"expected_detected_count"`
			ExpectedEmptyDirectories int    `json:"expected_empty_directories"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBody))
	decoder.DisallowUnknownFields()
	phase = "MANIFEST_SCHEMA"
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.SchemaVersion != 1 || len(manifest.Cases) != 4 {
		reject()
		return
	}
	expectedIDs := []string{"clean", "marker", "zero-byte", "zip-mixed"}
	cases := []map[string]any{}
	allPassed := true
	for i, c := range manifest.Cases {
		phase, caseID = "CASE_SELECTION", expectedIDs[i]
		if c.ID != expectedIDs[i] || c.Input != filepath.Base(c.Input) || !regexp.MustCompile(`^[a-z-]+\.(txt|zip)$`).MatchString(c.Input) || (c.ExpectedType != "txt" && c.ExpectedType != "zip") {
			reject()
			return
		}
		phase = "CASE_ASSET"
		body, err := fixtureAsset("/av/product-fixtures/"+c.Input, 1<<20)
		digest := sha256.Sum256(body)
		if err != nil || hex.EncodeToString(digest[:]) != c.SHA256 || int64(len(body)) != c.ByteSize {
			reject()
			return
		}
		phase = "CASE_INPUT"
		if fixtureInput(body) != nil {
			reject()
			return
		}
		command := restrictedWorker("--product-av-worker", c.ExpectedType)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=/job/adapter-tmp", "TMP=/job/adapter-tmp", "TEMP=/job/adapter-tmp"}
		diagnostics := &diagnosticDigest{hash: sha256.New()}
		command.Stderr = diagnostics
		phase = "WORKER_PIPE"
		pipe, err := command.StdoutPipe()
		if err != nil {
			reject()
			return
		}
		phase = "WORKER_START"
		if command.Start() != nil {
			reject()
			return
		}
		output, readErr := io.ReadAll(io.LimitReader(pipe, 1<<20+1))
		if readErr != nil || len(output) > 1<<20 {
			command.Process.Kill()
		}
		waitErr := command.Wait()
		exitCode := -1
		if command.ProcessState != nil {
			exitCode = command.ProcessState.ExitCode()
		}
		detail = map[string]any{"stdout_bytes": len(output), "stderr_bytes": diagnostics.count, "stderr_sha256": hex.EncodeToString(diagnostics.hash.Sum(nil)), "worker_exit_code": exitCode}
		var result map[string]any
		phase = "WORKER_OUTPUT"
		if readErr != nil || len(output) > 1<<20 {
			reject()
			return
		}
		phase = "WORKER_EXIT"
		if waitErr != nil {
			reject()
			return
		}
		phase = "WORKER_STDERR"
		if diagnostics.count != 0 {
			reject()
			return
		}
		phase = "WORKER_JSON"
		if json.Unmarshal(output, &result) != nil {
			reject()
			return
		}
		format, formatOK := result["result"].(map[string]any)
		av, avOK := result["av"].(map[string]any)
		binding, bindingOK := av["binding"].(map[string]any)
		detections, detectionsOK := av["confirmed_detections"].([]any)
		objects, objectsOK := av["objects"].([]any)
		manifestObjects, manifestOK := format["manifest"].([]any)
		emptyDirectories := 0
		for _, object := range manifestObjects {
			if row, ok := object.(map[string]any); ok && row["kind"] == "verified_empty_directory" && row["av_required"] == false && row["av_exclusion_reason"] == "VERIFIED_EMPTY_DIRECTORY" {
				emptyDirectories++
			}
		}
		passed := formatOK && avOK && bindingOK && detectionsOK && objectsOK && manifestOK && result["schema_version"] == float64(1) && format["structure_status"] == "ACCEPT_FORMAT_STRUCTURE" && format["required_checks_complete"] == false && binding["fixture_definitions_only"] == true && av["binding_verified"] == true && av["results_complete"] == true && av["process_status"] == "completed" && av["av_result"] == c.ExpectedAVResult && av["required_input_count"] == float64(c.ExpectedRequiredCount) && av["normal_result_count"] == float64(c.ExpectedRequiredCount) && len(objects) == c.ExpectedRequiredCount && len(detections) == c.ExpectedDetectedCount && emptyDirectories == c.ExpectedEmptyDirectories
		allPassed = allPassed && passed
		cases = append(cases, map[string]any{"expected": c, "actual": result, "passed": passed})
		detail = map[string]any{}
		phase = "EXTRACT_LIST"
		entries, err := os.ReadDir("/job/extract")
		if err != nil {
			reject()
			return
		}
		for _, entry := range entries {
			phase = "EXTRACT_CLEANUP"
			if !entry.Type().IsRegular() || !regexp.MustCompile(`^object_[0-9]{6}\.data$`).MatchString(entry.Name()) || os.Remove("/job/extract/"+entry.Name()) != nil {
				reject()
				return
			}
		}
	}
	manifestDigest := sha256.Sum256(manifestBody)
	send(map[string]any{"event": "product_av_result", "runner_success": allPassed, "verdict": "NOT_A_PRODUCT_SCAN", "fixture_definitions_only": true,
		"manifest_sha256": hex.EncodeToString(manifestDigest[:]), "cases": cases})
}
