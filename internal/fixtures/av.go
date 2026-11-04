package fixtures

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"filegate.local/filegate/internal/av"
)

type avCase struct {
	id, database, input, expected, trigger string
	overrides                              map[string]string
}
type avObservation struct {
	ExitCode       int              `json:"exit_code"`
	Valid          bool             `json:"observation_valid"`
	Normal         int              `json:"normal_ok_count"`
	Empty          int              `json:"empty_file_count"`
	Denied         int              `json:"access_denied_count"`
	Warnings       int              `json:"warning_count"`
	Errors         int              `json:"error_count"`
	ErrorReported  bool             `json:"error_reported"`
	Marker         bool             `json:"marker_detection"`
	Limits         []string         `json:"limit_notifications"`
	Diagnostics    map[string]int   `json:"diagnostics"`
	Bytes          int64            `json:"output_bytes"`
	SHA            string           `json:"output_sha256"`
	Reason         string           `json:"reason,omitempty"`
	ObserverErrors []map[string]any `json:"xml_observer_errors,omitempty"`
}

var avDiagnostics = map[string]string{
	"pcre-size": "pcre max filesize", "pcre-match": "pcre_exec: match limit exceeded", "pcre-depth": "pcre_exec: recursive limit exceeded",
	"html-normalize": "file larger than MaxHTMLNormalize", "html-notags": "normalized size over MaxHTMLNoTags", "script-normalize": "file larger than MaxScriptSize",
	"zip-type": "zip file > MaxZipTypeRcg", "embedded-pe": "MaxEmbeddedPE exceeded", "partitions": "maximum partitions reached", "pdf-objects": "pdf_findobj: reached object maximum",
	"pdf-depth": "pdf_parse_dict: Recursion limit reached", "bytecode-warning": "Bytecode 'FileGate.Harmless.BytecodeLoop", "bytecode-timeout": "Bytecode run timed out in interpreter after",
	"image-allocation": "Memory limit exceeded", "temp-create-denied": "Can't create temporary directory for scan:",
}
var avLimitNotification = regexp.MustCompile(`Heuristics\.Limits\.Exceeded\.[A-Za-z0-9_]+`)
var avXMLObserver = regexp.MustCompile(`^FILEGATE_XML_OBSERVER failure=([a-z-]+) code=([0-9]{1,4}) domain=([0-9]{1,4})$`)

type avCapture struct {
	mu      sync.Mutex
	result  avObservation
	hash    hash.Hash
	pending []byte
	maximum int64
	failed  bool
	cancel  context.CancelFunc
	needles map[string]string
}

func (c *avCapture) line(body []byte) {
	text := string(bytes.TrimRight(body, "\r\n"))
	r := &c.result
	if strings.HasSuffix(text, ": OK") {
		r.Normal++
	}
	if strings.HasSuffix(text, ": Empty file") {
		r.Empty++
	}
	if strings.HasSuffix(text, ": Access denied") {
		r.Denied++
	}
	if strings.Contains(text, "Warning:") || strings.Contains(text, "WARNING:") {
		r.Warnings++
	}
	if strings.Contains(text, "LibClamAV Error:") || strings.HasPrefix(text, "ERROR:") || strings.HasSuffix(text, " ERROR") {
		r.Errors++
	}
	if strings.Contains(text, " ERROR") || strings.Contains(text, "ERROR:") {
		r.ErrorReported = true
	}
	if strings.HasSuffix(text, " FOUND") {
		if strings.Contains(text, "FileGate.Harmless.Marker") {
			r.Marker = true
		}
		for _, name := range avLimitNotification.FindAllString(text, -1) {
			known := false
			for _, old := range r.Limits {
				known = known || old == name
			}
			if !known {
				r.Limits = append(r.Limits, name)
			}
		}
	}
	for name, needle := range c.needles {
		if strings.Contains(text, needle) {
			r.Diagnostics[name]++
		}
	}
	if m := avXMLObserver.FindStringSubmatch(text); m != nil {
		known := false
		for _, item := range r.ObserverErrors {
			if item["kind"] == m[1] && item["code"] == m[2] && item["domain"] == m[3] {
				item["count"] = item["count"].(int) + 1
				known = true
			}
		}
		if !known {
			if len(r.ObserverErrors) >= 32 {
				c.failed = true
				c.cancel()
				return
			}
			r.ObserverErrors = append(r.ObserverErrors, map[string]any{"kind": m[1], "code": m[2], "domain": m[3], "count": 1})
		}
	}
}
func (c *avCapture) Write(body []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(body)
	if c.failed || int64(n) > c.maximum-c.result.Bytes {
		c.failed = true
		c.cancel()
		return 0, invalid
	}
	c.hash.Write(body)
	c.result.Bytes += int64(n)
	for len(body) > 0 {
		index := bytes.IndexByte(body, '\n')
		length := len(body)
		if index >= 0 {
			length = index + 1
		}
		if len(c.pending)+length > 1<<20 {
			c.failed = true
			c.cancel()
			return 0, invalid
		}
		c.pending = append(c.pending, body[:length]...)
		body = body[length:]
		if index >= 0 {
			c.line(c.pending)
			c.pending = nil
		}
	}
	return n, nil
}
func observeAV(arguments []string, root string, diagnostics map[string]string, library string, maximum int64) avObservation {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	counts := map[string]int{}
	needles := map[string]string{}
	for k, v := range avDiagnostics {
		needles[k] = v
	}
	for k, v := range diagnostics {
		needles[k] = v
	}
	for k := range needles {
		counts[k] = 0
	}
	capture := &avCapture{result: avObservation{ExitCode: -1, Limits: []string{}, Diagnostics: counts}, hash: sha256.New(), maximum: maximum, cancel: cancel, needles: needles}
	cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	cmd.Dir = root
	cmd.Env = []string{"PATH=/bin:/usr/bin", "LC_ALL=C", "HOME=" + root, "TMPDIR=" + filepath.Join(root, "avtmp"), "TMP=" + filepath.Join(root, "avtmp"), "TEMP=" + filepath.Join(root, "avtmp")}
	if library != "" {
		cmd.Env = append(cmd.Env, "LD_PRELOAD="+library)
	}
	cmd.Stdout = capture
	cmd.Stderr = capture
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.pending) > 0 {
		capture.line(capture.pending)
	}
	if cmd.ProcessState != nil {
		capture.result.ExitCode = cmd.ProcessState.ExitCode()
	}
	capture.result.SHA = hex.EncodeToString(capture.hash.Sum(nil))
	var exit *exec.ExitError
	capture.result.Valid = ctx.Err() == nil && !capture.failed && (err == nil || errors.As(err, &exit))
	if !capture.result.Valid {
		capture.result.Reason = "OBSERVATION_TIMEOUT_OR_OUTPUT_LIMIT"
	}
	return capture.result
}
func avClean(value avObservation) bool {
	return value.Valid && value.ExitCode == 0 && value.Normal == 1 && value.Warnings == 0 && value.Errors == 0 && !value.ErrorReported && len(value.Limits) == 0
}
func avArguments(binary, root, temp string, test avCase) ([]string, error) {
	options, err := av.FixtureArguments(test.overrides)
	if err != nil {
		return nil, err
	}
	args := []string{binary, "--database=" + filepath.Join(root, "inputs", test.database), "--stdout", "--no-summary", "--tempdir=" + temp}
	args = append(args, options...)
	return append(args, filepath.Join(root, "inputs", test.input)), nil
}
func avDebug(arguments []string) []string {
	result := append([]string{}, arguments[:len(arguments)-1]...)
	return append(result, "--debug", arguments[len(arguments)-1])
}
func avCaseReport(root, binary, suite string, test avCase) (map[string]any, error) {
	args, err := avArguments(binary, root, filepath.Join(root, "avtmp"), test)
	if err != nil {
		return nil, err
	}
	limit := int64(64 << 20)
	if suite == "basic" {
		limit = 1 << 20
	}
	normal := observeAV(args, root, nil, "", limit)
	var debug *avObservation
	if test.expected == "hidden" || test.expected == "warning" || test.expected == "pcre" {
		v := observeAV(avDebug(args), root, nil, "", limit)
		debug = &v
	}
	met := normal.Valid
	switch test.expected {
	case "normal_ok":
		met = avClean(normal)
	case "marker_detection":
		met = met && normal.ExitCode == 1 && normal.Marker
	case "limit_alert":
		met = met && normal.ExitCode == 1 && len(normal.Limits) > 0
	case "pcre":
		met = avClean(normal) && debug != nil && debug.Valid && debug.Diagnostics[test.trigger] > 0
	case "empty":
		met = met && normal.ExitCode == 0 && normal.Empty == 1
	case "notice":
		found := false
		for _, name := range normal.Limits {
			found = found || name == "Heuristics.Limits.Exceeded."+test.trigger
		}
		met = met && normal.ExitCode == 1 && found
	case "hidden":
		met = avClean(normal) && debug != nil && debug.Valid && debug.Diagnostics[test.trigger] > 0
	case "warning":
		met = met && normal.Warnings > 0 && normal.ExitCode == 0 && normal.Normal == 1 && debug != nil && debug.Valid && debug.Diagnostics[test.trigger] > 0
	default:
		return nil, invalid
	}
	settings, err := av.FixtureArguments(test.overrides)
	if err != nil {
		return nil, err
	}
	settingsBytes, _ := json.Marshal(settings)
	argumentBytes, _ := json.Marshal(args[1:])
	databaseSHA, err := fileDigest(filepath.Join(root, "inputs", test.database))
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": test.id, "arguments": args[1:], "expected": test.expected, "configuration_sha256": digest(argumentBytes), "case_settings_sha256": digest(settingsBytes), "fixture_overrides": test.overrides, "definition_sha256": databaseSHA, "normal": normal, "debug": debug, "expectation_met": met}, nil
}
func avBasicCases() []avCase {
	return []avCase{
		{"clean", "marker.ndb", "clean.txt", "normal_ok", "", nil}, {"marker", "marker.ndb", "marker.txt", "marker_detection", "", nil},
		{"max-file", "marker.ndb", "limit.txt", "limit_alert", "", map[string]string{"max-filesize": "1024"}},
		{"max-files", "marker.ndb", "max-files.zip", "limit_alert", "", map[string]string{"max-files": "1"}},
		{"max-scan-size", "marker.ndb", "max-size.zip", "limit_alert", "", map[string]string{"max-scansize": "2048"}},
		{"pcre-match", "pcre-match.ldb", "pcre.txt", "pcre", "pcre-match", map[string]string{"pcre-match-limit": "1"}},
		{"pcre-depth", "pcre-depth.ldb", "pcre.txt", "pcre", "pcre-depth", map[string]string{"pcre-recmatch-limit": "1"}},
	}
}
func avLimitsCases() []avCase {
	return []avCase{
		{"zero-file", "marker.ndb", "empty.txt", "empty", "", nil}, {"max-recursion", "marker.ndb", "nested.zip", "notice", "MaxRecursion", map[string]string{"max-recursion": "2"}},
		{"max-scan-time", "marker.ndb", "scan-time.txt", "notice", "MaxScanTime", map[string]string{"max-scantime": "1"}},
		{"pcre-size", "pcre-match.ldb", "pcre.txt", "hidden", "pcre-size", map[string]string{"pcre-max-filesize": "512"}},
		{"html-normalize", "marker.ndb", "html.html", "hidden", "html-normalize", map[string]string{"max-htmlnormalize": "128"}},
		{"html-notags", "marker.ndb", "html.html", "hidden", "html-notags", map[string]string{"max-htmlnotags": "128"}},
		{"script-normalize", "marker.ndb", "script.txt", "hidden", "script-normalize", map[string]string{"max-scriptnormalize": "128"}},
		{"zip-type", "marker.ndb", "max-files.zip", "hidden", "zip-type", map[string]string{"max-ziptypercg": "64"}},
		{"embedded-pe", "marker.ndb", "embedded-pe.bin", "hidden", "embedded-pe", map[string]string{"max-embeddedpe": "64"}},
		{"partitions", "marker.ndb", "mbr.bin", "hidden", "partitions", map[string]string{"max-partitions": "1"}},
		{"mail-headers", "marker.ndb", "mail-headers.eml", "notice", "EmailHeaders", nil}, {"mail-header-bytes", "marker.ndb", "mail-header-bytes.eml", "notice", "EmailHeaderBytes", nil},
		{"mail-folds", "marker.ndb", "mail-folds.eml", "notice", "EmailLineFoldCnt", nil}, {"mail-arguments", "marker.ndb", "mail-arguments.eml", "notice", "EmailMIMEArguments", nil},
		{"mail-parts", "marker.ndb", "mail-parts.eml", "notice", "EmailMIMEPartsPerMessage", nil}, {"pdf-objects", "marker.ndb", "pdf-objects.pdf", "hidden", "pdf-objects", nil},
		{"image-allocation", "marker.ndb", "image-allocation.png", "hidden", "image-allocation", nil}, {"alz-max-files", "marker.ndb", "stored.alz", "notice", "MaxFiles", map[string]string{"max-files": "2"}},
		{"bytecode-timeout", "bytecode-loop.cbc", "pcre.txt", "warning", "bytecode-warning", map[string]string{"bytecode-unsigned": "yes", "bytecode-timeout": "1", "bytecode-mode": "ForceInterpreter"}},
	}
}
func avManifest(destination string, inputs map[string][]byte) (map[string]any, error) {
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	files := map[string]any{}
	for _, name := range names {
		body := inputs[name]
		f, err := os.OpenFile(filepath.Join(destination, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.Write(body)
		if err == nil {
			err = f.Sync()
		}
		closeError := f.Close()
		if err != nil {
			return nil, err
		}
		if closeError != nil {
			return nil, closeError
		}
		files[name] = map[string]any{"bytes": len(body), "sha256": digest(body)}
	}
	manifest := map[string]any{"schema": 1, "evidence_kind": "synthetic_fixture_generation_only", "target_executed": false, "inputs": files}
	return manifest, write(filepath.Join(destination, "manifest.json"), manifest)
}
func RunAV(suite, work, output string) (returned error) {
	stage := "GUEST_ISOLATION"
	defer func() {
		if returned != nil && filepath.IsAbs(output) && filepath.Clean(output) == output && filepath.Dir(output) == "/job/metadata" {
			if _, e := os.Lstat(output); os.IsNotExist(e) {
				_ = write(output, map[string]any{"schema_version": 1, "evidence_kind": "target_guest_fixture_setup_failure", "implementation": "go", "suite": suite, "failure_code": "AV_FIXTURE_" + stage, "all_expectations_met": false, "cases": []any{}, "production_profile_enabled": false, "product_enabled": false, "stage0_gate_passed": false, "raw_output_persisted": false})
			}
		}
	}()
	if !guest() {
		return invalid
	}
	stage = "SUITE_SELECTION"
	if suite != "basic" && suite != "limits" && suite != "hard" && suite != "io" && suite != "internal" && suite != "remaining" {
		return invalid
	}
	stage = "WORK_SCOPE"
	canonical, err := filepath.EvalSymlinks(filepath.Dir(work))
	if err != nil || filepath.Join(canonical, filepath.Base(work)) != work || !filepath.IsAbs(output) {
		return invalid
	}
	stage = "WORK_CREATE"
	if err = os.Mkdir(work, 0700); err != nil {
		return err
	}
	stage = "TEMP_CREATE"
	if err = os.Mkdir(filepath.Join(work, "avtmp"), 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stage = "RUNTIME_BINDING"
	profile, binding, err := av.FixtureRuntime(ctx)
	if err != nil {
		return err
	}
	stage = "SCANNER_VERSION"
	binary := "/usr/bin/clamscan"
	version, stderr, status, err := command([]string{binary, "--version"}, nil, 8192, []string{"PATH=/bin:/usr/bin", "LC_ALL=C"})
	if err != nil || status != 0 || len(stderr) != 0 || strings.TrimSpace(strings.Split(string(version), "/")[0]) != "ClamAV 1.4.6" {
		return invalid
	}
	stage = "FIXTURE_GENERATE"
	inputs := avBasicInputs()
	switch suite {
	case "limits":
		inputs, err = avLimitInputs()
	case "internal":
		inputs = avInternalInputs()
	case "remaining":
		inputs = avRemainingInputs()
	case "hard":
		inputs, err = avHardInputs()
	}
	if err != nil {
		return err
	}
	stage = "FIXTURE_WRITE"
	manifest, err := avManifest(filepath.Join(work, "inputs"), inputs)
	if err != nil {
		return err
	}
	stage = "CASE_EXECUTION"
	rows := []map[string]any{}
	switch suite {
	case "basic", "limits":
		cases := avBasicCases()
		if suite == "limits" {
			cases = avLimitsCases()
		}
		for _, test := range cases {
			row, err := avCaseReport(work, binary, suite, test)
			if err != nil {
				return err
			}
			rows = append(rows, row)
		}
	case "io":
		rows, err = runAVIO(work, binary)
	case "internal":
		rows, err = runAVInternal(work, binary)
	case "remaining":
		rows, err = runAVRemaining(work, binary)
	case "hard":
		rows, err = runAVHard(work, binary)
	}
	if err != nil {
		return err
	}
	passed := len(rows) > 0
	for _, row := range rows {
		passed = passed && row["expectation_met"] == true
	}
	binarySHA, err := fileDigest(binary)
	if err != nil {
		return err
	}
	report := map[string]any{"schema_version": 1, "evidence_kind": "target_guest_measurement", "implementation": "go", "suite": suite, "recorded_at_unix": time.Now().Unix(), "uid": os.Geteuid(), "engine_version_output": strings.TrimSpace(string(version)), "binary_sha256": binarySHA, "profile": av.FixtureProfile(), "apk_scan_binding": binding, "runtime_profile": profile, "fixture_manifest": manifest, "cases": rows, "all_expectations_met": passed, "production_profile_enabled": false, "product_enabled": false, "stage0_gate_passed": false, "raw_output_persisted": false}
	stage = "REPORT_WRITE"
	if err = write(output, report); err != nil {
		return err
	}
	if !passed {
		return invalid
	}
	return nil
}
