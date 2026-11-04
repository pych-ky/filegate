package fixtures

import (
	"path/filepath"
)

const avRemainingObserverSHA = "4dccbc740691c1517a66eebf30e2d9621b5de2a834c129f03e5d60e4457a27ff"

var avRemainingDiagnostics = map[string]string{
	"remaining-marker": "FileGate.Harmless.Remaining.", "hwp-recursion-limit": "Continuing after file scan resulted with: Exceeded max recursion depth",
	"xlm-record-limit": "[cli_extract_xlm_macros_and_images] Record size exceeds maximum allowed", "xlm-image-route": "[scan_biff_for_xlm_macros_and_images] Found image in sheet",
	"observer-loaded": "FILEGATE_REMAINING_OBSERVER loaded=1", "observer-failure": "FILEGATE_REMAINING_OBSERVER failure=", "xml-20-of-20": "FILEGATE_REMAINING_XML_ATTR visited=20 available=20", "xml-20-of-21": "FILEGATE_REMAINING_XML_ATTR visited=20 available=21",
	"xml-base64-call": "FILEGATE_REMAINING_XML_BASE64 bytes=", "xml-decoded-marker": "FILEGATE_REMAINING_XML_BASE64 bytes=32 marker=1", "xml-decoded-scan": "HWPML: Decoded binary data to ", "html-control-tail": "longest_A=1012 tail=1", "html-limited-tail": "longest_A=1013 tail=0",
}

func avSameOrdinary(left, right avObservation) bool {
	if left.ExitCode != right.ExitCode || left.Normal != right.Normal || left.Warnings != right.Warnings || left.Errors != right.Errors || len(left.Limits) != len(right.Limits) {
		return false
	}
	for i, v := range left.Limits {
		if v != right.Limits[i] {
			return false
		}
	}
	return true
}
func runAVRemaining(root, binary string) ([]map[string]any, error) {
	source := "/av/remaining_candidate/boundary_observer.c"
	body, _, err := readOwned(source, 1<<20, true)
	if err != nil || digest(body) != avRemainingObserverSHA {
		return nil, invalid
	}
	observer := filepath.Join(root, "boundary-observer.so")
	compile := []string{"/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-I/usr/include/libxml2", source, "-lxml2", "-ldl", "-o", observer}
	compiled := observeAV(compile, root, nil, "", 64<<20)
	observerReady := compiled.Valid && compiled.ExitCode == 0
	var observerSHA any
	if observerReady {
		sha, err := fileDigest(observer)
		if err != nil {
			return nil, err
		}
		observerSHA = sha
	}
	cases := []avCase{{"xml-attributes-control", "xml-marker.ndb", "xml-attributes-20.xml", "marker", "xml-20-of-20", nil}, {"xml-attributes-limit", "xml-marker.ndb", "xml-attributes-21.xml", "hidden", "xml-20-of-21", nil}, {"html-token-control", "html-marker.ndb", "html-token-1024.html", "marker", "html-control-tail", nil}, {"html-token-limit", "html-marker.ndb", "html-token-1025.html", "hidden", "html-limited-tail", nil}, {"hwp-recursion-control", "clean-marker.ndb", "hwp-recursion-15.hwp", "control", "hwp-recursion-limit", nil}, {"hwp-recursion-limit", "clean-marker.ndb", "hwp-recursion-16.hwp", "hidden", "hwp-recursion-limit", nil}, {"xlm-record-control", "clean-marker.ndb", "xlm-record-8228.ole", "control", "xlm-record-limit", nil}, {"xlm-record-limit", "clean-marker.ndb", "xlm-record-8229.ole", "hidden", "xlm-record-limit", nil}}
	rows := []map[string]any{}
	for _, test := range cases {
		args, err := avArguments(binary, root, filepath.Join(root, "avtmp"), test)
		if err != nil {
			return nil, err
		}
		normal := observeAV(args, root, avRemainingDiagnostics, "", 64<<20)
		debug := observeAV(avDebug(args), root, avRemainingDiagnostics, "", 64<<20)
		var diagnostic *avObservation
		xml, html := test.id[:3] == "xml", test.id[:4] == "html"
		if (xml || html) && observerReady {
			observed := observeAV(args, root, avRemainingDiagnostics, observer, 64<<20)
			diagnostic = &observed
		}
		reached := false
		if xml || html {
			reached = diagnostic != nil && diagnostic.Valid && diagnostic.Diagnostics["observer-loaded"] == 1 && diagnostic.Diagnostics["observer-failure"] == 0 && diagnostic.Diagnostics[test.trigger] == 1 && avSameOrdinary(normal, *diagnostic) && normal.Diagnostics["remaining-marker"] == diagnostic.Diagnostics["remaining-marker"]
			if xml {
				decoded := boolInt(test.expected == "marker")
				reached = reached && debug.Valid && diagnostic != nil && diagnostic.Diagnostics["xml-base64-call"] == decoded && diagnostic.Diagnostics["xml-decoded-marker"] == decoded && debug.Diagnostics["xml-decoded-scan"] == decoded
			}
		} else {
			reached = debug.Valid
			if test.expected == "control" {
				reached = reached && debug.Diagnostics[test.trigger] == 0
			} else {
				reached = reached && debug.Diagnostics[test.trigger] > 0
			}
			if test.id[:3] == "xlm" {
				reached = reached && debug.Diagnostics["xlm-image-route"] > 0
			}
		}
		matched := reached && avClean(normal) && normal.Diagnostics["remaining-marker"] == 0
		if test.expected == "marker" {
			matched = reached && normal.Valid && normal.ExitCode == 1 && normal.Diagnostics["remaining-marker"] == 1 && normal.Warnings == 0 && normal.Errors == 0 && len(normal.Limits) == 0
		}
		rows = append(rows, map[string]any{"id": test.id, "expected": test.expected, "arguments": args[1:], "fixture_overrides": map[string]string{}, "normal": normal, "debug": debug, "diagnostic_instrumented": diagnostic, "limit_or_control_witness": reached, "expectation_met": matched, "observer_compile": compiled, "observer_arguments": compile, "observer_source_sha256": avRemainingObserverSHA, "observer_binary_sha256": observerSHA, "witness_scope": "diagnostic_interposition_compared_with_unmodified_ordinary_output"})
	}
	return rows, nil
}
