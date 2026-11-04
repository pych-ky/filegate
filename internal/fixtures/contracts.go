package fixtures

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func same(a, b any) bool {
	one, first := json.Marshal(a)
	two, second := json.Marshal(b)
	return first == nil && second == nil && string(one) == string(two)
}

func number(value any) int64 {
	switch n := value.(type) {
	case json.Number:
		value, err := n.Int64()
		if err == nil {
			return value
		}
	case float64:
		if float64(int64(n)) == n {
			return int64(n)
		}
	case int:
		return int64(n)
	case int64:
		return n
	}
	return -1
}

func extraProductCases(directory string) ([]formatCase, error) {
	body := []byte("<!doctype html><html><body>Synthetic login page</body></html>\n")
	if err := os.WriteFile(filepath.Join(directory, "inputs/product-login.html"), body, 0600); err != nil {
		return nil, err
	}
	rows := [][5]string{
		{"expected_zip_received_text", "txt_ascii.bin", "zip", "HOLD", "UNEXPECTED_ARTIFACT_TYPE"},
		{"expected_zip_received_html", "product-login.html", "zip", "HOLD", "UNEXPECTED_ARTIFACT_TYPE"},
		{"expected_text_received_zip", "store.zip", "txt", "HOLD", "UNEXPECTED_ARTIFACT_TYPE"},
		{"zip_crc_corruption", "crc_recorded_zero_actual_nonzero.zip", "zip", "HOLD", "ARCHIVE_CORRUPT"},
		{"zip_prefix_profile", "prefix.zip", "zip", "HOLD", "ARCHIVE_PROFILE_UNSUPPORTED"},
		{"zip_complete_structure", "store.zip", "zip", "ACCEPT_FORMAT_STRUCTURE", ""},
	}
	var result []formatCase
	for _, row := range rows {
		name := "inputs/" + row[1]
		path := filepath.Join(directory, name)
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		expected := map[string]any{"product_validation": row[3]}
		if row[4] != "" {
			expected["reason"] = row[4]
		}
		result = append(result, formatCase{row[0], name, digest(body), int64(len(body)), map[string]any{"expected_type": row[2]}, expected})
	}
	return result, nil
}

func FormatContracts(archive, manifest, work, output string) error {
	if !guest() {
		return invalid
	}
	if err := os.Mkdir(work, 0700); err != nil {
		return err
	}
	directory := filepath.Join(work, "fixtures")
	corpus, err := ExtractCorpus(archive, manifest, directory, true)
	if err != nil {
		return err
	}
	zipCases, textCases, err := readCases(filepath.Join(directory, "fixture-manifest.json"))
	if err != nil {
		return err
	}
	images, _, err := readCases(filepath.Join(directory, "image-manifest.json"))
	if err != nil {
		return err
	}
	office, _, err := readCases(filepath.Join(directory, "ooxml-manifest.json"))
	if err != nil {
		return err
	}
	product, err := extraProductCases(directory)
	if err != nil {
		return err
	}
	product = append(append(product, images...), office...)
	type group struct {
		kind, field string
		cases       []formatCase
	}
	groups := []group{{"zip", "zip_validation", zipCases}, {"txt", "text_validation", textCases}, {"product", "product_validation", product}}
	var results []map[string]any
	allPassed := true
	for _, set := range groups {
		for _, c := range set.cases {
			if !corpusPath(c.Input) {
				return invalid
			}
			source := filepath.Join(directory, c.Input)
			before, err := fileDigest(source)
			info, statErr := os.Lstat(source)
			if err != nil || statErr != nil || !info.Mode().IsRegular() || before != c.SHA256 || info.Size() != c.Bytes {
				return invalid
			}
			target := filepath.Join(work, set.kind+"-"+c.ID)
			if !filepath.IsLocal(set.kind+"-"+c.ID) || filepath.Base(target) != set.kind+"-"+c.ID || os.Mkdir(target, 0700) != nil {
				return invalid
			}
			mode := set.kind + "-contract"
			if set.kind == "product" {
				mode = "inspect"
			}
			if c.Metadata == nil {
				c.Metadata = map[string]any{}
			}
			metadata, _ := json.Marshal(c.Metadata)
			arguments := []string{"/filegate-worker", "--mode", mode, "--input", source, "--work", target, "--metadata", string(metadata)}
			stdout, stderr, status, runErr := command(arguments, nil, 33<<20, nil)
			report := map[string]any{}
			decoded := decode(stdout, &report) == nil
			after, changed := fileDigest(source)
			passed := runErr == nil && decoded && changed == nil && before == after && status == 0 && len(stdout) <= 32<<20 && len(stderr) <= 1<<20 &&
				report["structure_status"] == c.Expected[set.field] && report["required_checks_complete"] == false
			expectedStatus := c.Expected[set.field]
			if (expectedStatus == "HOLD" || expectedStatus == "BLOCK") && c.Expected["reason"] != nil {
				passed = passed && same(report["reason_codes"], []any{c.Expected["reason"]})
			}
			for _, key := range []string{"archive_entry_count", "required_av_input_count"} {
				if expected, ok := c.Expected[key]; ok {
					passed = passed && same(expected, report[key])
				}
			}
			objects, objectOK := report["manifest"].([]any)
			excluded := 0
			var formats []any
			for _, item := range objects {
				object, ok := item.(map[string]any)
				if !ok {
					passed = false
					continue
				}
				formats = append(formats, object["format"])
				if object["av_required"] != true {
					excluded++
				}
			}
			if expected, ok := c.Expected["manifest_formats"]; ok {
				passed = passed && objectOK && report["structure_checks_complete"] == true && report["format_checks_complete"] == true && same(formats, expected) && excluded == 0
				checks, _ := report["completed_checks"].([]any)
				wanted, _ := c.Expected["completed_checks"].([]any)
				for _, check := range wanted {
					found := false
					for _, actual := range checks {
						found = found || same(actual, check)
					}
					passed = passed && found
				}
			}
			if expected, ok := c.Expected["excluded_entries"]; ok {
				passed = passed && number(expected) == int64(excluded)
			}
			if c.Expected["directory_av_exclusion_permitted"] == false {
				passed = passed && excluded == 0
			}
			if set.kind == "txt" && expectedStatus == "ACCEPT_TXT_STRUCTURE" {
				passed = passed && number(report["required_av_input_count"]) == 1 && excluded == 0
			}
			delete(report, "manifest")
			results = append(results, map[string]any{"id": c.ID, "kind": set.kind, "input_sha256": c.SHA256, "input_bytes": c.Bytes,
				"expected": c.Expected, "actual": report, "worker_report_sha256": digest(stdout), "exit_code": status, "stderr_bytes": len(stderr), "passed": passed})
			allPassed = allPassed && passed
			files, err := os.ReadDir(target)
			if err != nil {
				return err
			}
			for _, file := range files {
				if !file.Type().IsRegular() || os.Remove(filepath.Join(target, file.Name())) != nil {
					return invalid
				}
			}
			if err := os.Remove(target); err != nil {
				return err
			}
		}
	}
	worker, err := fileDigest("/filegate-worker")
	if err != nil {
		return err
	}
	record := map[string]any{"schema": 2, "scope": "Protected VM format-contract E2E over identical pinned finite inputs; AV and product acceptance excluded",
		"fixture_manifest_sha256": corpus.Manifests["fixture-manifest.json"], "image_manifest_sha256": corpus.Manifests["image-manifest.json"],
		"ooxml_manifest_sha256": corpus.Manifests["ooxml-manifest.json"], "corpus_archive_sha256": corpus.ArchiveSHA256, "worker_sha256": worker,
		"uid": os.Getuid(), "results": results, "all_passed": allPassed, "product_enabled": false, "stage0_gate_passed": false, "av_executed": false}
	if err := write(output, record); err != nil {
		return err
	}
	if !allPassed {
		return invalid
	}
	return nil
}
