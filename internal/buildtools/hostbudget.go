package buildtools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"unicode/utf8"
)

// The host-budget contract is not read by any guest; its only accepted change is the reviewed accounting-description addition.
const hostBudgetContract = "experiments/contracts/host-budgets.json"

var hostBudgetAccountingAdditions = map[string]string{
	"retained_run_evidence": "finished scan and update run control files, including per-run integrated watchdog events, stay charged to detailed_report_pool until retention removes them; update final reports and their pending copies are charged to update_report_pool",
	"normalized_logs_scope": "normalized_logs_all_rotations covers host-wide rotating diagnostic logs; per-run integrated watchdog events are run control evidence bounded by integrated_watchdog_normalized_events_ram",
}

// hostBudgetAccountingDelta accepts the new contract only when it adds exactly the reviewed accounting descriptions and keeps every
// other key and value; both files are bound to the given digests.
func hostBudgetAccountingDelta(oldPath, oldSHA, newPath, newSHA string) (map[string]any, error) {
	old, err := hostBudgetObject(oldPath, oldSHA)
	if err != nil {
		return nil, err
	}
	current, err := hostBudgetObject(newPath, newSHA)
	if err != nil {
		return nil, err
	}
	if old["profile_id"] != "filegate-host-budget-v1" || old["schema_version"] != json.Number("1") {
		return nil, errors.New("HOST_BUDGET_CONTRACT_UNKNOWN")
	}
	if len(old) != len(current) {
		return nil, errors.New("HOST_BUDGET_CONTRACT_KEYS_CHANGED")
	}
	for name, value := range old {
		next, ok := current[name]
		if !ok {
			return nil, errors.New("HOST_BUDGET_CONTRACT_KEYS_CHANGED")
		}
		if name != "accounting" && !reflect.DeepEqual(value, next) {
			return nil, fmt.Errorf("HOST_BUDGET_CONTRACT_VALUE_CHANGED: %s", name)
		}
	}
	before, ok := old["accounting"].(map[string]any)
	after, valid := current["accounting"].(map[string]any)
	if !ok || !valid {
		return nil, errors.New("HOST_BUDGET_ACCOUNTING_INVALID")
	}
	for name, value := range before {
		if next, exists := after[name]; !exists || !reflect.DeepEqual(value, next) {
			return nil, fmt.Errorf("HOST_BUDGET_ACCOUNTING_CHANGED: %s", name)
		}
	}
	added := []string{}
	for name, value := range after {
		if _, existing := before[name]; existing {
			continue
		}
		if reviewed, known := hostBudgetAccountingAdditions[name]; !known || value != reviewed {
			return nil, fmt.Errorf("HOST_BUDGET_ACCOUNTING_ADDITION_UNREVIEWED: %s", name)
		}
		added = append(added, name)
	}
	if len(added) != len(hostBudgetAccountingAdditions) {
		return nil, errors.New("HOST_BUDGET_ACCOUNTING_ADDITION_INCOMPLETE")
	}
	sort.Strings(added)
	return map[string]any{"path": hostBudgetContract, "baseline_sha256": oldSHA, "sha256": newSHA, "added_accounting_keys": added, "other_keys_and_values_identical": true}, nil
}

// hostBudgetObject reads one bounded regular file once, checks its digest and decodes a single JSON object without duplicate keys.
func hostBudgetObject(path, expected string) (map[string]any, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("HOST_BUDGET_CONTRACT_FILE_INVALID")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if digest(body) != expected {
		return nil, fmt.Errorf("pinned source/artifact changed: %s", path)
	}
	if !utf8.Valid(body) || duplicateJSONKeys(json.NewDecoder(bytes.NewReader(body))) != nil {
		return nil, errors.New("HOST_BUDGET_CONTRACT_MALFORMED")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil || value == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("HOST_BUDGET_CONTRACT_MALFORMED")
	}
	return value, nil
}

// duplicateJSONKeys walks one JSON value and fails on a repeated object key or a syntax error.
func duplicateJSONKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, _ := key.(string)
			if seen[name] {
				return errors.New("duplicate JSON key")
			}
			seen[name] = true
			if err = duplicateJSONKeys(decoder); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for decoder.More() {
			if err = duplicateJSONKeys(decoder); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = decoder.Token()
	return err
}
