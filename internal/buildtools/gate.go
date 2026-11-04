package buildtools

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type GateResult struct {
	Stage                    int      `json:"stage"`
	Passed                   bool     `json:"passed"`
	Incomplete               []string `json:"incomplete"`
	MissingEvidenceFiles     []string `json:"missing_evidence_files"`
	CustomerOperationEnabled bool     `json:"customer_operation_enabled"`
}

func Gate(repository string) (GateResult, int, error) {
	result := GateResult{Stage: 0, Incomplete: []string{}, MissingEvidenceFiles: []string{}}
	root, err := Repository(repository)
	if err != nil {
		return result, 2, err
	}
	body, err := os.ReadFile(filepath.Join(root, "experiments/stage0-gates.json"))
	if err != nil {
		return result, 2, err
	}
	var record struct {
		Gates []struct {
			ID       string   `json:"id"`
			Status   string   `json:"status"`
			Evidence []string `json:"evidence"`
		} `json:"gates"`
		Stage1AuthorizedByGate   bool `json:"stage1_authorized_by_gate"`
		CustomerOperationEnabled bool `json:"customer_operation_enabled"`
	}
	if err = json.Unmarshal(body, &record); err != nil {
		return result, 2, err
	}
	for _, gate := range record.Gates {
		if gate.Status != "verified_experiment" {
			result.Incomplete = append(result.Incomplete, gate.ID)
		}
		for _, name := range gate.Evidence {
			path := filepath.Join(root, "experiments", name)
			if filepath.IsAbs(name) {
				path = name
			}
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				result.MissingEvidenceFiles = append(result.MissingEvidenceFiles, name)
			}
		}
	}
	result.Passed = len(result.Incomplete) == 0 && len(result.MissingEvidenceFiles) == 0
	if record.Stage1AuthorizedByGate != result.Passed || record.CustomerOperationEnabled || len(result.MissingEvidenceFiles) != 0 {
		return result, 2, nil
	}
	if !result.Passed {
		return result, 1, nil
	}
	return result, 0, nil
}
