package bench

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

// Formal denotes a frozen experimental run, not a mathematical certificate.
// The launcher additionally checks source/binary hashes and actual RNS primes.
func formalEvidence(raw []byte, selected string) (map[string]any, error) {
	path := os.Getenv("TUPLE8_FORMAL_MANIFEST")
	if path == "" { return nil, fmt.Errorf("formal run requires frozen manifest") }
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var manifest struct {
		Status string `json:"status"`
		Repetitions int `json:"repetitions"`
		Tasks []struct {
			ConfigHash string `json:"config_sha256"`
			Case string `json:"case"`
			SecurityCase string `json:"security_case"`
		} `json:"tasks"`
		Evidence map[string]struct {
			Path string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"security_evidence"`
	}
	if err = json.Unmarshal(b, &manifest); err != nil { return nil, err }
	if manifest.Status != "FROZEN_FOR_TEN_REPEATS" || manifest.Repetitions != 10 {
		return nil, fmt.Errorf("manifest not frozen for ten repeats")
	}
	securityCase := ""
	for _, t := range manifest.Tasks {
		if t.ConfigHash == hashBytes(raw) && t.Case == selected { securityCase = t.SecurityCase; break }
	}
	if securityCase == "" { return nil, fmt.Errorf("config/case is absent from frozen manifest") }
	evidence, ok := manifest.Evidence[securityCase]
	if !ok { return nil, fmt.Errorf("missing security evidence") }
	eb, err := os.ReadFile(filepath.Join(filepath.Dir(path), evidence.Path))
	if err != nil { return nil, err }
	if hashBytes(eb) != evidence.SHA256 { return nil, fmt.Errorf("security evidence hash changed") }
	var report struct {
		Case string `json:"case"`
		Finished bool `json:"finished"`
		Model string `json:"secret_model"`
		CostModel string `json:"cost_model"`
		Attacks map[string]struct {
			Bits float64 `json:"log2_rop"`
			Finite bool `json:"finite"`
			Error string `json:"error"`
		} `json:"attacks"`
	}
	if err = json.Unmarshal(eb, &report); err != nil { return nil, err }
	if !report.Finished || report.Case != securityCase || report.Model != "ND.SparseBinomial(eta=1,hw=128,n=N)" || report.CostModel != "RC.MATZOV" {
		return nil, fmt.Errorf("incomplete or mismatched security model")
	}
	minimum := math.Inf(1)
	for _, name := range []string{"primal_usvp", "primal_bdd", "primal_hybrid_mitm", "primal_hybrid_bdd", "dual_hybrid_matzov"} {
		a, ok := report.Attacks[name]
		if !ok || a.Error != "" || !a.Finite || math.IsNaN(a.Bits) || math.IsInf(a.Bits, 0) || a.Bits < 128 {
			return nil, fmt.Errorf("security gate failed for %s", name)
		}
		if a.Bits < minimum { minimum = a.Bits }
	}
	return map[string]any{"manifest_sha256":hashBytes(b), "evidence_sha256":evidence.SHA256,
		"security_case":securityCase, "minimum_estimated_classical_bits":minimum,
		"scope":"five specified classical lattice estimators with RC.MATZOV; not a proof"}, nil
}

func RunFormal(s *Suite, raw []byte, dir, selected string) error {
	evidence, err := formalEvidence(raw, selected)
	if err != nil { return err }
	return runSuite(s, raw, dir, selected, evidence)
}
