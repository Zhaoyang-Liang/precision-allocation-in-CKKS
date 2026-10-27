package bench

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
)

// The contract excludes repeat/data seeds and file locations, but includes
// every mathematical and arithmetic choice. It is common to both repeats.
func profileContract(c *ProfileConfig, plan *ProfilePlan) (map[string]any, string, error) {
	branches := make([]any, 0, len(c.Branches))
	for i, b := range c.Branches {
		p := plan.Branches[i].Parameters
		pattern := b.Pattern
		if pattern == nil {
			pattern = []int{}
		}
		multiplier := map[string]any{"period": 1, "coefficients": []string{"1"}, "inverse_coefficients": []string{"1"},
			"embedding_intervals": []EmbeddingInterval{{"1", "1"}}}
		if b.Multiplier != nil {
			multiplier = map[string]any{"period": b.Multiplier.Period, "coefficients": b.Multiplier.Coefficients,
				"inverse_coefficients": b.Multiplier.Inverse, "embedding_intervals": b.Multiplier.Embeddings}
		}
		branches = append(branches, map[string]any{"id": b.ID, "groups": b.Groups, "slot_pattern": pattern, "N": p.N, "Q": p.Q, "P": p.P,
			"initial_scale_bits": b.ScaleBits, "rescale_counts": b.RescaleCounts, "output_drop_primes": b.OutputDropPrimes, "multiplier": multiplier})
	}
	contract := map[string]any{"depth": c.Depth, "precision": c.Precision, "target_bits": c.Targets, "group_sizes": c.GroupSizes,
		"branches": branches, "backend": Backend, "scale_metadata_bits": 1024, "input_interval": []string{"3/4", "7/8"}, "old_error": "0",
		"input_interface": "native", "output_interface": "ordinary_coefficients_high_precision_metadata", "algorithm": "direct_square_chain"}
	data, e := json.Marshal(contract)
	if e != nil {
		return nil, "", e
	}
	return contract, hashBytes(data), nil
}

type profileSecurity struct {
	Schema      string   `json:"schema"`
	Model       string   `json:"model"`
	Secret      string   `json:"secret"`
	Sigma       string   `json:"error_sigma"`
	Samples     string   `json:"samples"`
	Target      int      `json:"target_bits"`
	Commit      string   `json:"estimator_commit"`
	WrapperHash string   `json:"wrapper_sha256"`
	Dirty       []string `json:"estimator_tracked_dirty"`
	Cases       []struct {
		N       int `json:"N"`
		Q, P    []string
		QP      string `json:"qp_exact"`
		LogQ    int    `json:"q_est_log2"`
		Attacks map[string]struct {
			Bits string `json:"log2_rop"`
			Pass bool   `json:"target_pass"`
		} `json:"attacks"`
	} `json:"cases"`
}

func resolveProfileFile(configDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(configDir, path)
}

func verifyProfileSecurity(c *ProfileConfig, plan *ProfilePlan, configDir string) (map[string]string, error) {
	evidence := map[string]string{}
	for i, b := range c.Branches {
		if b.SecurityFile == "" || len(b.SecuritySHA256) != 64 {
			return nil, fmt.Errorf("branch %s lacks security evidence; HE not started", b.ID)
		}
		path := resolveProfileFile(configDir, b.SecurityFile)
		data, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		if hashBytes(data) != b.SecuritySHA256 {
			return nil, fmt.Errorf("security file hash mismatch")
		}
		var s profileSecurity
		if e = json.Unmarshal(data, &s); e != nil {
			return nil, e
		}
		if s.Schema != "ckks-new-security-v1" || s.Model != "RC.MATZOV" || s.Secret != "uniform_ternary" || s.Sigma != "3.2" || s.Samples != "infinity" || s.Target < 128 || len(s.Commit) != 40 || len(s.WrapperHash) != 64 || len(s.Dirty) != 0 {
			return nil, fmt.Errorf("security model/version mismatch")
		}
		p := plan.Branches[i].Parameters
		if p.N < 4096 || p.N > 65536 {
			return nil, fmt.Errorf("HE dimension outside declared experiment")
		}
		matched := false
		for _, v := range s.Cases {
			if v.N != p.N || v.QP != p.ProductQP {
				continue
			}
			if len(v.Q) != len(p.Q) || len(v.P) != len(p.P) {
				continue
			}
			equal := true
			for j := range v.Q {
				equal = equal && v.Q[j] == p.Q[j]
			}
			for j := range v.P {
				equal = equal && v.P[j] == p.P[j]
			}
			if !equal {
				continue
			}
			qp, e := rat(p.ProductQP)
			if e != nil {
				return nil, e
			}
			expected := qp.Num().BitLen()
			// QP is an odd product >1, hence never a power of two.
			if v.LogQ != expected {
				return nil, fmt.Errorf("security modulus ceiling mismatch")
			}
			if len(v.Attacks) != 3 {
				return nil, fmt.Errorf("incomplete security attacks")
			}
			for _, name := range []string{"primal_usvp", "primal_bdd", "dual_hybrid"} {
				a, ok := v.Attacks[name]
				if !ok || !a.Pass {
					return nil, fmt.Errorf("security attack %s missing or failing", name)
				}
				bits, e := strconv.ParseFloat(a.Bits, 64)
				if e != nil || math.IsNaN(bits) || math.IsInf(bits, 0) || bits < float64(s.Target) {
					return nil, fmt.Errorf("invalid security work-factor estimate")
				}
			}
			matched = true
			break
		}
		if !matched {
			return nil, fmt.Errorf("no exact Q/P security match for %s", b.ID)
		}
		evidence[path] = hashBytes(data)
	}
	return evidence, nil
}

func verifyProfileCertificate(c *ProfileConfig, plan *ProfilePlan, configDir string) (map[string]string, error) {
	if c.CertificationStatus != "conditional_certified" || c.CertificateFile == "" {
		return nil, fmt.Errorf("formal runner requires completed conditional certificate")
	}
	path := resolveProfileFile(configDir, c.CertificateFile)
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var v struct {
		Schema   string `json:"schema"`
		Contract string `json:"contract_sha256"`
		Pass     bool   `json:"all_branches_pass"`
		Decoder  bool   `json:"decoder_bound_included"`
		Branches []struct {
			ID           string `json:"id"`
			Pass         bool   `json:"pass"`
			SampledEvent struct {
				Secrets int `json:"secret_polynomials_max"`
				Errors  int `json:"error_polynomials_max"`
			} `json:"sampled_event"`
		} `json:"branches"`
	}
	if e = json.Unmarshal(data, &v); e != nil {
		return nil, e
	}
	if v.Schema != "ckks-profile-certificate-v1" || v.Contract != plan.ContractSHA256 || !v.Pass || !v.Decoder || len(v.Branches) != len(c.Branches) {
		return nil, fmt.Errorf("certificate contract or status mismatch")
	}
	for i, b := range c.Branches {
		if v.Branches[i].ID != b.ID || !v.Branches[i].Pass {
			return nil, fmt.Errorf("branch certificate mismatch")
		}
		if v.Branches[i].SampledEvent.Secrets != 256 || v.Branches[i].SampledEvent.Errors != 4096 {
			return nil, fmt.Errorf("certificate sampled-event version mismatch; recompute for V3")
		}
	}
	return map[string]string{path: hashBytes(data)}, nil
}

// CheckProfileEvidence validates every formal-run gate without generating keys
// or creating a run directory. It is used when freezing the two-repeat registry.
func CheckProfileEvidence(path string) (map[string]any, error) {
	c, raw, e := LoadProfile(path)
	if e != nil {
		return nil, e
	}
	plan, e := PlanProfile(c, raw)
	if e != nil {
		return nil, e
	}
	security, certificates, e := profileEvidence(c, plan, filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	return map[string]any{"id": c.ID, "contract_sha256": plan.ContractSHA256, "config_sha256": hashBytes(raw),
		"security_files": security, "certificate_files": certificates, "preflight_memory_guard_bytes": plan.MemoryGuard,
		"key_family_count": len(plan.KeyFamilies), "HE_executions": 0, "generated_keys": 0, "all_preflight_checks_pass": true}, nil
}

func profileEvidence(c *ProfileConfig, plan *ProfilePlan, dir string) (map[string]string, map[string]string, error) {
	security, e := verifyProfileSecurity(c, plan, dir)
	if e != nil {
		return nil, nil, e
	}
	certificates, e := verifyProfileCertificate(c, plan, dir)
	if e != nil {
		return nil, nil, e
	}
	if plan.MemoryGuard > 8<<30 {
		return nil, nil, fmt.Errorf("local 8 GiB allocation guard exceeded; no HE started")
	}
	for _, counts := range plan.SampleCounts {
		if counts["secret_polynomials_upper"] > 256 || counts["error_polynomials_upper"] > 4096 {
			return nil, nil, fmt.Errorf("sampled-family certificate count exceeded before key generation")
		}
	}
	return security, certificates, nil
}
