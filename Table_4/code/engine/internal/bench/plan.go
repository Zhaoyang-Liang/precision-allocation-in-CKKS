package bench

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Plan creates public parameters and displays exact metadata trajectories.
// It performs NO key generation, encryption, decryption or circuit evaluation.
// An ideal-message range ratio is a diagnostic, not an error certificate.
func Plan(s *Suite) (map[string]any, error) {
	if e := s.Validate(); e != nil {
		return nil, e
	}
	var cases []any
	for _, c := range s.Cases {
		var branches []any
		for _, b := range c.Branches {
			ordinary := c.Kind == "ordinary_joint" || c.Kind == "ordinary_split"
			p, e := b.Parameters.Build()
			if e != nil {
				return nil, e
			}
			D := scale(pow2(b.ScaleBits))
			level := p.MaxLevel()
			amplitude := big.NewRat(7, 8)
			if s.Task == "mean16" && s.Entry == "native" {
				amplitude = big.NewRat(1, 16)
				if b.Layout == "real_imag" {
					amplitude = big.NewRat(1, 8) // sqrt(2)/16 < 1/8, both channels centred
				}
				if b.Paired() {
					amplitude = big.NewRat(99, 1120)
				}
			}
			rows := []any{}
			var graph *PolynomialGraph
			push := func(name string, restored bool) {
				row := map[string]any{"stage": name, "level": level, "q_components": level + 1, "scale_exact": scaleRat(D).RatString(), "q_exact": prod(p.Q()[:level+1]).String(), "ideal_logical_amplitude_all_physical_slots": amplitude.RatString()}
				if restored {
					row["ideal_logical_embedding_range_ratio_only"] = div(mul(ri(2), mul(scaleRat(D), amplitude)), new(big.Rat).SetInt(prod(p.Q()[:level+1]))).RatString()
				}
				rows = append(rows, row)
			}
			push("input", ordinary)
			if s.Task == "mean16" {
				amplitude = big.NewRat(1, 16)
				if b.Layout == "real_imag" {
					amplitude = big.NewRat(1, 8)
				}
				if b.Paired() {
					amplitude = big.NewRat(99, 1120)
				}
				if s.Entry == "existing" {
					if b.Group != "all" {
						// Subtracting the public centre also changes unused slots.
						amplitude = big.NewRat(13, 16)
					}
					push("after_center", ordinary)
				}
				divisor := int64(16)
				if b.Paired() {
					divisor = 32
				}
				D = D.Mul(scale(ri(divisor)))
				push("mean_before_restore", false)
			} else if b.Algorithm == "chebyshev6" {
				g, err := planPolynomialGraph(p, b)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", b.ID, err)
				}
				graph = &g
				state := g.Nodes[g.Output].State
				level = state.Level
				r, _ := new(big.Rat).SetString(state.Scale)
				D = scale(r)
				amplitude = powRat(big.NewRat(7, 8), 16)
				push("polynomial_official_scheduler_output", ordinary)
			} else {
				for k, n := range b.RescaleCounts {
					D = D.Mul(D)
					if c.Kind == "diagonal" {
						D = D.Mul(scale(pow2(c.MultiplierScaleBits)))
					}
					for j := 0; j < n; j++ {
						D = D.Div(rlwe.NewScale(p.Q()[level-j]))
					}
					level -= n
					amplitude = mul(amplitude, amplitude)
					push(fmt.Sprintf("square_%d", k+1), ordinary)
				}
			}
			if c.Kind == "diagonal" {
				D = D.Mul(scale(pow2(c.MultiplierScaleBits)))
				for j := 0; j < b.RestoreRescaleCount; j++ {
					D = D.Div(rlwe.NewScale(p.Q()[level-j]))
				}
				level -= b.RestoreRescaleCount
			}
			for j := 0; j < b.OutputRescaleCount; j++ {
				D = D.Div(rlwe.NewScale(p.Q()[level-j]))
			}
			level -= b.OutputRescaleCount
			level -= b.OutputDropPrimes
			push("final_restored_output", true)
			branches = append(branches, map[string]any{"id": b.ID, "group": b.Group, "layout": b.Layout, "parameters": paramReport(p), "metadata_trajectory": rows, "polynomial_graph": graph})
		}
		cases = append(cases, map[string]any{"id": c.ID, "kind": c.Kind, "parameter_status": c.ParameterStatus, "certificate_note": c.CertificateNote, "branches": branches})
	}
	return map[string]any{"suite": s.ID, "mode": "public_parameter_plan_only", "backend": Backend, "task": s.Task, "entry": s.Entry, "he_executions": 0, "certified": false, "security_target_bits": s.SecurityTarget, "security_assessment": s.SecurityAssessment, "cases": cases, "warning": "A metadata trajectory or ideal-message range ratio is not an error bound, a security estimate, or a performance result."}, nil
}
