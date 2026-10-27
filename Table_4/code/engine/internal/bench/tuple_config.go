package bench

import (
	"ckks-precision-experiments/neighbor"
	"encoding/json"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math/big"
	"os"
)

type TupleCase struct {
	ID            string      `json:"id"`
	Kind          string      `json:"kind"`
	Extended      ParamSpec   `json:"extended_parameters"`
	ScaleBits     int         `json:"scale_bits"`
	RescaleCounts []int       `json:"rescale_counts"`
	Low           *BranchSpec `json:"ordinary_low,omitempty"`
	RelinStorage  string      `json:"relinearization_storage,omitempty"`
}
type TupleSuite struct {
	ID         string      `json:"id"`
	GroupSize  int         `json:"group_size"`
	Targets    [2]int      `json:"target_bits_low_high"`
	Seed       string      `json:"plaintext_seed"`
	Precision  uint        `json:"encoder_decode_bits"`
	GOMAXPROCS int         `json:"gomaxprocs"`
	Cases      []TupleCase `json:"cases"`
}

func LoadTuple(path string) (*TupleSuite, []byte, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, e
	}
	var s TupleSuite
	if e = json.Unmarshal(b, &s); e != nil {
		return nil, nil, e
	}
	if s.GroupSize != 8192 || (s.Targets != [2]int{22, 72} && s.Targets != [2]int{32, 112}) || s.Precision < 256 {
		return nil, nil, fmt.Errorf("planning supports 8192/group, 72/22 or public-only 112/32, precision>=256")
	}
	seen := map[string]bool{}
	for _, c := range s.Cases {
		if seen[c.ID] || c.ID == "" {
			return nil, nil, fmt.Errorf("duplicate/empty case")
		}
		seen[c.ID] = true
		ctx, contextErr := tupleContext(c)
		if contextErr != nil {
			e = contextErr
			return nil, nil, fmt.Errorf("%s: %w", c.ID, e)
		}
		if c.RelinStorage != "" && (c.RelinStorage != "shared_single_p" || ctx.Extended.PCount() != 1) {
			return nil, nil, fmt.Errorf("unsupported Tuple relinearization storage")
		}
		if c.Kind == "tuple_high_ordinary_low" {
			if c.Low == nil || c.Low.Group != "low" || c.Low.Layout != "compact" || len(c.Low.RescaleCounts) != 4 {
				return nil, nil, fmt.Errorf("missing ordinary low branch")
			}
			if c.Low.Algorithm != "" && c.Low.Algorithm != "square_chain" || c.Low.OutputDropPrimes != 0 || c.Low.OutputRescaleCount != 0 || c.Low.RestoreRescaleCount != 0 {
				return nil, nil, fmt.Errorf("unsupported low algorithm/output adjustment")
			}
			p, e := c.Low.Parameters.Build()
			if e != nil {
				return nil, nil, e
			}
			sum := 0
			for _, v := range c.Low.RescaleCounts {
				if v < 0 {
					return nil, nil, fmt.Errorf("negative low rescale")
				}
				sum += v
			}
			if sum > p.MaxLevel() {
				return nil, nil, fmt.Errorf("low chain exhausted")
			}
			if p.MaxSlots() < s.GroupSize {
				return nil, nil, fmt.Errorf("low capacity")
			}
		} else if c.Kind != "tuple_joint" || c.Low != nil {
			return nil, nil, fmt.Errorf("invalid Tuple organization")
		}
	}
	return &s, b, nil
}
func tupleContext(c TupleCase) (*neighbor.Context, error) {
	p, e := c.Extended.Build()
	if e != nil {
		return nil, e
	}
	if len(p.Q()) < 2 || len(c.RescaleCounts) != 4 || c.ScaleBits <= 0 {
		return nil, fmt.Errorf("invalid Tuple chain")
	}
	l := p.ParametersLiteral()
	qd := l.Q[0]
	l.Q = l.Q[1:]
	base, e := ckks.NewParametersFromLiteral(l)
	if e != nil {
		return nil, e
	}
	cnt := 0
	for _, n := range c.RescaleCounts {
		if n < 0 {
			return nil, fmt.Errorf("negative rescale")
		}
		cnt += n
	}
	if cnt > base.MaxLevel() {
		return nil, fmt.Errorf("Tuple exhausts base modulus")
	}
	need := 8192
	if c.Kind == "tuple_joint" {
		need *= 2
	}
	if base.MaxSlots() < need {
		return nil, fmt.Errorf("Tuple slot capacity")
	}
	return neighbor.NewContext(base, qd)
}
func securityCap(p ckks.Parameters) bool {
	cap := map[int]uint{8192: 218, 16384: 438, 32768: 881}[p.N()]
	return cap > 0 && new(big.Int).Mul(prod(p.Q()), prod(p.P())).Cmp(new(big.Int).Lsh(big.NewInt(1), cap)) < 0
}
func TuplePlan(s *TupleSuite) (map[string]any, error) {
	var rows []any
	for _, c := range s.Cases {
		ctx, e := tupleContext(c)
		if e != nil {
			return nil, e
		}
		D := scale(pow2(c.ScaleBits))
		level := ctx.Base.MaxLevel()
		stages := []any{map[string]any{"stage": "input", "level": level, "scale_exact": scaleRat(D).RatString()}}
		for k, n := range c.RescaleCounts {
			D = D.Mul(D).Div(rlwe.NewScale(ctx.QDiv))
			for j := 0; j < n; j++ {
				D = D.Div(rlwe.NewScale(ctx.Base.Q()[level-j]))
			}
			level -= n
			stages = append(stages, map[string]any{"stage": fmt.Sprintf("square_%d", k+1), "level": level, "scale_exact": scaleRat(D).RatString()})
		}
		row := map[string]any{"id": c.ID, "kind": c.Kind, "base": paramReport(ctx.Base), "extended": paramReport(ctx.Extended), "q_div": fmt.Sprint(ctx.QDiv), "context_id": ctx.ID, "trajectory": stages, "security_cap_pass": securityCap(ctx.Extended), "key_organization": "one extended public key; one base and one extended relinearization key, each reused at all prefix levels"}
		if c.RelinStorage == "shared_single_p" {
			row["key_organization"] = "one extended relinearization owner; base is a read-only single-P projected view, no separate coefficient storage or transmission"
		}
		if c.Low != nil {
			lo, e := c.Low.Parameters.Build()
			if e != nil {
				return nil, e
			}
			row["ordinary_low"] = paramReport(lo)
			dl := scale(pow2(c.Low.ScaleBits))
			ll := lo.MaxLevel()
			trajectory := []any{map[string]any{"stage": "input", "scale_exact": scaleRat(dl).RatString(), "level": ll}}
			for k, n := range c.Low.RescaleCounts {
				dl = dl.Mul(dl)
				for j := 0; j < n; j++ {
					dl = dl.Div(rlwe.NewScale(lo.Q()[ll-j]))
				}
				ll -= n
				trajectory = append(trajectory, map[string]any{"stage": fmt.Sprintf("square_%d", k+1), "scale_exact": scaleRat(dl).RatString(), "level": ll})
			}
			row["ordinary_low_trajectory"] = trajectory
			row["ordinary_low_security_cap_pass"] = securityCap(lo)
			row["ordinary_low_can_reuse_base_evalkey"] = compatiblePrefix(ctx.Base, lo)
		}
		rows = append(rows, row)
	}
	return map[string]any{"HE_executions": 0, "backend": Backend, "suite": s.ID, "cases": rows, "scope": "public plan, conditional certificates generated separately"}, nil
}
