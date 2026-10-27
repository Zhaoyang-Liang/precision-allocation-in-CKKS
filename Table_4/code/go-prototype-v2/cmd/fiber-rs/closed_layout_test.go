package main

import (
	"encoding/json"
	"math"
	"math/cmplx"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

func TestClosedPublicZeroCiphertext(t *testing.T) {
	p, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 8, LogQ: []int{50, 35}, LogDefaultScale: 35})
	if e != nil {
		t.Fatal(e)
	}
	reference := ckks.NewCiphertext(p, 1, 1)
	reference.Scale = rlwe.NewScale(math.Exp2(34.25))
	zero := zeroCiphertextLike(p, reference)
	if zero.Degree() != 1 || zero.Level() != 1 || !zero.Scale.Equal(reference.Scale) || zero.IsNTT != reference.IsNTT {
		t.Fatal("zero ciphertext metadata mismatch")
	}
	for _, poly := range zero.Value {
		for _, coeffs := range poly.Coeffs {
			for _, v := range coeffs {
				if v != 0 {
					t.Fatal("zero has nonzero residue")
				}
			}
		}
	}
	zero.Scale = zero.Scale.Mul(rlwe.NewScale(2))
	if zero.Scale.Equal(reference.Scale) {
		t.Fatal("metadata alias")
	}
}
func TestClosedSingleBranchBootstrapAndAllLevels(t *testing.T) {
	c := smallConfig()
	c.ActiveBranches = 1
	c.OutputLevel = 8
	c.Degree = 63
	c.Power = 1
	c.ShapeCtS = true
	c.CheckSquare = true
	c.Diagnostics = true
	c.ChainLength = -1
	c.ChainPhase = math.Pi / 16
	c.ChainFactorShape = true
	u := unitSpec{R: 2, Coeffs: []string{"-239", "169", "0", "-169"}, Inverse: []string{"239", "169", "0", "-169"}, Focus: "0.002092041053063247485394391438975278274546938704224366858875720433788860096089565715493301371425792217"}
	c.UnitFile = filepath.Join(t.TempDir(), "unit.json")
	b, _ := json.Marshal([]unitSpec{u})
	if e := os.WriteFile(c.UnitFile, b, 0600); e != nil {
		t.Fatal(e)
	}
	var r result
	if e := run(c, &r); e != nil {
		t.Fatal(e)
	}
	tr := r.Trials[0]
	if r.LogicalMessages != 8 || r.ActiveBranches != 1 || tr.RefreshedBranches != 1 || len(tr.SkippedBranchIndices) != 1 || tr.SkippedBranchIndices[0] != 1 || !tr.Branches[1].Skipped {
		t.Fatal("incorrect public support accounting")
	}
	if tr.Branches[1].OutputMetrics.MaxAbsError != 0 || tr.Branches[1].Output.Level != 8 {
		t.Fatal("skipped branch is not ideal zero at correct level")
	}
	if tr.AfterSquare.Level != 7 || tr.ApplicationChain.ExecutedSteps != 8 || !tr.ApplicationChain.ReachedLevelZero {
		t.Fatal("missing real square or full chain")
	}
	if tr.OutputMetrics.MaxAbsError > 1e-3 || tr.SquareMetrics.MaxAbsError > 1e-3 || tr.ApplicationChain.FinalMetrics.MaxAbsError > 1e-3 {
		t.Fatal("closed branch arithmetic inaccurate")
	}
	t.Logf("one active/%d skipped, bootstrap %.5f bits, square %.5f, all8 chain %.5f", len(tr.SkippedBranchIndices), tr.OutputMetrics.MaxErrorBits, tr.SquareMetrics.MaxErrorBits, tr.ApplicationChain.FinalMetrics.MaxErrorBits)
}
func applyDiagonals(d lintrans.Diagonals[complex128], v []complex128) []complex128 {
	out := make([]complex128, len(v))
	for offset, diag := range d {
		for j := range out {
			out[j] += diag[j] * v[(j+offset)%len(v)]
		}
	}
	return out
}
func fiberPlainRoundTrip(v []complex128, k, R int) ([]complex128, error) {
	d, e := lb.FiberDiagonals(len(v), k, R, false, 1)
	if e != nil {
		return nil, e
	}
	forward := applyDiagonals(d, v)
	traced := make([]complex128, len(v))
	D := len(v) / k
	for j := range traced {
		for r := 0; r < D; r++ {
			traced[j] += forward[(j+r*k)%len(v)] / complex(float64(D), 0)
		}
	}
	inv, e := lb.FiberDiagonals(len(v), k, R, true, 1)
	if e != nil {
		return nil, e
	}
	return applyDiagonals(inv, traced), nil
}
func TestClosedMultiplicationAndSecondFiberReadout(t *testing.T) {
	top, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 9, LogQ: []int{50, 45}, LogDefaultScale: 40})
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 8, Q: top.Q(), LogDefaultScale: 40})
	if e != nil {
		t.Fatal(e)
	}
	k, R := 8, 2
	for _, active := range []int{1, 2} {
		values := make([][]complex128, 2)
		plains := make([]*rlwe.Ciphertext, 2)
		for b := range values {
			values[b] = make([]complex128, leaf.MaxSlots())
			if b < active {
				for j := 0; j < leaf.MaxSlots(); j += R {
					a := float64((j/R)%k + 1)
					values[b][j] = complex(.02*a+.01*float64(b), .013*a-.025*float64(b))
				}
			}
			plains[b], e = plainCipher(leaf, values[b], 1, rlwe.NewScale(math.Exp2(40)))
			if e != nil {
				t.Fatal(e)
			}
		}
		merged, e := lb.MergeCoefficientBranches(top, leaf, plains)
		if e != nil {
			t.Fatal(e)
		}
		squared := merged.CopyNew()
		mont := merged.Value[0].CopyNew()
		top.RingQ().MForm(*mont, *mont)
		top.RingQ().MulCoeffsMontgomery(merged.Value[0], *mont, squared.Value[0])
		squared.Scale = merged.Scale.Mul(merged.Scale)
		split, e := lb.SplitCoefficientBranches(top, leaf, squared)
		if e != nil {
			t.Fatal(e)
		}
		branch, e := decodePlain(leaf, split[0])
		if e != nil {
			t.Fatal(e)
		}
		read, e := fiberPlainRoundTrip(branch, k, R)
		if e != nil {
			t.Fatal(e)
		}
		periodErr, readErr, originalSquareErr := 0.0, 0.0, 0.0
		for j := 0; j < len(branch); j += R {
			periodErr = math.Max(periodErr, cmplx.Abs(branch[j]-branch[(j+k*R)%len(branch)]))
			readErr = math.Max(readErr, cmplx.Abs(read[j]-branch[j]))
			originalSquareErr = math.Max(originalSquareErr, cmplx.Abs(branch[j]-values[0][j]*values[0][j]))
		}
		if active == 1 {
			if periodErr > 1e-8 || readErr > 1e-8 || originalSquareErr > 1e-8 {
				t.Fatalf("single-branch closure failed: period%g readout%g square%g", periodErr, readErr, originalSquareErr)
			}
		} else {
			if periodErr < 1e-4 || readErr < 1e-4 {
				t.Fatal("counterexample did not expose double-branch closure loss")
			}
		}
		t.Logf("active%d: after top square branch0 periodic defect %.6g, second fiber readout error %.6g", active, periodErr, readErr)
	}
}
