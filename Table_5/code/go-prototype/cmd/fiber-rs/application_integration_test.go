package main

// Independent integration checks. Run Go compilation and all HE tests on HPC;
// local review of this file only used gofmt parsing and mathematical checks.

import (
	"encoding/json"
	"math"
	"math/cmplx"
	"os"
	"path/filepath"
	"testing"
)

func TestDenseStatisticsReductionLayout(t *testing.T) {
	// Every original dense slot contributes once to exactly one focus group.
	// This independent vector reduction models the documented rotation order.
	for _, R := range []int{2, 8, 16} {
		S, k := 1024, max(8, R)
		values, expected := make([]complex128, S), make([]float64, k)
		for j := range values {
			x := .01 + float64((17*j+3)%101)/73
			values[j] = complex(x*x, 0)
			expected[(j/R)%k] += x * x
		}
		addRotation := func(offset int) {
			before := append([]complex128(nil), values...)
			for j := range values {
				values[j] += before[(j+offset)%S]
			}
		}
		for step := k * R; step < S; step *= 2 {
			addRotation(step)
		}
		for step := 1; step < R; step *= 2 {
			addRotation(step)
		}
		masked := make([]complex128, S)
		for j := 0; j < S; j += R {
			group := (j / R) % k
			if cmplx.Abs(values[j]-complex(expected[group], 0)) > 1e-10 {
				t.Fatalf("R%d focus%d sum uses wrong group", R, j)
			}
			masked[j] = values[j] / complex(32*float64(S/k), 0)
		}
		for j := range masked {
			if cmplx.Abs(masked[j]-masked[(j+k*R)%S]) > 1e-14 || cmplx.Abs(masked[j]-masked[(j+S/2)%S]) > 1e-14 {
				t.Fatalf("R%d output not period kR/even branch", R)
			}
			if j%R != 0 && masked[j] != 0 {
				t.Fatal("ideal guard not zero")
			}
		}
	}
}

func TestInverseSqrtPlannerRealPrimeRecurrence(t *testing.T) {
	// Parameter generation only; no HE. This checks the planner against a
	// separate simulation of the actual DAG, including the y path's levels.
	for _, bits := range []int{30, 32, 40} {
		c := smallConfig()
		c.LogN, c.Logn, c.OutputLevel, c.OutputBits = 16, 15, 13, bits
		_, p, _, _, _, err := parameters(c)
		if err != nil {
			t.Fatal(err)
		}
		start := inverseSqrtInitialLogScale(p.Q(), 13, 7, float64(bits))
		aScale, yScale, aLevel, yLevel := start, start, 13, 12
		for i := 2; i <= 7; i++ {
			square := 2*aScale - math.Log2(float64(p.Q()[aLevel]))
			aScale = square + aScale - math.Log2(float64(p.Q()[aLevel-1]))
			aLevel -= 2
			level := min(aLevel, yLevel)
			yScale += aScale - math.Log2(float64(p.Q()[level]))
			yLevel = level - 1
			if aScale < 20 {
				t.Fatalf("calibrated %dbit case has low masked-constant scale %g", bits, aScale)
			}
		}
		if aLevel != 1 || yLevel != 0 || math.Abs(yScale-float64(bits)) > 1e-8 {
			t.Fatalf("real prime DAG did not end at target: start%g final%g", start, yScale)
		}
	}
}

func TestDenseStatisticsInverseRMSBeforeReturnIntegration(t *testing.T) {
	c := smallConfig()
	c.ActiveBranches = 1
	c.Statistics = true
	c.ApplicationBeforeReturn = true
	c.CalibrateApplicationScale = true
	c.InverseSqrtIterations = 7
	c.OutputLevel, c.OutputBits = 13, 40
	c.Degree, c.Power = 63, 1
	c.ShapeCtS, c.CheckSquare, c.Diagnostics = true, false, true
	c.ChainLength = 0
	u := unitSpec{R: 2, Coeffs: []string{"-239", "169", "0", "-169"}, Inverse: []string{"239", "169", "0", "-169"}, Focus: "0.002092041053063247485394391438975278274546938704224366858875720433788860096089565715493301371425792217"}
	c.UnitFile = filepath.Join(t.TempDir(), "unit.json")
	b, err := json.Marshal([]unitSpec{u})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.UnitFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	var r result
	if err = run(c, &r); err != nil {
		t.Fatal(err)
	}
	if r.CasesFailed != 0 || len(r.Trials) != 1 || r.ReturnKeyLevel != 0 {
		t.Fatal("missing completed pipeline/final-level return key")
	}
	tr := r.Trials[0]
	f, app := tr.Frontend, tr.InverseSqrt
	if f.TotalSamples != 1<<(c.LogN-1) || f.Groups != c.KMessages || f.SamplesPerGroup*f.Groups != f.TotalSamples || !f.IdealOddBranchIsZero {
		t.Fatal("frontend was not dense or did not produce the closed layout")
	}
	if f.InputMetrics.DataSlots != f.TotalSamples || f.SquaredMetrics.DataSlots != f.TotalSamples {
		t.Fatal("dense-input diagnostics did not inspect every original slot")
	}
	if f.Input.Level != 3 || f.AfterSquare.Level != 2 || f.Output.Level != 1 || math.Abs(f.Output.LogScale-40) > 1e-8 || f.FinalArithmetic.Rescales != 1 {
		t.Fatal("frontend skipped actual levels or output scale mismatch")
	}
	if tr.PreBootstrap.Level != f.Output.Level || tr.PreBootstrap.LogScale != f.Output.LogScale || tr.PreBootstrap.LogQ != f.Output.LogQ {
		t.Fatal("bootstrap did not receive the frontend output state")
	}
	if tr.RefreshedBranches != 1 || len(tr.SkippedBranchIndices) != 1 || tr.SkippedBranchIndices[0] != 1 {
		t.Fatal("dummy branch was not skipped")
	}
	if tr.Output.Level != 13 || tr.Branches[0].Output.Level != 13 || app.Initial.Level != 13 || tr.Final.Level != 0 || app.Final.Level != 0 {
		t.Fatal("bootstrap diagnostics were overwritten by application/return output")
	}
	if !app.Completed || app.RequiredLevels != 13 || app.ConsumedLevels != 13 || app.Arithmetic.Rescales != 19 || app.Arithmetic.Relinearizations != 18 {
		t.Fatalf("inverse RMS did not perform the real 13-level/19-rescale DAG: %+v", app.Arithmetic)
	}
	if math.Abs(app.Final.LogScale-40) > 1e-7 || math.Abs(tr.Final.LogScale-app.Final.LogScale) > 1e-8 {
		t.Fatal("actual calibrated application/return scale mismatch")
	}
	if app.IdealTruncationBound > 2e-12 || app.ActualReferenceTruncationMax > app.IdealTruncationBound+1e-14 {
		t.Fatal("seven-step exact-function approximation bound failed")
	}
	if app.SeedConstantEncodingMetrics.MaxAbsError > 1e-8 {
		t.Fatal("scalar seed diagnostic must decode every repeated focus slot")
	}
	if tr.FinalMetrics.MaxAbsError > 1e-3 {
		t.Fatalf("integrated inverse RMS error too large: %g", tr.FinalMetrics.MaxAbsError)
	}
	if tr.FinalMeetsTarget != (tr.FinalMetrics.MaxAbsError <= math.Exp2(-float64(c.TargetBits))) {
		t.Fatal("20bit success label does not use returned original-function error")
	}
	if math.Abs(tr.FinalMetrics.MaxErrorBits-bitsError(tr.FinalMetrics.MaxAbsError)) > 1e-8 {
		t.Fatal("reported returned precision disagrees with actual error")
	}
	wantPipeline := f.OnlineSeconds + tr.EntrySplitSeconds + tr.LeafsSeconds + tr.MergeReturnSeconds + app.ArithmeticSeconds
	if math.Abs(tr.PipelineOnlineSeconds-wantPipeline) > 1e-8 {
		t.Fatal("online timing omits or double counts the application")
	}
	for _, stage := range app.Stages {
		if stage.HasEncodedConstant && stage.ConstantLogScale < 20 {
			t.Fatal("masked constant used an inadequately represented scale")
		}
	}
	t.Logf("dense%d -> %d MSE -> bootstrapL13 -> inverse RMS13 levels -> returnedL0; boot%.5f bit, leaf function%.5f bit, returned function%.5f bit; mean-square unscaled%.5f bit", f.TotalSamples, f.Groups, tr.OutputMetrics.MaxErrorBits, app.FinalMetrics.MaxErrorBits, tr.FinalMetrics.MaxErrorBits, f.MeanSquareWorstBits)
}
