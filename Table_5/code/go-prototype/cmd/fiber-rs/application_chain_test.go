package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedApplicationChainFromActualBootstrap(t *testing.T) {
	for _, shapeFactor := range []bool{true, false} {
		t.Run(map[bool]string{true: "shaped-factors", false: "ordinary-factors"}[shapeFactor], func(t *testing.T) {
			c := smallConfig()
			c.OutputLevel = 8
			c.Degree = 63
			c.Power = 1
			c.ShapeCtS = true
			c.CheckSquare = false
			c.Diagnostics = false
			c.ChainLength = -1
			c.ChainPhase = math.Pi / 16
			c.ChainFactorShape = shapeFactor
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
			if r.CasesChainComplete != 1 {
				t.Fatal("chain was not completed")
			}
			chain := r.Trials[0].ApplicationChain
			if chain.ExecutedSteps != 8 || chain.RequestedSteps != 8 || chain.Final.Level != 0 || !chain.ReachedLevelZero {
				t.Fatal("all eight real multiplications were not consumed")
			}
			firstMean := chain.Steps[0].ExpectedMeanMagnitude
			for i, s := range chain.Steps {
				if s.Input.Level != 8-i || s.ProductBeforeRescale.Level != 8-i || s.Output.Level != 7-i {
					t.Fatal("incorrect arithmetic level progression")
				}
				if s.Arithmetic.Relinearizations != 1 || s.Arithmetic.Rescales != 1 {
					t.Fatalf("step%d skipped real arithmetic: %+v", i, s.Arithmetic)
				}
				if math.Abs(s.Output.LogScale-35) > 1e-8 {
					t.Fatal("incorrect returned scale")
				}
				if math.Abs(s.ExpectedMeanMagnitude-firstMean) > 1e-14 {
					t.Fatal("reference magnitude changed")
				}
				if s.OutputMetrics.MaxAbsError > .001 {
					t.Fatal("bounded chain became incorrect")
				}
			}
			if chain.FinalMetrics.MaxAbsError > chain.InitialMetrics.MaxAbsError+1e-6 {
				t.Fatal("chain introduces excessive new error")
			}
			t.Logf("actual bootstrap %.6f bit -> 8 bounded multiplications %.6f bit; phase %.5f, factor shaped %v", chain.InitialMetrics.MaxErrorBits, chain.FinalMetrics.MaxErrorBits, c.ChainPhase, shapeFactor)
		})
	}
}
