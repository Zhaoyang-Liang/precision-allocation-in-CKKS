package main

import (
	"math"
	"testing"
)

func smallConfig() config {
	return config{LogN: 9, Logn: 8, KMessages: 8, R: 2, Power: 0, Trials: 1, Workers: 2, OutputLevel: 3, Q0Bits: 50, InputBits: 40, OutputBits: 35, EMBits: 40, EvalQBits: 40, CtSQBits: 61, PBits: 55, PCount: 2, Degree: 31, DA: 3, KMod1: 17, RatioBits: 4, SparseH: 16, TargetBits: 20, Seed: 731, Amplitude: .1, CheckSquare: true, Diagnostics: true, ShapeEntry: true}
}
func TestFiberDriverModulusLedger(t *testing.T) {
	c := smallConfig()
	c.DryRun = true
	var r result
	if e := run(c, &r); e != nil {
		t.Fatal(e)
	}
	if r.MainLevel != c.OutputLevel+r.EvalModDepth+1 || r.EvalModLevel != c.OutputLevel+r.EvalModDepth || r.InputLevel != 1 || r.OutputLevel != 3 {
		t.Fatal("wrong depth/level ledger")
	}
	if math.Abs(r.OutputQBits-r.InputQBits-70) > 1e-3 {
		t.Fatalf("unexpected restored Q %g", r.OutputQBits-r.InputQBits)
	}
}
func TestFiberDriverFullEncryptedSmallRing(t *testing.T) {
	c := smallConfig()
	var r result
	if e := run(c, &r); e != nil {
		t.Fatal(e)
	}
	if r.CasesExecuted != 1 || r.CasesFailed != 0 || len(r.Trials) != 1 {
		t.Fatal("missing executed result")
	}
	tr := r.Trials[0]
	if tr.Output.Level != 3 || tr.AfterSquare.Level != 2 || len(tr.Branches) != 2 {
		t.Fatal("wrong output or square level")
	}
	for _, b := range tr.Branches {
		if b.StC.Level != 0 || b.SSE.Level != 0 || b.CtSReal.Level != r.EvalModLevel {
			t.Fatal("wrong intermediate levels")
		}
		if len(b.Stages) == 0 {
			t.Fatal("missing stage diagnostics")
		}
	}
	t.Logf("input %.5f bit, output %.5f bit, square %.5f bit, Q %.4f -> %.4f", tr.InputMetrics.MaxErrorBits, tr.OutputMetrics.MaxErrorBits, tr.SquareMetrics.MaxErrorBits, tr.PreBootstrap.LogQ, tr.Output.LogQ)
	if tr.OutputMetrics.MaxAbsError > 1e-3 {
		t.Fatalf("full circuit error too large: %g", tr.OutputMetrics.MaxAbsError)
	}
}
