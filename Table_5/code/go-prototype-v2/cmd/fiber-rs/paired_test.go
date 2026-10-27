package main

import (
	"runtime"
	"testing"
)

func TestPairedTimingSkipsDummyBranches(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	c := smallConfig()
	c.PCount = 1
	c.SSEBase = 14
	c.MainBase = 14
	c.PairedTiming = true
	c.ActiveBranches = 1
	c.Workers = 1
	c.Trials = 2
	var r result
	if err := run(c, &r); err != nil {
		t.Fatal(err)
	}
	if r.CasesFailed != 0 {
		t.Fatalf("cases failed: %+v", r.Trials)
	}
	for _, tr := range r.Trials {
		if tr.OutputMetrics.MaxAbsError > 1e-3 {
			t.Fatalf("unhoisted matrix precision failed: %g", tr.OutputMetrics.MaxAbsError)
		}
		if !tr.PairedCiphertextsEqual || tr.RefreshedBranches != 1 || len(tr.SkippedBranchIndices) != 1 || tr.SerialOnlineSeconds <= 0 || tr.ParallelOnlineSeconds <= 0 {
			t.Fatalf("bad paired result: %+v", tr)
		}
	}
}

// A good useful-slot bootstrap error is not sufficient: return-switch noise
// on guards must also fit the real residual-prime application arithmetic.
func TestSmallPReturnGuardAllowsSquare(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	c := smallConfig()
	c.R = 8
	c.Power = 1
	c.UnitFile = "../../../units/R8-s40-calibrated.json"
	c.PBits = 26
	c.PCount = 1
	c.MainBase = 14
	c.SSEBase = 14
	c.OutputLevel = 1
	c.OutputBits = 30
	c.EMBits = 25
	c.EvalQBits = 25
	c.ActiveBranches = 1
	c.Workers = 1
	c.PairedTiming = true
	c.Trials = 2
	c.ShapeCtS = true
	var r result
	if err := run(c, &r); err != nil {
		t.Fatal(err)
	}
	for _, tr := range r.Trials {
		if tr.Error != "" || !tr.PairedCiphertextsEqual || tr.AfterSquare.Level != 0 || tr.SquareMetrics.MaxAbsError > 1e-5 || tr.OutputMetrics.GuardMax > 1 || tr.SquareMetrics.GuardMax > 1 {
			t.Fatalf("small-P return/application failed: %+v", tr)
		}
	}
}
