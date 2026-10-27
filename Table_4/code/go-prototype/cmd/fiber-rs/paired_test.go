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
		if !tr.PairedCiphertextsEqual || tr.RefreshedBranches != 1 || len(tr.SkippedBranchIndices) != 1 || tr.SerialOnlineSeconds <= 0 || tr.ParallelOnlineSeconds <= 0 {
			t.Fatalf("bad paired result: %+v", tr)
		}
	}
}
