package main

import (
	"runtime"
	"testing"
)

func TestPairedDirectTiming(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	c := baseConfig()
	c.R = 8
	c.UnitFile = "../../units-weak.json"
	c.PairedTiming = true
	c.Trials = 2
	var r result
	if err := run(c, &r); err != nil {
		t.Fatal(err)
	}
	if r.CasesFailed != 0 {
		t.Fatalf("cases failed: %+v", r.Trials)
	}
	for _, tr := range r.Trials {
		if !tr.PairedCiphertextsEqual || tr.SerialOnlineSeconds <= 0 || tr.ParallelOnlineSeconds <= 0 {
			t.Fatalf("bad pair: %+v", tr)
		}
	}
}
