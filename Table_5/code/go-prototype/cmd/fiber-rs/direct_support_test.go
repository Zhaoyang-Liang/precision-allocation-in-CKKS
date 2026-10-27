package main

import "testing"

func TestDirectModeIsSameSecretWithoutRingKeys(t *testing.T) {
	c := smallConfig()
	c.NoRS = true
	c.Logn = c.LogN
	c.ActiveBranches = 1
	c.ChainLength = 2
	c.ChainFactorShape = true
	c.ChainPhase = .1
	var r result
	if err := run(c, &r); err != nil {
		t.Fatal(err)
	}
	if r.Branches != 1 || r.EntryKeyBytes != 0 || r.ReturnKeyBytes != 0 || r.ApplicationKeyBytes != 0 {
		t.Fatal("direct mode must use one secret, no cross-ring keys, and reuse its relin key")
	}
	tr := r.Trials[0]
	if tr.OutputMetrics.MaxAbsError > 1e-3 || tr.ApplicationChain.FinalMetrics.MaxAbsError > 1e-3 {
		t.Fatal("direct mode arithmetic failed")
	}
	if tr.ApplicationChain.ExecutedSteps != 2 {
		t.Fatal("missing real multiplication chain")
	}
}

func TestDirectModeRejectsUnequalDimensions(t *testing.T) {
	c := smallConfig()
	c.NoRS = true
	if _, _, _, _, _, err := parameters(c); err == nil {
		t.Fatal("no-rs accepted different dimensions")
	}
	c.NoRS = false
	c.Logn = c.LogN
	if _, _, _, _, _, err := parameters(c); err == nil {
		t.Fatal("ring-switch mode silently accepted same ring")
	}
}
