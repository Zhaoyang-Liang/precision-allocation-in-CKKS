package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func baseConfig() config {
	return config{LogN: 7, R: 1, Power: 1, Trials: 1, TargetBits: 20, FreshLevel: 2, OutputLevel: 1, InputBits: 21, OutputBits: 30, EMBits: 40, OutputPrimeBits: 30, Degree: 63, DoubleAngle: 3, InverseDegree: 7, K: 17, RatioBits: 4, MainH: 64, SparseH: 8, MainBase: 9, EntryBase: 1, Q0: 7340033, Qout: 786433, MainP: 65537, SmallP: 8191, WorkPrime: 5767169, ChainMode: "uniform", Mod1Family: "continuous", Seed: 29, Amplitude: .01, Diagnostics: true}
}
func TestParameterLedgerAccountsInverseAndResidualLevels(t *testing.T) {
	c := baseConfig()
	p, lit, e := parameters(c)
	if e != nil {
		t.Fatal(e)
	}
	if p.MaxLevel() != lit.Depth()+c.OutputLevel {
		t.Fatalf("maxlevel %d != depth+output %d", p.MaxLevel(), lit.Depth()+c.OutputLevel)
	}
	old := c
	old.InverseDegree = 0
	_, oldLit, e := parameters(old)
	if e != nil {
		t.Fatal(e)
	}
	if lit.Depth()-oldLit.Depth() != 3 {
		t.Fatalf("degree7 inverse must add three levels; got %d", lit.Depth()-oldLit.Depth())
	}
	if p.Q()[0] != c.Q0 || p.Q()[1] != c.Qout {
		t.Fatal("output prefix changed")
	}
}
func TestDirectSameRingInversePolynomialAndModulusLedger(t *testing.T) {
	c := baseConfig()
	c.UnitFile = filepath.Join(t.TempDir(), "units.json")
	b, _ := json.Marshal([]unitSpec{{R: 1, Coeffs: []string{"1", "0"}, Inverse: []string{"1", "0"}, Focus: "1"}})
	if e := os.WriteFile(c.UnitFile, b, 0600); e != nil {
		t.Fatal(e)
	}
	var res result
	if e := run(c, &res); e != nil {
		t.Fatal(e)
	}
	if res.RingSwitching || res.CasesExecuted != 1 || res.InverseDepth != 3 {
		t.Fatal("wrong direct/inverse result")
	}
	tr := res.Trials[0]
	if tr.Fresh.Level != 2 || tr.PreBootstrap.Level != 0 || tr.Output.Level != 1 {
		t.Fatalf("incorrect modulus states: %+v %+v %+v", tr.Fresh, tr.PreBootstrap, tr.Output)
	}
	if !tr.FreshQGreaterThanOutputQ || tr.PreBootstrapQGreaterThanOutputQ || !tr.InternalQGreaterThanOutputQ {
		t.Fatal("incorrect Q comparisons")
	}
	if tr.OutputMetrics.MaxAbsError > 1e-3 || math.IsNaN(tr.OutputMetrics.MaxAbsError) {
		t.Fatalf("real encrypted direct output incorrect: %.9g", tr.OutputMetrics.MaxAbsError)
	}
	if len(tr.Stages) == 0 {
		t.Fatal("missing diagnostics")
	}
	found := false
	for _, s := range tr.Stages {
		if s.Name == "evalmod_inverse_polynomial" {
			found = true
		}
	}
	if !found {
		t.Fatal("arcsine was not executed")
	}
	t.Logf("direct same-ring arcsine output precision %.5f bits, inputQ %.5f outputQ %.5f internalQ %.5f", tr.OutputMetrics.MaxErrorBits, tr.PreBootstrap.LogQ, tr.Output.LogQ, tr.InternalMaximum.LogQ)
}

// The old inverse schedule used the final beta*Delta scale for the sine
// intermediate. On the actual 17--21-bit Q limbs this requires coefficient
// scales below one. A separately targeted sine scale is a genuine arithmetic
// change, keeping the same depth, Q primes and output scale.
func TestInverseIntermediateScaleOnServerChain(t *testing.T) {
	c := baseConfig()
	c.LogN = 8
	c.R = 8
	c.MainH = 128
	c.SparseH = 16
	c.FreshLevel = 0
	c.InputBits = 21
	c.OutputBits = 21
	c.EMBits = 20
	c.Degree = 31
	c.InverseInputBits = 20
	c.QChain = "7340033,786433,114689,147457,163841,557057,638977,737281,1032193,1097729,1130497,1146881,1179649"
	c.UnitFile = "../../units-weak.json"
	c.Amplitude = .2
	c.Diagnostics = true
	var res result
	if e := run(c, &res); e != nil {
		t.Fatal(e)
	}
	tr := res.Trials[0]
	if tr.Output.Level != 1 || math.Abs(tr.Output.LogScale-21) > 1e-8 {
		t.Fatal("output level/scale changed")
	}
	found := false
	for _, s := range tr.Stages {
		if s.Name == "evalmod_da_3" {
			found = true
			if math.Abs(s.State.LogScale-20) > 1e-8 {
				t.Fatalf("sine scale is not actually 2^20: %g", s.State.LogScale)
			}
		}
	}
	if !found {
		t.Fatal("missing intermediate stage")
	}
	if tr.Arithmetic.SubunitCoefficientProducts != 0 {
		t.Fatal("unexpected subunit coefficient product")
	}
	if tr.OutputMetrics.MaxAbsError > .001 {
		t.Fatalf("incorrect direct inverse output: %g", tr.OutputMetrics.MaxAbsError)
	}
	t.Logf("same Q/depth intermediate-scale repair: %.4f bits, QP %.4f", tr.OutputMetrics.MaxErrorBits, res.MainQPBits)
}
