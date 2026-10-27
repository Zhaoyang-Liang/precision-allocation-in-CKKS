package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
	"math"
	"math/big"
	"math/cmplx"
	"testing"
)

// Test the capacity probe independently of existing bootstrap tests. The
// negative fixture must fail precision even though its level count is correct.
func TestPhaseChainConsumesRealLevelsWithoutSignalDecay(t *testing.T) {
	for _, tc := range []struct {
		name      string
		qs        []uint64
		bits      int
		pass      bool
		operation string
	}{
		{"usable", []uint64{7340033, 786433, 1073748737}, 18, true, "phase"},
		{"wrap-at-last-level", []uint64{7340033, 786433, 1073748737}, 30, false, "phase"},
		{"successive-squares", []uint64{7340033, 114689, 786433}, 18, true, "square"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 7, Q: tc.qs, LogP: []int{40}, LogDefaultScale: tc.bits})
			if err != nil {
				t.Fatal(err)
			}
			kg := rlwe.NewKeyGenerator(p)
			sk := kg.GenSecretKeyNew()
			keys := rlwe.NewMemEvaluationKeySet(kg.GenRelinearizationKeyNew(sk))
			unit := make([]*big.Int, p.N())
			for i := range unit {
				unit[i] = new(big.Int)
			}
			unit[0].SetInt64(1)
			ev, err := lb.NewShapedEvaluator(p, ckks.NewEvaluator(p, keys), unit, unit, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			pt := ckks.NewPlaintext(p, 2)
			pt.Scale = rlwe.NewScale(math.Exp2(float64(tc.bits)))
			values := make([]complex128, p.MaxSlots())
			z := cmplx.Exp(complex(0, math.Pi/7))
			for i := range values {
				values[i] = z
			}
			if err = ckks.NewEncoder(p, 128).Encode(values, pt); err != nil {
				t.Fatal(err)
			}
			ct, err := rlwe.NewEncryptor(p, sk).EncryptNew(pt)
			if err != nil {
				t.Fatal(err)
			}
			c := config{R: 1, OutputBits: tc.bits, TargetBits: 8, ChainLength: -1, ChainOperation: tc.operation}
			a, err := runPhaseChain(p, sk, ev, ct, z, c)
			if err != nil {
				t.Fatal(err)
			}
			if a.ExecutedSteps != 2 || a.Final.Level != 0 || a.EveryOutputMeetsTarget != tc.pass {
				t.Fatalf("bad chain: %+v", a)
			}
			for _, s := range a.Steps {
				if s.Output.Level != s.Input.Level-1 || s.Arithmetic.Rescales != 1 || s.Arithmetic.Relinearizations != 1 {
					t.Fatal("not a real single-level multiplication")
				}
				if math.Abs(s.ExpectedMagnitude-1) > 1e-12 || math.Abs(s.Product.LogScale-s.Input.LogScale-s.Factor.LogScale) > 1e-9 {
					t.Fatal("reference/scale mismatch")
				}
			}
		})
	}
}
