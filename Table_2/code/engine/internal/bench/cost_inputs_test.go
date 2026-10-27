package bench

import (
	"math/big"
	"testing"
)

func TestCostInputPairsAndEndpoints(t *testing.T) {
	for i := 0; i < 20; i++ {
		a := profileFamilyInput("grow", 2026101301, 0, i)
		b := profileFamilyInput("reciprocal", 2026101301, 0, i)
		if new(big.Rat).Mul(a, b).Cmp(big.NewRat(1, 1)) != 0 {
			t.Fatal("not reciprocal")
		}
		if a.Cmp(big.NewRat(1, 1)) < 0 || a.Cmp(big.NewRat(2, 1)) > 0 {
			t.Fatal("input range")
		}
	}
	if profileReference(profileFamilyInput("grow", 1, 0, 1), 6).Cmp(new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), 64))) != 0 {
		t.Fatal("depth six reference")
	}
}

func TestCostInputFamilyBoundToContract(t *testing.T) {
	c := publicTestProfile()
	c.Schema = "pa-fixed-precision-experiment-v1"
	if c.Validate() == nil {
		t.Fatal("missing family accepted")
	}
	c.InputFamily = "grow"
	c.Repeat = 5
	a, e := PlanProfile(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	c.InputFamily = "reciprocal"
	b, e := PlanProfile(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	if a.ContractSHA256 == b.ContractSHA256 {
		t.Fatal("different input ranges share a certificate")
	}
	c.InputFamily = "unknown"
	if c.Validate() == nil {
		t.Fatal("unknown family accepted")
	}
}
