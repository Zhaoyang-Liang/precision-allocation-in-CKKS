package bench

import (
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
	"math/big"
	"testing"
)

func TestProfileAccuracyDoesNotCountDummy(t *testing.T) {
	c := &ProfileConfig{Targets: []int{160}, GroupSizes: []int{1}}
	got := []*bignum.Complex{bignum.ToComplex(1, 1024), bignum.ToComplex(5000, 1024)}
	got[0][1].Set(bf(pow2(-170), 1024))
	m := ProfileBatchMap{Branch: "x", PhysicalSlots: 2, Values: []ProfileAssignment{{0, 0, 0}}}
	a := newProfileErrors(c)
	if e := a.add(got, m, [][]*big.Rat{{ri(1)}}); e != nil {
		t.Fatal(e)
	}
	rows, e := a.finish()
	if e != nil {
		t.Fatal(e)
	}
	if !rows[0].Pass || rows[0].Checked != 1 || a.dummyChecked != 1 || a.dummyMaximum.Cmp(ri(25000000)) != 0 {
		t.Fatal("dummy or imaginary error accounting")
	}
	if e = a.add(got, m, [][]*big.Rat{{ri(1)}}); e == nil {
		t.Fatal("duplicate outputs accepted")
	}
}
func TestProfileAccuracyRejectsOneWrongSlot(t *testing.T) {
	c := &ProfileConfig{Targets: []int{160, 32}, GroupSizes: []int{1, 1}}
	got := []*bignum.Complex{bignum.ToComplex(1, 1024), bignum.ToComplex(1, 1024)}
	got[0][1].Set(bf(pow2(-159), 1024))
	got[1][1].Set(bf(pow2(-40), 1024))
	a := newProfileErrors(c)
	m := ProfileBatchMap{Branch: "x", PhysicalSlots: 2, Values: []ProfileAssignment{{0, 0, 0}, {1, 1, 0}}}
	if e := a.add(got, m, [][]*big.Rat{{ri(1)}, {ri(1)}}); e != nil {
		t.Fatal(e)
	}
	rows, e := a.finish()
	if e != nil {
		t.Fatal(e)
	}
	if rows[0].Pass || !rows[1].Pass {
		t.Fatal("group-specific error check failed")
	}
}
