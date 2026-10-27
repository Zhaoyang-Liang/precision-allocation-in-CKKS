package lowbootstrap

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math/cmplx"
	"testing"
)

// Test the actual encoder's complex orientation and PA data class, not merely
// a support-set calculation. A wrap introduces Y and breaks the repeated-value
// leaf interface even though a coefficient branch is still well defined.
func TestKnownSupportSquareClosureAndWrapObstruction(t *testing.T) {
	top, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 9, LogQ: []int{40, 30}, LogDefaultScale: 25})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 5, Q: top.Q(), LogDefaultScale: 25})
	if err != nil {
		t.Fatal(err)
	}
	const k = 16
	const R = 8
	makeInput := func(zs map[int]complex128) *rlwe.Ciphertext {
		cts := make([]*rlwe.Ciphertext, k)
		for b := range cts {
			pt := ckks.NewPlaintext(leaf, 1)
			values := make([]complex128, leaf.MaxSlots())
			for j := 0; j < len(values); j += R {
				values[j] = zs[b]
			}
			if e := ckks.NewEncoder(leaf, 128).Encode(values, pt); e != nil {
				t.Fatal(e)
			}
			cts[b] = ckks.NewCiphertext(leaf, 0, 1)
			cts[b].Value[0] = pt.Value
			cts[b].MetaData = pt.MetaData.CopyNew()
		}
		ct, e := MergeCoefficientBranches(top, leaf, cts)
		if e != nil {
			t.Fatal(e)
		}
		return ct
	}
	squareSplit := func(ct *rlwe.Ciphertext) []*rlwe.Ciphertext {
		out := ct.CopyNew()
		mont := ct.Value[0].CopyNew()
		top.RingQ().MForm(ct.Value[0], *mont)
		top.RingQ().MulCoeffsMontgomery(ct.Value[0], *mont, out.Value[0])
		out.Scale = ct.Scale.Mul(ct.Scale)
		bs, e := SplitCoefficientBranches(top, leaf, out)
		if e != nil {
			t.Fatal(e)
		}
		return bs
	}
	decodeBranch := func(ct *rlwe.Ciphertext) []complex128 {
		pt := ckks.NewPlaintext(leaf, ct.Level())
		pt.Value = ct.Value[0]
		pt.MetaData = ct.MetaData.CopyNew()
		v := make([]complex128, leaf.MaxSlots())
		if e := ckks.NewEncoder(leaf, 128).Decode(pt, v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	a, b := complex(.2, .1), complex(-.15, .25)
	bs := squareSplit(makeInput(map[int]complex128{0: a, 1: b}))
	wants := map[int]complex128{0: a * a, 1: 2 * a * b, 2: b * b}
	for r, ct := range bs {
		v := decodeBranch(ct)
		for j, x := range v {
			want := complex(0, 0)
			if j%R == 0 {
				want = wants[r]
			}
			if cmplx.Abs(x-want) > 1e-6 {
				t.Fatalf("branch %d slot %d: got %v want %v", r, j, x, want)
			}
		}
	}
	wrapped := squareSplit(makeInput(map[int]complex128{15: a}))
	v := decodeBranch(wrapped[14])
	if cmplx.Abs(v[0]-v[8]) < .01 {
		t.Fatal("expected Y-dependent data values after exponent wrap")
	}
}
