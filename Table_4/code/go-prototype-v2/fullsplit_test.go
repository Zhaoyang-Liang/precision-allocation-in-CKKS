package lowbootstrap

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math/big"
	"testing"
)

func TestFullSplitMergePreservesEveryBranch(t *testing.T) {
	for _, gap := range []int{3, 4} {
		top, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 9, LogQ: []int{40, 30}, LogP: []int{25}, LogDefaultScale: 20, Xs: ring.Ternary{H: 32}})
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 9 - gap, Q: top.Q(), P: top.P(), LogDefaultScale: 20, Xs: ring.Ternary{H: 16}})
		if e != nil {
			t.Fatal(e)
		}
		ct := ckks.NewCiphertext(top, 1, 1)
		for c := range ct.Value {
			for l := 0; l <= 1; l++ {
				for j := 0; j < top.N(); j++ {
					ct.Value[c].Coeffs[l][j] = uint64(31*j + 17*c + 13*l)
				}
			}
			top.RingQ().NTT(ct.Value[c], ct.Value[c])
		}
		split, e := SplitCoefficientBranches(top, leaf, ct)
		if e != nil {
			t.Fatal(e)
		}
		merged, e := MergeCoefficientBranches(top, leaf, split)
		if e != nil {
			t.Fatal(e)
		}
		for c := range ct.Value {
			for l := 0; l <= 1; l++ {
				for j := 0; j < top.N(); j++ {
					if ct.Value[c].Coeffs[l][j] != merged.Value[c].Coeffs[l][j] {
						t.Fatalf("gap%d component%d limb%d coefficient%d lost", gap, c, l, j)
					}
				}
			}
		}
		st := rlwe.NewKeyGenerator(top).GenSecretKeyNew()
		sl := rlwe.NewKeyGenerator(leaf).GenSecretKeyNew()
		entry, e := NewRingEntry(top, leaf, st, sl, 0, 0, 14)
		if e != nil {
			t.Fatal(e)
		}
		coeff := make([]*big.Int, top.N())
		for j := range coeff {
			coeff[j] = big.NewInt(int64((j%11)-5) * (1 << 18))
		}
		p, e := PolynomialFromCoefficients(top, coeff, 0, true, false)
		if e != nil {
			t.Fatal(e)
		}
		pt := ckks.NewPlaintext(top, 0)
		pt.Value = p
		enc, e := rlwe.NewEncryptor(top, st).EncryptNew(pt)
		if e != nil {
			t.Fatal(e)
		}
		branches, e := entry.ApplyAll(enc)
		if e != nil {
			t.Fatal(e)
		}
		if len(branches) != 1<<gap {
			t.Fatal("wrong branch count")
		}
		for b, ctb := range branches {
			dec := rlwe.NewDecryptor(leaf, sl).DecryptNew(ctb)
			got, e := CenteredCoefficients(leaf, dec.Value, dec.IsNTT, false)
			if e != nil {
				t.Fatal(e)
			}
			for j, v := range got {
				d := new(big.Int).Sub(v, coeff[j*len(branches)+b])
				d.Abs(d)
				if d.Cmp(big.NewInt(1<<16)) > 0 {
					t.Fatalf("gap%d branch%d coefficient%d phase mismatch: %s", gap, b, j, d)
				}
			}
		}
	}
}
