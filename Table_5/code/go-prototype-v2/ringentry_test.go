package lowbootstrap

import (
	"math/big"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestRingEntryCryptoSmoke(t *testing.T) {
	report, err := RunRingEntrySmoke(RingEntrySmokeConfig{TopLogN: 8, LeafLogN: 7, QBits: 52, PBits: 25, BaseTwo: 14, TopWeight: 32, LeafWeight: 32})
	if err != nil {
		t.Fatal(err)
	}
	if !report.UnitInverseExact || report.OutputLevel != 0 || report.OutputLogSlots != 6 {
		t.Fatalf("unexpected stage metadata: %+v", report)
	}
	t.Logf("actual encrypted N=256 -> n=128: KS added coefficient max=%s, key logQP=%.4f", report.MaxKSAddedCoeffError, report.ActualKeyLogQP)
}

func TestCoefficientRNSAndSecretRebase(t *testing.T) {
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 7, LogQ: []int{43, 30}, LogP: []int{53}, LogDefaultScale: 25, Xs: ring.Ternary{H: 32}})
	if err != nil {
		t.Fatal(err)
	}
	coeffs := make([]*big.Int, p.N())
	for i := range coeffs {
		// Exercise values larger than either limb, including negative CRT lifts.
		coeffs[i] = new(big.Int).Lsh(big.NewInt(int64(i-64)), 47)
	}
	for _, ntt := range []bool{false, true} {
		for _, mont := range []bool{false, true} {
			poly, err := PolynomialFromCoefficients(p, coeffs, 1, ntt, mont)
			if err != nil {
				t.Fatal(err)
			}
			got, err := CenteredCoefficients(p, poly, ntt, mont)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				if got[i].Cmp(coeffs[i]) != 0 {
					t.Fatalf("CRT roundtrip failed at coefficient %d, NTT=%v Montgomery=%v", i, ntt, mont)
				}
			}
		}
	}
	low, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 7, Q: p.Q()[:1], LogP: []int{25}, LogDefaultScale: 25, Xs: ring.Ternary{H: 32}})
	if err != nil {
		t.Fatal(err)
	}
	sk := rlwe.NewKeyGenerator(low).GenSecretKeyNew()
	rebased, err := RebaseSecretKey(low, p, sk)
	if err != nil {
		t.Fatal(err)
	}
	src, _ := CenteredCoefficients(low, sk.Value.Q, true, true)
	dst, _ := CenteredCoefficients(p, rebased.Value.Q, true, true)
	for i := range src {
		if src[i].Cmp(dst[i]) != 0 {
			t.Fatal("secret coefficients changed under local rebasing")
		}
	}
}
