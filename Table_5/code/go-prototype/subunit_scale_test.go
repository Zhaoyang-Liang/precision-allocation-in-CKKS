package lowbootstrap

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math"
	"math/big"
	"math/cmplx"
	"testing"
)

func TestSubunitCoefficientScaleEncrypted(t *testing.T) {
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 8, LogQ: []int{45}, LogDefaultScale: 16})
	if err != nil {
		t.Fatal(err)
	}
	kg := rlwe.NewKeyGenerator(p)
	sk := kg.GenSecretKeyNew()
	embed := func(v []int64) []*big.Int {
		a := make([]*big.Int, p.N())
		for j := range a {
			a[j] = new(big.Int)
		}
		for j, x := range v {
			a[j*p.N()/len(v)].SetInt64(x)
		}
		return a
	}
	ev, err := NewShapedEvaluator(p, ckks.NewEvaluator(p, nil), embed([]int64{59, -20, -21, 10, 0, -10, 21, 20}), embed([]int64{98541, 91040, 69679, 37710, 0, -37710, -69679, -91040}), 4, 2.5370153291646064e-6)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ev.ShapedPlaintext(.25, 0, rlwe.NewScale(65536))
	if err != nil {
		t.Fatal(err)
	}
	p.RingQ().MulCoeffsMontgomery(pt.Value, ev.InverseNTT, pt.Value)
	ct, err := rlwe.NewEncryptor(p, sk).EncryptNew(pt)
	if err != nil {
		t.Fatal(err)
	}
	ct, err = ev.rawUnit(ct, false)
	if err != nil {
		t.Fatal(err)
	}
	ct.LogDimensions = p.LogMaxDimensions()
	out := ckks.NewCiphertext(p, 1, 0)
	out.Scale = rlwe.NewScale(4096)
	if err = ev.MulThenAdd(ct, .6, out); err == nil {
		t.Fatal("default policy should reject unsupported subunit coefficient scale")
	}
	ev.AllowSubunitCoefficientScale = true
	if err = ev.MulThenAdd(ct, .6, out); err != nil {
		t.Fatal(err)
	}
	if out.Level() != 0 || !out.Scale.Equal(rlwe.NewScale(4096)) {
		t.Fatal("must preserve accumulator level and true scale")
	}
	values := make([]complex128, p.MaxSlots())
	if err = ckks.NewEncoder(p, 128).Decode(rlwe.NewDecryptor(p, sk).DecryptNew(out), values); err != nil {
		t.Fatal(err)
	}
	maxErr := 0.0
	for j, x := range values {
		if j%4 == 0 {
			maxErr = math.Max(maxErr, cmplx.Abs(x-.15))
		}
	}
	if maxErr > 1e-3 || ev.Stats.SubunitCoefficientProducts != 1 || math.Abs(ev.Stats.MinCoefficientLogScale+4) > 1e-8 {
		t.Fatalf("subunit actual computation failed: err=%g stats=%+v", maxErr, ev.Stats)
	}
	t.Logf("actual encrypted target .15, coefficient scale 1/16, max data error %g", maxErr)
}
