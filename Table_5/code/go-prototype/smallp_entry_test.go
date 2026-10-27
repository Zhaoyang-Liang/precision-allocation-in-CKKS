package lowbootstrap

import (
	"math/rand"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestSmallPEntryExactConvolutionAndKS(t *testing.T) {
	top, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 8, Q: []uint64{14155777}, LogDefaultScale: 16, Xs: ring.Ternary{H: 64}})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 7, Q: top.Q(), LogDefaultScale: 16, Xs: ring.Ternary{H: 8}})
	if err != nil {
		t.Fatal(err)
	}
	st := rlwe.NewKeyGenerator(top).GenSecretKeyNew()
	sl := rlwe.NewKeyGenerator(leaf).GenSecretKeyNew()
	e, err := NewSmallPEntry(top, leaf, st, sl, 8191, 5767169)
	if err != nil {
		t.Fatal(err)
	}
	// Independent schoolbook convolution modulo P verifies the auxiliary CRT
	// implementation against signed negacyclic arithmetic, including wraparound.
	rng := rand.New(rand.NewSource(927))
	c1 := top.RingQ().NewPoly()
	for i := range c1.Coeffs[0] {
		c1.Coeffs[0][i] = uint64(rng.Intn(int(top.Q()[0])))
	}
	coeff := append([]uint64(nil), c1.Coeffs[0]...)
	top.RingQ().NTT(c1, c1)
	got, err := e.pProduct(c1)
	if err != nil {
		t.Fatal(err)
	}
	for c := 0; c < 2; c++ {
		want := make([]int64, top.N())
		for j := range e.KeyP {
			kp := e.KeyP[j][c].CopyNew()
			e.Work.IMForm(*kp, *kp)
			e.Work.INTT(*kp, *kp)
			for a, x := range coeff {
				if (x>>j)&1 == 0 {
					continue
				}
				for b, y := range kp.Coeffs[0] {
					at := a + b
					sign := int64(1)
					if at >= top.N() {
						at -= top.N()
						sign = -1
					}
					want[at] += sign * int64(y)
				}
			}
		}
		for i, v := range want {
			v %= int64(e.P)
			if v < 0 {
				v += int64(e.P)
			}
			if v > int64(e.P/2) {
				v -= int64(e.P)
			}
			if v != got[c][i] {
				t.Fatalf("component %d coefficient %d: exact P product mismatch", c, i)
			}
		}
	}
	// A real encrypted arbitrary polynomial, not a specially sparse plaintext.
	embedded := rlwe.NewSecretKey(top)
	ring.MapSmallDimensionToLargerDimensionNTT(sl.Value.Q, embedded.Value.Q)
	for trial := 0; trial < 4; trial++ {
		pt := ckks.NewPlaintext(top, 0)
		for i := range pt.Value.Coeffs[0] {
			pt.Value.Coeffs[0][i] = uint64(rng.Intn(10000))
		}
		top.RingQ().NTT(pt.Value, pt.Value)
		ct, err := rlwe.NewEncryptor(top, st).EncryptNew(pt)
		if err != nil {
			t.Fatal(err)
		}
		sw, err := e.ApplyTop(ct)
		if err != nil {
			t.Fatal(err)
		}
		before := rlwe.NewDecryptor(top, st).DecryptNew(ct)
		after := rlwe.NewDecryptor(top, embedded).DecryptNew(sw)
		diff := top.RingQ().NewPoly()
		top.RingQ().Sub(after.Value, before.Value, diff)
		top.RingQ().INTT(diff, diff)
		maxErr := int64(0)
		for _, x := range diff.Coeffs[0] {
			v := int64(x)
			if x > top.Q()[0]/2 {
				v -= int64(top.Q()[0])
			}
			if v < 0 {
				v = -v
			}
			if v > maxErr {
				maxErr = v
			}
		}
		if maxErr > 64 {
			t.Fatalf("small-P KS error too large: %d", maxErr)
		}
		leaves, err := e.ApplyAll(ct)
		if err != nil {
			t.Fatal(err)
		}
		if len(leaves) != 2 || leaves[0].Level() != 0 || !leaves[0].Scale.Equal(ct.Scale) {
			t.Fatal("split metadata mismatch")
		}
		t.Logf("trial%d actual KS max added coefficient error=%d", trial, maxErr)
	}
}
