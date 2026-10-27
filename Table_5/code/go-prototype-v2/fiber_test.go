package lowbootstrap

import (
	"math"
	"math/cmplx"
	"math/rand"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func applyFiberPlain(d lintrans.Diagonals[complex128], v []complex128) []complex128 {
	out := make([]complex128, len(v))
	for o, diag := range d {
		for s := range v {
			out[s] += diag[s] * v[(s+o)%len(v)]
		}
	}
	return out
}
func TestFiberLayoutPlain(t *testing.T) {
	const slots = 2048
	const k = 64
	rng := rand.New(rand.NewSource(42))
	for _, R := range []int{1, 2, 4, 8, 16, 32} {
		z := make([]complex128, k)
		v := make([]complex128, slots)
		for j := range z {
			z[j] = complex(rng.Float64()-.5, rng.Float64()-.5)
		}
		for s := range v {
			if s%R == 0 {
				v[s] = z[(s/R)%k]
			} else {
				v[s] = complex(1e6*rng.Float64(), -1e6*rng.Float64())
			}
		}
		stc, e := FiberDiagonals(slots, k, R, false, 1)
		if e != nil {
			t.Fatal(e)
		}
		partial := applyFiberPlain(stc, v)
		traced := make([]complex128, slots)
		for s := range traced {
			for j := 0; j < slots/k; j++ {
				traced[s] += partial[(s+j*k)%slots]
			}
		}
		cts, e := FiberDiagonals(slots, k, R, true, float64(k)/slots)
		if e != nil {
			t.Fatal(e)
		}
		got := applyFiberPlain(cts, traced)
		for s, x := range got {
			want := complex(0, 0)
			if s%R == 0 {
				want = z[(s/R)%k]
			}
			if cmplx.Abs(x-want) > 1e-11 {
				t.Fatalf("R%d slot%d err%.3g", R, s, cmplx.Abs(x-want))
			}
		}
	}
}

// Independent encoded matrix evaluation checks rotation conventions and BSGS
// diagonal placement, beyond the purely floating-point formula check.
func TestFiberEncryptedTransforms(t *testing.T) {
	p, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 8, LogQ: []int{45, 40, 40}, LogP: []int{50}, LogDefaultScale: 30, Xs: ring.Ternary{H: 32}})
	if e != nil {
		t.Fatal(e)
	}
	const k = 8
	const R = 2
	f, _ := FiberDiagonals(p.MaxSlots(), k, R, false, 1)
	b, _ := FiberDiagonals(p.MaxSlots(), k, R, true, float64(k)/float64(p.MaxSlots()))
	fm, e := NewFiberMatrix(p, f, 2, rlwe.NewScale(p.Q()[2]))
	if e != nil {
		t.Fatal(e)
	}
	bm, e := NewFiberMatrix(p, b, 1, rlwe.NewScale(p.Q()[1]))
	if e != nil {
		t.Fatal(e)
	}
	unique := map[uint64]bool{}
	for _, g := range append(append(fm.GaloisElements(p), bm.GaloisElements(p)...), FiberTraceGaloisElements(p, k)...) {
		unique[g] = true
	}
	gals := []uint64{}
	for g := range unique {
		gals = append(gals, g)
	}
	kg := rlwe.NewKeyGenerator(p)
	sk := kg.GenSecretKeyNew()
	keys := rlwe.NewMemEvaluationKeySet(nil, kg.GenGaloisKeysNew(gals, sk)...)
	ev := ckks.NewEvaluator(p, keys)
	lt := lintrans.NewEvaluator(ev)
	values := make([]complex128, p.MaxSlots())
	for s := range values {
		if s%R == 0 {
			j := (s / R) % k
			values[s] = complex(.01*float64(j+1), -.02*float64(j))
		}
	}
	pt := ckks.NewPlaintext(p, 2)
	encoder := ckks.NewEncoder(p, 128)
	if e = encoder.Encode(values, pt); e != nil {
		t.Fatal(e)
	}
	ct, e := rlwe.NewEncryptor(p, sk).EncryptNew(pt)
	if e != nil {
		t.Fatal(e)
	}
	ct, e = lt.EvaluateNew(ct, fm)
	if e != nil {
		t.Fatal(e)
	}
	if e = ev.Rescale(ct, ct); e != nil {
		t.Fatal(e)
	}
	ct, e = FiberRawTrace(ev, p, ct, k)
	if e != nil {
		t.Fatal(e)
	}
	ct, e = lt.EvaluateNew(ct, bm)
	if e != nil {
		t.Fatal(e)
	}
	if e = ev.Rescale(ct, ct); e != nil {
		t.Fatal(e)
	}
	got := make([]complex128, p.MaxSlots())
	if e = encoder.Decode(rlwe.NewDecryptor(p, sk).DecryptNew(ct), got); e != nil {
		t.Fatal(e)
	}
	maxErr := 0.0
	for s, x := range got {
		maxErr = math.Max(maxErr, cmplx.Abs(x-values[s]))
	}
	if maxErr > 2e-5 {
		t.Fatalf("encrypted transform err %g", maxErr)
	}
	t.Logf("fiber encrypted max error %.3g", maxErr)
}
