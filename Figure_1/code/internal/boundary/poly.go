package boundary

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"

	"github.com/tuneinsight/lattigo/v6/ring"
)

func Ints(n int) []*big.Int {
	a := make([]*big.Int, n)
	for i := range a {
		a[i] = new(big.Int)
	}
	return a
}
func ParseInts(a []string) []*big.Int {
	v := Ints(len(a))
	for i, s := range a {
		if _, ok := v[i].SetString(s, 10); !ok {
			panic("bad integer")
		}
	}
	return v
}
func MaxAbs(a []*big.Int) *big.Int {
	m := new(big.Int)
	tmp := new(big.Int)
	for _, x := range a {
		tmp.Abs(x)
		if tmp.Cmp(m) > 0 {
			m.Set(tmp)
		}
	}
	return m
}
func LogInt(x *big.Int) float64 {
	if x.Sign() == 0 {
		return math.Inf(-1)
	}
	f := new(big.Float).SetInt(new(big.Int).Abs(x))
	m := new(big.Float)
	e := f.MantExp(m)
	v, _ := m.Float64()
	return float64(e) + math.Log2(v)
}
func LogFloat(x *big.Float) float64 {
	if x.Sign() == 0 {
		return math.Inf(-1)
	}
	m := new(big.Float)
	e := x.MantExp(m)
	v, _ := m.Float64()
	return float64(e) + math.Log2(math.Abs(v))
}
func SafeNumber(x float64) any {
	if math.IsInf(x, 1) {
		return "+infinity"
	}
	if math.IsInf(x, -1) {
		return "-infinity"
	}
	if math.IsNaN(x) {
		panic("NaN diagnostic")
	}
	return x
}

// Multiplication by a small-subring element: coefficient j lies at j*N/d.
func SparseMultiply(a, u []*big.Int) []*big.Int {
	n, d := len(a), len(u)
	if n%d != 0 {
		panic("subring does not divide ring")
	}
	out := Ints(n)
	tmp := new(big.Int)
	for j, c := range u {
		if c.Sign() == 0 {
			continue
		}
		shift := j * (n / d)
		for i, v := range a {
			k := i + shift
			tmp.Mul(v, c)
			if k >= n {
				out[k-n].Sub(out[k-n], tmp)
			} else {
				out[k].Add(out[k], tmp)
			}
		}
	}
	return out
}

func Coefficients(r *ring.Ring, p ring.Poly, ntt, mont bool) []*big.Int {
	v := *p.CopyNew()
	if ntt {
		r.INTT(v, v)
	}
	if mont {
		r.IMForm(v, v)
	}
	out := Ints(r.N())
	r.PolyToBigintCentered(v, 1, out)
	return out
}

func Congruent(a, b []*big.Int, q *big.Int) bool {
	t := new(big.Int)
	for i := range a {
		t.Sub(a[i], b[i])
		t.Mod(t, q)
		if t.Sign() != 0 {
			return false
		}
	}
	return true
}
func Centered(a []*big.Int, q *big.Int) []*big.Int {
	h := new(big.Int).Rsh(new(big.Int).Set(q), 1)
	b := Ints(len(a))
	for i, v := range a {
		b[i].Mod(v, q)
		if b[i].Cmp(h) > 0 {
			b[i].Sub(b[i], q)
		}
	}
	return b
}
func Equals(a, b []*big.Int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}

// Auxiliary CRT is diagnostic only. Its product is larger than twice the
// deterministic coefficient bound N*max|a|^2; hence no shadow wrap is possible.
func ExactSquare(a []*big.Int) ([]*big.Int, int, error) {
	n := len(a)
	m := MaxAbs(a)
	bound := new(big.Int).Mul(m, m)
	bound.Mul(bound, big.NewInt(int64(n)))
	bound.Lsh(bound, 1)
	gen := ring.NewNTTFriendlyPrimesGenerator(59, uint64(2*n))
	qs := []uint64{}
	q := big.NewInt(1)
	for q.Cmp(bound) <= 0 || len(qs) == 0 {
		v, e := gen.NextDownstreamPrime()
		if e != nil {
			return nil, 0, e
		}
		qs = append(qs, v)
		q.Mul(q, new(big.Int).SetUint64(v))
	}
	r, e := ring.NewRing(n, qs)
	if e != nil {
		return nil, 0, e
	}
	x, y, z := r.NewPoly(), r.NewPoly(), r.NewPoly()
	r.SetCoefficientsBigint(a, x)
	r.NTT(x, x)
	r.MForm(x, y)
	r.MulCoeffsMontgomery(x, y, z)
	r.INTT(z, z)
	out := Ints(n)
	r.PolyToBigintCentered(z, 1, out)
	return out, q.BitLen(), nil
}

func SaveCoefficients(path string, a []*big.Int) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	w, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	enc := json.NewEncoder(w)
	for i, x := range a {
		if e = enc.Encode(map[string]any{"index": i, "integer": x.String()}); e != nil {
			return e
		}
	}
	if e = w.Close(); e != nil {
		return e
	}
	return f.Close()
}

func VerifySmallInverse(u, v []*big.Int) error {
	prod := SparseMultiply(v, u)
	for i, x := range prod {
		want := int64(0)
		if i == 0 {
			want = 1
		}
		if x.Cmp(big.NewInt(want)) != 0 {
			return fmt.Errorf("unit inverse identity failed at %d", i)
		}
	}
	return nil
}
