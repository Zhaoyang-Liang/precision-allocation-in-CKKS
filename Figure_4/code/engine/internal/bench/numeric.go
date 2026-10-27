package bench

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Rat helpers ALWAYS allocate; callers may safely retain an earlier quantity.
func ri(x int64) *big.Rat        { return new(big.Rat).SetInt64(x) }
func add(a, b *big.Rat) *big.Rat { return new(big.Rat).Add(a, b) }
func sub(a, b *big.Rat) *big.Rat { return new(big.Rat).Sub(a, b) }
func mul(a, b *big.Rat) *big.Rat { return new(big.Rat).Mul(a, b) }
func div(a, b *big.Rat) *big.Rat { return new(big.Rat).Quo(a, b) }
func neg(a *big.Rat) *big.Rat    { return new(big.Rat).Neg(a) }
func pow2(n int) *big.Rat {
	k := n
	if k < 0 {
		k = -k
	}
	z := new(big.Int).Lsh(big.NewInt(1), uint(k))
	if n < 0 {
		return new(big.Rat).SetFrac(big.NewInt(1), z)
	}
	return new(big.Rat).SetInt(z)
}
func prod(q []uint64) *big.Int {
	z := big.NewInt(1)
	for _, v := range q {
		z.Mul(z, new(big.Int).SetUint64(v))
	}
	return z
}
func rat(s string) (*big.Rat, error) {
	z, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("invalid rational %q", s)
	}
	return z, nil
}
func bf(x *big.Rat, bits uint) *big.Float { return new(big.Float).SetPrec(bits).SetRat(x) }
func scale(x *big.Rat) rlwe.Scale         { return rlwe.NewScale(bf(x, rlwe.ScalePrecision)) }
func scaleRat(s rlwe.Scale) *big.Rat      { x, _ := s.Value.Rat(nil); return x }
func hashBytes(b []byte) string           { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func primeStrings(q []uint64) []string {
	s := make([]string, len(q))
	for i, v := range q {
		s[i] = strconv.FormatUint(v, 10)
	}
	return s
}

// Displays only. Decisions must compare rationals or squared errors directly.
func log2Rat(x *big.Rat) float64 {
	f := bf(x, 128)
	m := new(big.Float).SetPrec(128)
	e := f.MantExp(m)
	v, _ := m.Float64()
	return float64(e) + math.Log2(v)
}

// quad is a+b*sqrt(2). Half-up rounding is verified with EXACT rational signs.
// No floating-point comparison decides a rounding boundary.
type quad struct{ a, b *big.Rat }

func (x quad) sign() int {
	sa, sb := x.a.Sign(), x.b.Sign()
	if sa == 0 {
		return sb
	}
	if sb == 0 || sa == sb {
		return sa
	}
	return sa * sub(mul(x.a, x.a), mul(ri(2), mul(x.b, x.b))).Sign()
}
func (x quad) round() (*big.Int, error) {
	for prec := uint(512); prec <= 8192; prec *= 2 {
		y := new(big.Float).SetPrec(prec).Sqrt(new(big.Float).SetPrec(prec).SetInt64(2))
		y.Mul(y, bf(x.b, prec))
		y.Add(y, bf(x.a, prec))
		y.Add(y, bf(big.NewRat(1, 2), prec))
		n, _ := y.Int(nil)
		if y.Sign() < 0 && !y.IsInt() {
			n.Sub(n, big.NewInt(1))
		}
		lo := quad{add(sub(x.a, new(big.Rat).SetInt(n)), big.NewRat(1, 2)), x.b}
		hi := quad{sub(sub(x.a, new(big.Rat).SetInt(n)), big.NewRat(1, 2)), x.b}
		if lo.sign() >= 0 && hi.sign() < 0 {
			return n, nil
		}
	}
	return nil, fmt.Errorf("unable to certify algebraic rounding")
}
func (x quad) absUpper() *big.Rat {
	if x.sign() < 0 {
		x = quad{neg(x.a), neg(x.b)}
	}
	const bits = 512
	d := new(big.Int).Lsh(big.NewInt(1), bits)
	l := new(big.Int).Sqrt(new(big.Int).Lsh(big.NewInt(2), 2*bits))
	if x.b.Sign() >= 0 {
		l.Add(l, big.NewInt(1))
	}
	return add(x.a, mul(x.b, new(big.Rat).SetFrac(l, d)))
}
func pell(n int) (a, b *big.Int) {
	a, b = big.NewInt(1), big.NewInt(0)
	for i := 0; i < n; i++ {
		a, b = new(big.Int).Add(a, new(big.Int).Lsh(b, 1)), new(big.Int).Add(a, b)
	}
	return
}

// unsigned quantities (durations, bytes, counters) are JSON strings, preventing
// accidental loss in JavaScript or spreadsheet consumers.
type Count uint64

func (c Count) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(strconv.FormatUint(uint64(c), 10))), nil
}
