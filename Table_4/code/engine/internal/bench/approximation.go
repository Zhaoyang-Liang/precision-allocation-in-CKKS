package bench

import (
	"fmt"
	cp "github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
	"math/big"
)

func powRat(a *big.Rat, n int) *big.Rat {
	return new(big.Rat).SetFrac(new(big.Int).Exp(a.Num(), big.NewInt(int64(n)), nil), new(big.Int).Exp(a.Denom(), big.NewInt(int64(n)), nil))
}

// Exact Chebyshev expansion of ((13+t)/16)^16. The low path uses degree 6.
// For t in [-1,1], the sum of discarded positive coefficients is a uniform
// approximation bound, NOT a bound on homomorphic evaluation error.
func power16Chebyshev() ([]*big.Rat, *big.Rat) {
	a := make([]*big.Rat, 17)
	for i := range a {
		a[i] = ri(0)
	}
	for n := 0; n <= 16; n++ {
		v := new(big.Rat).SetFrac(new(big.Int).Mul(new(big.Int).Binomial(16, int64(n)), new(big.Int).Exp(big.NewInt(13), big.NewInt(int64(16-n)), nil)), new(big.Int).Exp(big.NewInt(16), big.NewInt(16), nil))
		for k := 0; k <= n/2; k++ {
			j := n - 2*k
			c := div(new(big.Rat).SetInt(new(big.Int).Binomial(int64(n), int64(k))), pow2(n))
			if j > 0 {
				c = mul(ri(2), c)
			}
			a[j] = add(a[j], mul(v, c))
		}
	}
	tail := ri(0)
	for _, v := range a[7:] {
		tail = add(tail, v)
	}
	return a, tail
}

func evaluateChebyshev6(b *branchRuntime, ct *rlwe.Ciphertext, r *recorder) (*rlwe.Ciphertext, error) {
	if b.Representation.Forward != nil {
		return nil, fmt.Errorf("polynomial baseline requires ordinary representation")
	}
	e := &countedEvaluator{Evaluator: b.Evaluator, r: r, branch: b.Spec.ID}
	g := newGraphEvaluator(b.P, b.Evaluator, e)
	out, err := runPolynomialGraph(b.P, ct, *b.ApproxPolynomial, scale(pow2(b.Spec.ScaleBits)), g, b.PolyEvaluator)
	b.ActualGraph = &g.graph
	return out, err
}

func prepareApproximation(b *branchRuntime) {
	coeff, _ := power16Chebyshev()
	values := make([]*big.Float, 7)
	for i := range values {
		values[i] = bf(coeff[i], 512)
	}
	p := bignum.NewPolynomial(bignum.Chebyshev, values, [2]float64{-1, 1})
	b.ApproxPolynomial = &p
	b.PolyEvaluator = cp.NewEvaluator(b.P, b.Evaluator)
	var err error
	b.ExpectedGraph, err = planPolynomialGraph(b.P, b.Spec)
	if err != nil {
		panic(err)
	}
}

// Every method of the polynomial evaluator's schemes.Evaluator interface is
// intercepted. Fused APIs count their internal relinearization once. These
// counts are API operations, not machine/NTT instruction counts.
type countedEvaluator struct {
	*ckks.Evaluator
	r      *recorder
	branch string
}

func (e *countedEvaluator) record(kind string, a *rlwe.Ciphertext, b rlwe.Operand, relin bool) {
	op := Operation{Kind: kind, Branch: e.branch, InputLevel: a.Level(), InputDegree: a.Degree()}
	if d, ok := b.(interface{ Degree() int }); ok && d.Degree() > 0 && (kind == "mul" || kind == "mul_then_add") {
		if a == b {
			op.Kind = "ciphertext_square"
		} else {
			op.Kind = "ciphertext_multiply"
		}
		if relin {
			op.KeySwitches = 1
		}
	} else if kind == "mul" {
		op.Kind = "plaintext_or_scalar_multiply"
	}
	e.r.ops = append(e.r.ops, op)
}
func (e *countedEvaluator) Add(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	e.record("add", a, b, false)
	return e.Evaluator.Add(a, b, o)
}
func (e *countedEvaluator) AddNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	e.record("add", a, b, false)
	return e.Evaluator.AddNew(a, b)
}
func (e *countedEvaluator) Sub(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	e.record("sub", a, b, false)
	return e.Evaluator.Sub(a, b, o)
}
func (e *countedEvaluator) SubNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	e.record("sub", a, b, false)
	return e.Evaluator.SubNew(a, b)
}
func (e *countedEvaluator) Mul(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	e.record("mul", a, b, false)
	return e.Evaluator.Mul(a, b, o)
}
func (e *countedEvaluator) MulNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	e.record("mul", a, b, false)
	return e.Evaluator.MulNew(a, b)
}
func (e *countedEvaluator) MulRelin(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	e.record("mul", a, b, true)
	return e.Evaluator.MulRelin(a, b, o)
}
func (e *countedEvaluator) MulRelinNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	e.record("mul", a, b, true)
	return e.Evaluator.MulRelinNew(a, b)
}
func (e *countedEvaluator) MulThenAdd(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	e.record("mul_then_add", a, b, false)
	return e.Evaluator.MulThenAdd(a, b, o)
}
func (e *countedEvaluator) Relinearize(a, o *rlwe.Ciphertext) error {
	e.r.ops = append(e.r.ops, Operation{Kind: "relinearize", Branch: e.branch, InputLevel: a.Level(), InputDegree: a.Degree(), KeySwitches: 1})
	return e.Evaluator.Relinearize(a, o)
}
func (e *countedEvaluator) Rescale(a, o *rlwe.Ciphertext) error {
	level, degree := a.Level(), a.Degree()
	err := e.Evaluator.Rescale(a, o)
	if err == nil {
		e.r.ops = append(e.r.ops, Operation{Kind: "rescale", Branch: e.branch, InputLevel: level, InputDegree: degree, RemovedPrimes: level - o.Level()})
	}
	return err
}

func approximationReference(d *Dataset) []*big.Rat {
	c, _ := power16Chebyshev()
	out := make([]*big.Rat, len(d.Values))
	for i, x := range d.Values {
		t := sub(mul(ri(16), x), ri(13))
		prev, cur := ri(1), t
		v := add(c[0], mul(c[1], t))
		for k := 2; k <= 6; k++ {
			next := sub(mul(mul(ri(2), t), cur), prev)
			v = add(v, mul(c[k], next))
			prev, cur = cur, next
		}
		out[i] = v
	}
	return out
}
