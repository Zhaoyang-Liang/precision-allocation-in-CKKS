package bench

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type ConstantReport struct {
	Purpose             string    `json:"purpose"`
	Scale               string    `json:"scale_exact"`
	Coefficients        []string  `json:"coefficients_at_0_N4_N2_3N4"`
	EmbeddingErrorUpper [2]string `json:"embedding_error_upper_low_high"`
}
type PublicMultiplier struct {
	Poly   ring.Poly
	Scale  rlwe.Scale
	Report ConstantReport
}
type Representation struct {
	Kind    string
	A, B    *big.Int
	Weights [2]*big.Float
	Forward *PublicMultiplier
}

// Coefficients are INTEGERS modulo Q, not a CKKS encoding at an implicit scale.
// The resulting polynomial is in Montgomery NTT form for raw component products.
func integerPoly(p ckks.Parameters, coeff []*big.Int) ring.Poly {
	r := p.RingQ()
	out := r.NewPoly()
	for k, q := range p.Q() {
		m := new(big.Int).SetUint64(q)
		for i, c := range coeff {
			out.Coeffs[k][i*p.N()/len(coeff)] = new(big.Int).Mod(c, m).Uint64()
		}
	}
	r.NTT(out, out)
	r.MForm(out, out)
	return out
}
func constantReport(purpose string, factor *big.Rat, coeff []*big.Int) ConstantReport {
	r := ConstantReport{Purpose: purpose, Scale: factor.RatString()}
	for _, c := range coeff {
		r.Coefficients = append(r.Coefficients, c.String())
	}
	return r
}

func NewRepresentation(p ckks.Parameters, c CaseSpec, prec uint) (*Representation, error) {
	r := &Representation{Kind: c.Kind, A: big.NewInt(1), B: big.NewInt(0)}
	r.Weights = [2]*big.Float{bf(ri(1), prec), bf(ri(1), prec)}
	if c.Kind == "unit" || c.Kind == "integer_nonunit" {
		r.A, r.B = pell(c.UnitPower)
		norm := int64(1)
		purpose := "exact integer unit; no extra scale"
		if c.Kind == "integer_nonunit" {
			// k=(2+h)*(1+h)^n has positive embeddings and norm 2.
			// Native encoding only needs real inverse weights, NOT k^-1 in R.
			a, b := new(big.Int).Set(r.A), new(big.Int).Set(r.B)
			r.A = new(big.Int).Lsh(new(big.Int).Add(a, b), 1)
			r.B = new(big.Int).Add(a, new(big.Int).Lsh(b, 1))
			norm = 2
			purpose = "exact integer nonunit of norm 2; native inputs; no extra scale"
		}
		check := new(big.Int).Sub(new(big.Int).Mul(r.A, r.A), new(big.Int).Lsh(new(big.Int).Mul(r.B, r.B), 1))
		if check.Cmp(big.NewInt(norm)) != 0 {
			return nil, fmt.Errorf("integer multiplier norm is not %d", norm)
		}
		root := new(big.Float).SetPrec(prec).Sqrt(new(big.Float).SetPrec(prec).SetInt64(2))
		b := new(big.Float).SetPrec(prec).Mul(root, new(big.Float).SetPrec(prec).SetInt(r.B))
		a := new(big.Float).SetPrec(prec).SetInt(r.A)
		r.Weights[0] = new(big.Float).SetPrec(prec).Add(a, b)
		r.Weights[1] = new(big.Float).SetPrec(prec).Sub(a, b)
		if r.Weights[1].Sign() <= 0 {
			return nil, fmt.Errorf("insufficient precision to resolve the small unit embedding")
		}
		coeff := []*big.Int{new(big.Int).Set(r.A), new(big.Int).Set(r.B), big.NewInt(0), new(big.Int).Neg(r.B)}
		report := constantReport(purpose, ri(1), coeff)
		report.EmbeddingErrorUpper = [2]string{"0", "0"}
		r.Forward = &PublicMultiplier{integerPoly(p, coeff), scale(ri(1)), report}
	} else if c.Kind == "diagonal" {
		w := [2]*big.Rat{pow2(c.DyadicBits), pow2(-c.DyadicBits)}
		r.Weights = [2]*big.Float{bf(w[0], prec), bf(w[1], prec)}
		f := pow2(c.MultiplierScaleBits)
		// a+b*h, sigma_even(h)=+sqrt(2), sigma_odd(h)=-sqrt(2).
		q0 := quad{mul(f, div(add(w[0], w[1]), ri(2))), ri(0)}
		q1 := quad{ri(0), mul(f, div(sub(w[0], w[1]), ri(4)))}
		n0, e := q0.round()
		if e != nil {
			return nil, e
		}
		n1, e := q1.round()
		if e != nil {
			return nil, e
		}
		coeff := []*big.Int{n0, n1, big.NewInt(0), new(big.Int).Neg(n1)}
		report := constantReport("dyadic diagonal, rounded subfield plaintext", f, coeff)
		for j, sgn := range []int64{1, -1} {
			report.EmbeddingErrorUpper[j] = div((quad{sub(new(big.Rat).SetInt(n0), mul(f, w[j])), mul(ri(sgn), new(big.Rat).SetInt(n1))}).absUpper(), f).RatString()
		}
		r.Forward = &PublicMultiplier{integerPoly(p, coeff), scale(f), report}
		if c.MatchQuantizedWeights {
			// Strong baseline: match the ACTUAL rational-algebraic multiplier.
			// Quantization relative to nominal dyadic weights is then descriptive,
			// not an artificial multiplicative bias charged at every gate.
			root := new(big.Float).SetPrec(prec).Sqrt(new(big.Float).SetPrec(prec).SetInt64(2))
			alpha := bf(div(new(big.Rat).SetInt(n0), f), prec)
			beta := new(big.Float).SetPrec(prec).Mul(root, bf(div(new(big.Rat).SetInt(n1), f), prec))
			r.Weights = [2]*big.Float{new(big.Float).SetPrec(prec).Add(alpha, beta), new(big.Float).SetPrec(prec).Sub(alpha, beta)}
			if r.Weights[0].Sign() <= 0 || r.Weights[1].Sign() <= 0 {
				return nil, fmt.Errorf("quantized diagonal has a nonpositive embedding")
			}
			r.Forward.Report.Purpose = "quantized non-unit diagonal; input matches actual embeddings; listed residual is relative to nominal dyadic weights"
		}
	}
	return r, nil
}

// This public algebra check detects a changed slot/automorphism convention.
// It does not decrypt and does not infer a probabilistic error bound.
func (r *Representation) CheckRotations(p ckks.Parameters, rots []int) error {
	if r.Forward == nil {
		return nil
	}
	q := p.RingQ()
	other := q.NewPoly()
	for _, rot := range rots {
		q.AutomorphismNTT(r.Forward.Poly, p.GaloisElementForRotation(rot), other)
		for k, qi := range p.Q() {
			for j, x := range other.Coeffs[k] {
				if x%qi != r.Forward.Poly.Coeffs[k][j]%qi {
					return fmt.Errorf("rotation %d does not preserve multiplier", rot)
				}
			}
		}
	}
	return nil
}

func (r *Representation) CheckConjugation(p ckks.Parameters) error {
	if r.Forward == nil {
		return nil
	}
	q := p.RingQ()
	other := q.NewPoly()
	q.AutomorphismNTT(r.Forward.Poly, p.GaloisElementForComplexConjugation(), other)
	for k, qi := range p.Q() {
		for j, x := range other.Coeffs[k] {
			if x%qi != r.Forward.Poly.Coeffs[k][j]%qi {
				return fmt.Errorf("conjugation does not preserve multiplier")
			}
		}
	}
	return nil
}

func imaginaryMultiplier(p ckks.Parameters) *PublicMultiplier {
	coeff := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)}
	r := constantReport("exact i monomial X^(N/2); scale one", ri(1), coeff)
	r.EmbeddingErrorUpper = [2]string{"0", "0"}
	return &PublicMultiplier{integerPoly(p, coeff), scale(ri(1)), r}
}

// Merge multiplier approximates factor*(A-Bh)*(1+sign*h/sqrt(2))/2.
// Rounding is checked exactly in Q(sqrt(2)); residuals are deterministic bounds.
func mergeMultiplier(p ckks.Parameters, r *Representation, sign int64, factor *big.Rat) (*PublicMultiplier, error) {
	a, b := new(big.Rat).SetInt(r.A), new(big.Rat).SetInt(r.B)
	c0 := quad{mul(factor, div(a, ri(2))), mul(factor, mul(ri(-sign), div(b, ri(2))))}
	c1 := quad{mul(factor, div(neg(b), ri(2))), mul(factor, mul(ri(sign), div(a, ri(4))))}
	n0, e := c0.round()
	if e != nil {
		return nil, e
	}
	n1, e := c1.round()
	if e != nil {
		return nil, e
	}
	e0 := quad{sub(new(big.Rat).SetInt(n0), c0.a), neg(c0.b)}
	e1 := quad{sub(new(big.Rat).SetInt(n1), c1.a), neg(c1.b)}
	coeff := []*big.Int{n0, n1, big.NewInt(0), new(big.Int).Neg(n1)}
	report := constantReport("existing-source merge mask; raw integer residual", ri(1), coeff)
	for j, s := range []int64{1, -1} {
		report.EmbeddingErrorUpper[j] = (quad{add(e0.a, mul(ri(2*s), e1.b)), add(e0.b, mul(ri(s), e1.a))}).absUpper().RatString()
	}
	return &PublicMultiplier{integerPoly(p, coeff), scale(ri(1)), report}, nil
}

func scalarConversion(p ckks.Parameters, factor *big.Rat) (*PublicMultiplier, error) {
	n, e := (quad{factor, ri(0)}).round()
	if e != nil {
		return nil, e
	}
	if n.Sign() == 0 {
		return nil, fmt.Errorf("source conversion rounds to zero: choose a larger retained scale or different drop")
	}
	coeff := []*big.Int{n, big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	report := constantReport("existing-source scalar scale conversion", ri(1), coeff)
	err := new(big.Rat).Abs(sub(new(big.Rat).SetInt(n), factor)).RatString()
	report.EmbeddingErrorUpper = [2]string{err, err}
	return &PublicMultiplier{integerPoly(p, coeff), scale(ri(1)), report}, nil
}

func centerPlaintext(p ckks.Parameters, level int, D *big.Rat, r *Representation) (*rlwe.Plaintext, error) {
	f := mul(D, big.NewRat(13, 16))
	if !f.IsInt() {
		return nil, fmt.Errorf("center requires integral dyadic scale")
	}
	a := new(big.Int).Mul(f.Num(), r.A)
	b := new(big.Int).Mul(f.Num(), r.B)
	poly := integerPoly(p, []*big.Int{a, new(big.Int).Neg(b), big.NewInt(0), b})
	p.RingQ().IMForm(poly, poly)
	pt := ckks.NewPlaintext(p, level)
	pt.Value.CopyLvl(level, poly)
	pt.Scale = scale(D)
	return pt, nil
}
