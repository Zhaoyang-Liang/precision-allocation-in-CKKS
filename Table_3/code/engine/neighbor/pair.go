// Package neighbor provides PUBLIC-ARITHMETIC Tuple building blocks for
// Lattigo v6.2.0. The Context wrapper and cmd/tuplebench connect these primitives.
// The complete reference runner remains unvalidated with real HE here.
// References: ePrint 2023/1788 Definitions 3.3, 4.3, 4.5; 2024/1014 Appendix B.
package neighbor

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Pair represents qDiv*Hi+Lo at one common logical scale. The two components
// are correlated and must NEVER be independently encrypted as plaintext digits.
type Pair struct {
	Hi, Lo *rlwe.Ciphertext
	QDiv   uint64
}

func compatible(p ckks.Parameters, c *rlwe.Ciphertext) error {
	if c == nil || c.MetaData == nil || c.Level() < 0 || c.Level() > p.MaxLevel() || c.N() != p.N() {
		return fmt.Errorf("incompatible ciphertext")
	}
	if c.IsMontgomery {
		return fmt.Errorf("Montgomery input is not supported")
	}
	return nil
}

// Decompose drops the LAST prime qDiv of ext. RCB(Pair) equals the input
// reduced modulo the remaining Q, component by component, with exact arithmetic.
// Metadata stores the LOGICAL scale; neither Hi nor Lo is a standalone message.
func Decompose(ext ckks.Parameters, ct *rlwe.Ciphertext) (Pair, error) {
	if e := compatible(ext, ct); e != nil {
		return Pair{}, e
	}
	l := ct.Level()
	if l < 1 {
		return Pair{}, fmt.Errorf("need Q and qDiv")
	}
	q := ext.Q()[l]
	r := ext.RingQ().AtLevel(l)
	rq := ext.RingQ().AtLevel(l - 1)
	hi := rlwe.NewCiphertext(ext, ct.Degree(), l-1)
	lo := rlwe.NewCiphertext(ext, ct.Degree(), l-1)
	hi.MetaData = ct.MetaData.CopyNew()
	lo.MetaData = ct.MetaData.CopyNew()
	for k := range ct.Value {
		if ct.IsNTT {
			r.DivRoundByLastModulusNTT(ct.Value[k], hi.Value[k])
		} else {
			r.DivRoundByLastModulus(ct.Value[k], hi.Value[k])
		}
		rq.MulScalar(hi.Value[k], q, lo.Value[k])
		rq.Sub(ct.Value[k], lo.Value[k], lo.Value[k])
	}
	return Pair{hi, lo, q}, nil
}

func (p Pair) validate(base ckks.Parameters) error {
	if e := compatible(base, p.Hi); e != nil {
		return e
	}
	if e := compatible(base, p.Lo); e != nil {
		return e
	}
	if p.QDiv < 2 || p.Hi.Level() != p.Lo.Level() || p.Hi.Degree() != p.Lo.Degree() || !p.Hi.MetaData.Equal(p.Lo.MetaData) {
		return fmt.Errorf("pair shape or logical metadata mismatch")
	}
	return nil
}

func (p Pair) Recombine(base ckks.Parameters) (*rlwe.Ciphertext, error) {
	if e := p.validate(base); e != nil {
		return nil, e
	}
	out := p.Hi.CopyNew()
	r := base.RingQ().AtLevel(out.Level())
	for k := range out.Value {
		r.MulScalar(p.Hi.Value[k], p.QDiv, out.Value[k])
		r.Add(out.Value[k], p.Lo.Value[k], out.Value[k])
	}
	return out, nil
}

// ScaleUp is the exact injection a mod Q -> qDiv*a mod qDiv*Q.
// ext must have precisely the active base Q prefix followed by qDiv. This is
// NOT ModUp of an arbitrary centered representative: the new residue is zero.
func ScaleUp(base, ext ckks.Parameters, ct *rlwe.Ciphertext, qDiv uint64) (*rlwe.Ciphertext, error) {
	if e := compatible(base, ct); e != nil {
		return nil, e
	}
	l := ct.Level()
	if ext.N() != base.N() || ext.MaxLevel() != l+1 || ext.Q()[l+1] != qDiv {
		return nil, fmt.Errorf("wrong extended modulus")
	}
	for i := 0; i <= l; i++ {
		if base.Q()[i] != ext.Q()[i] {
			return nil, fmt.Errorf("Q prefix mismatch")
		}
	}
	out := rlwe.NewCiphertext(ext, ct.Degree(), l+1)
	out.MetaData = ct.MetaData.CopyNew()
	out.Scale = ct.Scale.Mul(rlwe.NewScale(qDiv))
	for k := range ct.Value {
		base.RingQ().AtLevel(l).MulScalar(ct.Value[k], qDiv, out.Value[k])
	}
	// NewCiphertext zero-initializes the qDiv limb, in coefficient and NTT form.
	return out, nil
}

// RescaleOne implements RS2, preserving its correlated low component.
// Independently rescaling Hi and Lo is NOT equivalent.
func (p Pair) RescaleOne(base ckks.Parameters) (Pair, error) {
	if e := p.validate(base); e != nil {
		return Pair{}, e
	}
	l := p.Hi.Level()
	if l < 1 {
		return Pair{}, fmt.Errorf("no modulus available for rescale")
	}
	combined, e := p.Recombine(base)
	if e != nil {
		return Pair{}, e
	}
	rs := func(c *rlwe.Ciphertext) *rlwe.Ciphertext {
		out := rlwe.NewCiphertext(base, c.Degree(), l-1)
		out.MetaData = c.MetaData.CopyNew()
		out.Scale = c.Scale.Div(rlwe.NewScale(base.Q()[l]))
		r := base.RingQ().AtLevel(l)
		for k := range c.Value {
			if c.IsNTT {
				r.DivRoundByLastModulusNTT(c.Value[k], out.Value[k])
			} else {
				r.DivRoundByLastModulus(c.Value[k], out.Value[k])
			}
		}
		return out
	}
	hi := rs(p.Hi)
	lo := rs(combined)
	r := base.RingQ().AtLevel(l - 1)
	for k := range lo.Value {
		r.MulScalarThenSub(hi.Value[k], p.QDiv, lo.Value[k])
	}
	return Pair{hi, lo, p.QDiv}, nil
}

// SquareRelinearize implements Tensor2 (square specialization) and Relin2.
// The caller supplies evaluators with SAME-SECRET keys over Q and qDiv*Q.
// ext must match the ACTIVE Q prefix followed by qDiv, even below top level.
// Calls: 2 ciphertext products, 2 relinearizations (one at extended Q),
// 1 exact lift and 1 correlated decomposition. No rescale is hidden here.
// This is an unbenchmarked reference port; full key/context ownership, security,
// low-component bounds and end-to-end HE tests are the caller's responsibility.
func (p Pair) SquareRelinearize(base, ext ckks.Parameters, evBase, evExt *ckks.Evaluator) (Pair, error) {
	if e := p.validate(base); e != nil {
		return Pair{}, e
	}
	if p.Hi.Degree() != 1 || evBase == nil || evExt == nil {
		return Pair{}, fmt.Errorf("need degree-one pair and evaluators")
	}
	hi, e := evBase.MulNew(p.Hi, p.Hi)
	if e != nil {
		return Pair{}, e
	}
	lo, e := evBase.MulNew(p.Hi, p.Lo)
	if e != nil {
		return Pair{}, e
	}
	r := base.RingQ().AtLevel(lo.Level())
	for k := range lo.Value {
		r.MulScalar(lo.Value[k], 2, lo.Value[k])
	}
	logical := p.Hi.Scale.Mul(p.Hi.Scale).Div(rlwe.NewScale(p.QDiv))
	hi.Scale = logical
	lo.Scale = logical
	lifted, e := ScaleUp(base, ext, hi, p.QDiv)
	if e != nil {
		return Pair{}, e
	}
	hRelin, e := evExt.RelinearizeNew(lifted)
	if e != nil {
		return Pair{}, e
	}
	out, e := Decompose(ext, hRelin)
	if e != nil {
		return Pair{}, e
	}
	out.Hi.Scale = logical
	out.Lo.Scale = logical
	lRelin, e := evBase.RelinearizeNew(lo)
	if e != nil {
		return Pair{}, e
	}
	for k := range out.Lo.Value {
		r.Add(out.Lo.Value[k], lRelin.Value[k], out.Lo.Value[k])
	}
	return out, nil
}
