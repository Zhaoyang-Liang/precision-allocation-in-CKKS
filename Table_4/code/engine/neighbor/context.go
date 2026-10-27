package neighbor

import (
	"crypto/sha256"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"slices"
)

// Context uses [qDiv,Q...] in its extended basis, so active levels are prefixes.
// Exactly one base and one extended relinearization key suffice for all levels.
// A last-prime view is used only for public correlated decomposition.
type Context struct {
	Base, Extended ckks.Parameters
	QDiv           uint64
	ID             string
	decomposition  []ckks.Parameters
}
type BoundPair struct {
	Pair      Pair
	ContextID string
}

func NewContext(base ckks.Parameters, qDiv uint64) (*Context, error) {
	if qDiv < 3 {
		return nil, fmt.Errorf("invalid divisor prime")
	}
	for _, q := range append(slices.Clone(base.Q()), base.P()...) {
		if q == qDiv {
			return nil, fmt.Errorf("divisor overlaps Q/P")
		}
	}
	lit := base.ParametersLiteral()
	lit.Q = append([]uint64{qDiv}, base.Q()...)
	ext, err := ckks.NewParametersFromLiteral(lit)
	if err != nil {
		return nil, err
	}
	c := &Context{Base: base, Extended: ext, QDiv: qDiv}
	c.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d/%v/%v/%d", base.N(), base.Q(), base.P(), qDiv))))
	for level := 0; level <= base.MaxLevel(); level++ {
		l := base.ParametersLiteral()
		l.Q = append(slices.Clone(base.Q()[:level+1]), qDiv)
		p, e := ckks.NewParametersFromLiteral(l)
		if e != nil {
			return nil, e
		}
		c.decomposition = append(c.decomposition, p)
	}
	return c, nil
}
func (c *Context) Validate(p BoundPair) error {
	if p.ContextID != c.ID || p.Pair.QDiv != c.QDiv {
		return fmt.Errorf("Tuple context identity mismatch")
	}
	if err := p.Pair.validate(c.Base); err != nil {
		return err
	}
	if !p.Pair.Hi.IsNTT || p.Pair.Hi.Scale.Value.IsInf() || p.Pair.Hi.Scale.Value.Sign() <= 0 {
		return fmt.Errorf("need NTT pair with positive logical scale")
	}
	return nil
}

// ProjectSecret removes the divisor limb from a SAME integer secret. It does
// not sample a new key. The caller owns both keys and never exports either.
func (c *Context) ProjectSecret(ext *rlwe.SecretKey) (*rlwe.SecretKey, error) {
	if ext == nil || ext.LevelQ() != c.Extended.MaxLevel() || ext.LevelP() != c.Extended.MaxLevelP() || ext.Value.Q.N() != c.Base.N() {
		return nil, fmt.Errorf("secret context shape mismatch")
	}
	out := rlwe.NewSecretKey(c.Base)
	for i := range out.Value.Q.Coeffs {
		copy(out.Value.Q.Coeffs[i], ext.Value.Q.Coeffs[i+1])
	}
	for i := range out.Value.P.Coeffs {
		copy(out.Value.P.Coeffs[i], ext.Value.P.Coeffs[i])
	}
	return out, nil
}
func (c *Context) Decompose(ct *rlwe.Ciphertext) (BoundPair, error) {
	if err := compatible(c.Extended, ct); err != nil {
		return BoundPair{}, err
	}
	if ct.Level() < 1 {
		return BoundPair{}, fmt.Errorf("extended Q needs divisor and active Q")
	}
	l := ct.Level() - 1
	// Read-only coefficient views; only slice headers are reordered. Decompose
	// writes fresh Hi/Lo buffers. Avoid a full ciphertext copy just to permute RNS.
	view := *ct
	view.Value = append(ct.Value[:0:0], ct.Value...)
	for k := range view.Value {
		view.Value[k].Coeffs = append([][]uint64(nil), ct.Value[k].Coeffs[1:]...)
		view.Value[k].Coeffs = append(view.Value[k].Coeffs, ct.Value[k].Coeffs[0])
	}

	p, err := Decompose(c.decomposition[l], &view)
	return BoundPair{p, c.ID}, err
}
func (c *Context) Recombine(p BoundPair) (*rlwe.Ciphertext, error) {
	if err := c.Validate(p); err != nil {
		return nil, err
	}
	return p.Pair.Recombine(c.Base)
}
func (c *Context) ExactLift(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if err := compatible(c.Base, ct); err != nil {
		return nil, err
	}
	l := ct.Level()
	out := rlwe.NewCiphertext(c.Extended, ct.Degree(), l+1)
	out.MetaData = ct.MetaData.CopyNew()
	out.Scale = ct.Scale.Mul(rlwe.NewScale(c.QDiv))
	for k := range ct.Value {
		// Shifted output view: the zero divisor limb is never basis-extended.
		v := out.Value[k]
		v.Coeffs = v.Coeffs[1:]
		c.Base.RingQ().AtLevel(l).MulScalar(ct.Value[k], c.QDiv, v)
	}
	return out, nil
}
func (c *Context) RescaleOne(p BoundPair) (BoundPair, error) {
	if err := c.Validate(p); err != nil {
		return BoundPair{}, err
	}
	v, err := p.Pair.RescaleOne(c.Base)
	return BoundPair{v, c.ID}, err
}
func (c *Context) Square(p BoundPair, eb, ee *ckks.Evaluator) (BoundPair, error) {
	if err := c.Validate(p); err != nil {
		return BoundPair{}, err
	}
	if p.Pair.Hi.Degree() != 1 || eb == nil || ee == nil {
		return BoundPair{}, fmt.Errorf("need degree-one pair and both evaluators")
	}
	for _, item := range []struct {
		e *ckks.Evaluator
		p ckks.Parameters
	}{{eb, c.Base}, {ee, c.Extended}} {
		r := item.e.GetRLWEParameters()
		if r.N() != item.p.N() || !slices.Equal(r.Q(), item.p.Q()) || !slices.Equal(r.P(), item.p.P()) {
			return BoundPair{}, fmt.Errorf("evaluator context mismatch")
		}
	}
	hi, err := eb.MulNew(p.Pair.Hi, p.Pair.Hi)
	if err != nil {
		return BoundPair{}, err
	}
	lo, err := eb.MulNew(p.Pair.Hi, p.Pair.Lo)
	if err != nil {
		return BoundPair{}, err
	}
	r := c.Base.RingQ().AtLevel(lo.Level())
	for k := range lo.Value {
		r.MulScalar(lo.Value[k], 2, lo.Value[k])
	}
	logical := p.Pair.Hi.Scale.Mul(p.Pair.Hi.Scale).Div(rlwe.NewScale(c.QDiv))
	hi.Scale = logical
	lo.Scale = logical
	lifted, err := c.ExactLift(hi)
	if err != nil {
		return BoundPair{}, err
	}
	hr, err := ee.RelinearizeNew(lifted)
	if err != nil {
		return BoundPair{}, err
	}
	out, err := c.Decompose(hr)
	if err != nil {
		return BoundPair{}, err
	}
	out.Pair.Hi.Scale = logical
	out.Pair.Lo.Scale = logical
	lr, err := eb.RelinearizeNew(lo)
	if err != nil {
		return BoundPair{}, err
	}
	for k := range out.Pair.Lo.Value {
		r.Add(out.Pair.Lo.Value[k], lr.Value[k], out.Pair.Lo.Value[k])
	}
	return out, nil
}
