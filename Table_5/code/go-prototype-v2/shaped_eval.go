package lowbootstrap

// Experimental shaped arithmetic for the single-message bootstrap. This file
// intentionally does not modify Lattigo. It covers every method in the common
// polynomial evaluator's schemes.Evaluator interface; embedding ckks.Evaluator
// alone would let its New methods bypass the shaped overrides.

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type ShapedStats struct {
	SubunitCoefficientProducts                                        int
	MinCoefficientLogScale                                            float64
	Rescales, Relinearizations, EncodedConstants, CoefficientProducts int
	ScaleAlignments                                                   int
	MinAlignmentLogRatio                                              float64
}

type ShapedStageHook func(name string, ct *rlwe.Ciphertext) error

type ShapedEvaluator struct {
	AllowSubunitCoefficientScale bool
	// Optional genuine scale of the sine result passed into the inverse
	// polynomial. This changes arithmetic targets, never only the metadata.
	InverseInputLogScale float64
	*ckks.Evaluator
	Params     ckks.Parameters
	R          int
	Focus      complex128
	UnitNTT    ring.Poly
	InverseNTT ring.Poly
	Encoder128 *ckks.Encoder
	Stats      ShapedStats
}

var _ schemes.Evaluator = (*ShapedEvaluator)(nil)

// unitFull and inverseFull are full-ring coefficient vectors (or shorter vectors
// whose remaining coefficients are zero), not compact degree-2R unit vectors.
// The caller must establish their exact inverse relation and common focus value.
func NewShapedEvaluator(params ckks.Parameters, base *ckks.Evaluator, unitFull, inverseFull []*big.Int, replication int, focus complex128) (*ShapedEvaluator, error) {
	if replication < 1 || replication&(replication-1) != 0 || replication > params.MaxSlots() {
		return nil, fmt.Errorf("invalid replication %d", replication)
	}
	if focus == 0 || math.IsNaN(real(focus)) || math.IsNaN(imag(focus)) {
		return nil, fmt.Errorf("invalid focus value %v", focus)
	}
	g, err := PolynomialFromCoefficients(params, unitFull, params.MaxLevel(), true, true)
	if err != nil {
		return nil, err
	}
	gi, err := PolynomialFromCoefficients(params, inverseFull, params.MaxLevel(), true, true)
	if err != nil {
		return nil, err
	}
	return &ShapedEvaluator{Evaluator: base, Params: params, R: replication, Focus: focus,
		UnitNTT: g, InverseNTT: gi, Encoder128: ckks.NewEncoder(params, 128)}, nil
}

func (ev *ShapedEvaluator) rawUnit(ct *rlwe.Ciphertext, inverse bool) (*rlwe.Ciphertext, error) {
	if inverse {
		return MulNTTMontgomeryPolynomial(ev.Params, ct, ev.InverseNTT)
	}
	return MulNTTMontgomeryPolynomial(ev.Params, ct, ev.UnitNTT)
}

func copyShaped(dst, src *rlwe.Ciphertext) {
	dst.Resize(src.Degree(), src.Level())
	dst.Copy(src)
}

// Rescale implements g * round(g^-1*c / p), componentwise. All existing phase
// errors pass through unchanged; the new rounding error has a factor g.
func (ev *ShapedEvaluator) Rescale(in, out *rlwe.Ciphertext) error {
	tmp, err := ev.rawUnit(in, true)
	if err != nil {
		return err
	}
	if err = ev.Evaluator.Rescale(tmp, tmp); err != nil {
		return err
	}
	if tmp, err = ev.rawUnit(tmp, false); err != nil {
		return err
	}
	copyShaped(out, tmp)
	ev.Stats.Rescales++
	return nil
}

// Relinearize conjugates the ordinary switching operation by the unit. Scaling
// the whole degree-two ciphertext is equivalent to shaping only its switched
// contribution, and is simpler to audit. It is deliberately not optimized.
func (ev *ShapedEvaluator) Relinearize(in, out *rlwe.Ciphertext) error {
	if in.Degree() < 2 {
		copyShaped(out, in)
		return nil
	}
	tmp, err := ev.rawUnit(in, true)
	if err != nil {
		return err
	}
	res := ckks.NewCiphertext(ev.Params, 1, tmp.Level())
	if err = ev.Evaluator.Relinearize(tmp, res); err != nil {
		return err
	}
	if res, err = ev.rawUnit(res, false); err != nil {
		return err
	}
	copyShaped(out, res)
	ev.Stats.Relinearizations++
	return nil
}

func scalarComplex(v interface{}) (*bignum.Complex, error) {
	switch x := v.(type) {
	case nil:
		return bignum.ToComplex(0, 128), nil
	case *bignum.Complex:
		if x == nil {
			return bignum.ToComplex(0, 128), nil
		}
		return bignum.ToComplex(x, 128), nil
	case complex128, float64, int, int64, uint64, *big.Int, *big.Float:
		return bignum.ToComplex(x, 128), nil
	case uint:
		return bignum.ToComplex(uint64(x), 128), nil
	default:
		return nil, fmt.Errorf("unsupported shaped scalar %T", v)
	}
}

func divideComplex128(c *bignum.Complex, d complex128) *bignum.Complex {
	// The public focus value is supplied to double precision, but coefficient
	// arithmetic and the FFT use 128 bits to avoid losing shaping precision when
	// the inverse focus value is large. No claim of exact irrational encoding.
	a := new(big.Float).SetPrec(128).SetFloat64(real(d))
	b := new(big.Float).SetPrec(128).SetFloat64(imag(d))
	den := new(big.Float).SetPrec(128).Mul(a, a)
	den.Add(den, new(big.Float).SetPrec(128).Mul(b, b))
	re := new(big.Float).SetPrec(128).Mul(c[0], a)
	re.Add(re, new(big.Float).SetPrec(128).Mul(c[1], b)).Quo(re, den)
	im := new(big.Float).SetPrec(128).Mul(c[1], a)
	im.Sub(im, new(big.Float).SetPrec(128).Mul(c[0], b)).Quo(im, den)
	return &bignum.Complex{re, im}
}

// ShapedPlaintext encodes c*P/g by ordinary nearest rounding, then multiplies
// its integer polynomial by g. Every ideal coefficient constant is zero on
// guards, including Chebyshev's -1 and double-angle additive constants.
func (ev *ShapedEvaluator) ShapedPlaintext(v rlwe.Operand, level int, scale rlwe.Scale) (*rlwe.Plaintext, error) {
	var vals []*bignum.Complex
	var vectorLen int
	switch x := v.(type) {
	case []complex128:
		vectorLen = len(x)
	case []float64:
		vectorLen = len(x)
	case []*big.Float:
		vectorLen = len(x)
	case []*bignum.Complex:
		vectorLen = len(x)
	}
	if vectorLen == 0 {
		c, err := scalarComplex(v)
		if err != nil {
			return nil, err
		}
		vals = make([]*bignum.Complex, ev.R)
		for i := range vals {
			vals[i] = bignum.ToComplex(0, 128)
		}
		vals[0] = divideComplex128(c, ev.Focus)
	} else {
		if vectorLen > ev.Params.MaxSlots() || vectorLen&(vectorLen-1) != 0 || vectorLen < ev.R {
			return nil, fmt.Errorf("invalid shaped coefficient vector length %d", vectorLen)
		}
		vals = make([]*bignum.Complex, vectorLen)
		for i := range vals {
			vals[i] = bignum.ToComplex(0, 128)
			if i%ev.R != 0 {
				continue
			}
			var z interface{}
			switch x := v.(type) {
			case []complex128:
				z = x[i]
			case []float64:
				z = x[i]
			case []*big.Float:
				z = x[i]
				if x[i] == nil {
					z = 0
				}
			case []*bignum.Complex:
				z = x[i]
			}
			c, err := scalarComplex(z)
			if err != nil {
				return nil, err
			}
			vals[i] = divideComplex128(c, ev.Focus)
		}
	}
	pt := ckks.NewPlaintext(ev.Params, level)
	pt.Scale = scale
	pt.LogDimensions.Rows = 0
	pt.LogDimensions.Cols = bits.Len(uint(len(vals))) - 1
	if err := ev.Encoder128.Encode(vals, pt); err != nil {
		return nil, err
	}
	if !pt.IsNTT {
		return nil, fmt.Errorf("shaped plaintext requires NTT output")
	}
	ev.Params.RingQ().AtLevel(level).MulCoeffsMontgomery(pt.Value, ev.UnitNTT, pt.Value)
	ev.Stats.EncodedConstants++
	return pt, nil
}

func (ev *ShapedEvaluator) Add(a *rlwe.Ciphertext, b rlwe.Operand, out *rlwe.Ciphertext) error {
	if bc, ok := b.(*rlwe.Ciphertext); ok && !a.Scale.InDelta(bc.Scale, 100) {
		return ev.addAtDifferentScales(a, bc, false, out)
	}
	if _, ok := b.(rlwe.ElementInterface[ring.Poly]); ok {
		return ev.Evaluator.Add(a, b, out)
	}
	pt, err := ev.ShapedPlaintext(b, a.Level(), a.Scale)
	if err != nil {
		return err
	}
	return ev.Evaluator.Add(a, pt, out)
}
func (ev *ShapedEvaluator) AddNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	out := ckks.NewCiphertext(ev.Params, a.Degree(), a.Level())
	return out, ev.Add(a, b, out)
}
func (ev *ShapedEvaluator) Sub(a *rlwe.Ciphertext, b rlwe.Operand, out *rlwe.Ciphertext) error {
	if bc, ok := b.(*rlwe.Ciphertext); ok && !a.Scale.InDelta(bc.Scale, 100) {
		return ev.addAtDifferentScales(a, bc, true, out)
	}
	if _, ok := b.(rlwe.ElementInterface[ring.Poly]); ok {
		return ev.Evaluator.Sub(a, b, out)
	}
	pt, err := ev.ShapedPlaintext(b, a.Level(), a.Scale)
	if err != nil {
		return err
	}
	return ev.Evaluator.Sub(a, pt, out)
}
func (ev *ShapedEvaluator) SubNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	out := ckks.NewCiphertext(ev.Params, a.Degree(), a.Level())
	return out, ev.Sub(a, b, out)
}

// Lattigo's ordinary Add/Sub rounds a nonintegral scale ratio to an integer.
// In Chebyshev recurrences that creates unshaped coefficient error. Align the
// lower-scale ciphertext with an encoded, shaped +/-P coefficient instead.
// This consumes no extra level: the higher-scale accumulator already provides
// the required coefficient scale. It assumes all ideal guard values are zero.
func (ev *ShapedEvaluator) addAtDifferentScales(a, b *rlwe.Ciphertext, subtract bool, out *rlwe.Ciphertext) error {
	hi, lo := a.CopyNew(), b.CopyNew()
	sign := 1
	if subtract {
		sign = -1
	}
	if a.Scale.Cmp(b.Scale) < 0 {
		hi, lo = b.CopyNew(), a.CopyNew()
		if subtract {
			if err := ev.Evaluator.Mul(hi, big.NewInt(-1), hi); err != nil {
				return err
			}
		}
		sign = 1
	}
	ratio := hi.Scale.Div(lo.Scale).Float64()
	if ratio < 2 {
		return fmt.Errorf("shaped scale alignment ratio %.17g is too small for a stable masked coefficient", ratio)
	}
	if ev.Stats.ScaleAlignments == 0 || math.Log2(ratio) < ev.Stats.MinAlignmentLogRatio {
		ev.Stats.MinAlignmentLogRatio = math.Log2(ratio)
	}
	ev.Stats.ScaleAlignments++
	level := min(a.Level(), b.Level())
	degree := max(a.Degree(), b.Degree())
	hi.Resize(degree, level)
	copyShaped(out, hi)
	return ev.MulThenAdd(lo, sign, out)
}

func (ev *ShapedEvaluator) plaintextProductScale(level int) rlwe.Scale {
	s := rlwe.NewScale(1)
	for j := 0; j < ev.Params.LevelsConsumedPerRescaling(); j++ {
		s = s.Mul(rlwe.NewScale(ev.Params.Q()[level-j]))
	}
	return s
}

func (ev *ShapedEvaluator) Mul(a *rlwe.Ciphertext, b rlwe.Operand, out *rlwe.Ciphertext) error {
	if _, ok := b.(rlwe.ElementInterface[ring.Poly]); ok {
		return ev.Evaluator.Mul(a, b, out)
	}
	pt, err := ev.ShapedPlaintext(b, a.Level(), ev.plaintextProductScale(a.Level()))
	if err != nil {
		return err
	}
	return ev.Evaluator.Mul(a, pt, out)
}
func (ev *ShapedEvaluator) MulNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	degree := a.Degree()
	level := a.Level()
	if el, ok := b.(rlwe.ElementInterface[ring.Poly]); ok {
		degree += el.Degree()
		if el.Level() < level {
			level = el.Level()
		}
	}
	out := ckks.NewCiphertext(ev.Params, degree, level)
	return out, ev.Mul(a, b, out)
}
func (ev *ShapedEvaluator) MulRelin(a *rlwe.Ciphertext, b rlwe.Operand, out *rlwe.Ciphertext) error {
	tmp, err := ev.MulNew(a, b)
	if err != nil {
		return err
	}
	return ev.Relinearize(tmp, out)
}
func (ev *ShapedEvaluator) MulRelinNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	out := ckks.NewCiphertext(ev.Params, 1, a.Level())
	return out, ev.MulRelin(a, b, out)
}

func (ev *ShapedEvaluator) MulThenAdd(a *rlwe.Ciphertext, b rlwe.Operand, out *rlwe.Ciphertext) error {
	if _, ok := b.(rlwe.ElementInterface[ring.Poly]); ok {
		return ev.Evaluator.MulThenAdd(a, b, out)
	}
	level := a.Level()
	if out.Level() < level {
		level = out.Level()
	}
	if a.Scale.Cmp(out.Scale) > 0 && !ev.AllowSubunitCoefficientScale {
		return fmt.Errorf("shaped MulThenAdd: source scale exceeds accumulator")
	}
	if a.Scale.Cmp(out.Scale) == 0 {
		s := ev.plaintextProductScale(level)
		z := new(big.Int)
		s.Value.Int(z)
		if err := ev.Evaluator.Mul(out, z, out); err != nil {
			return err
		}
		out.Scale = out.Scale.Mul(s)
	}
	coefficientScale := out.Scale.Div(a.Scale)
	if coefficientScale.Cmp(rlwe.NewScale(1)) < 0 {
		logRatio := math.Log2(coefficientScale.Float64())
		if ev.Stats.SubunitCoefficientProducts == 0 || logRatio < ev.Stats.MinCoefficientLogScale {
			ev.Stats.MinCoefficientLogScale = logRatio
		}
		ev.Stats.SubunitCoefficientProducts++
	}
	// PA may encode a coefficient at positive scale <1: the inverse focus
	// amplifies the target before integer rounding. This is not a scale relabel.
	// Its data/guard encoding errors must still be bounded for the full circuit.
	pt, err := ev.ShapedPlaintext(b, level, coefficientScale)
	if err != nil {
		return err
	}
	ev.Stats.CoefficientProducts++
	return ev.Evaluator.MulThenAdd(a, pt, out)
}

// EvaluateShapedMod1 expects the actual decoded input t=(I+z/beta)/K.
// It never silently changes input scale. targetFractionalScale is the desired
// scale of the fractional result y≈z/beta after ALL double-angle rescales.
// Choose beta*Delta_out to finish at Delta_out after recovering message units.
// With deferLast=true, the final prime remains and the returned scale includes
// that prime: divide Scale by beta and call shaped Rescale once to combine the
// guard-reset square with final scale return.
func EvaluateShapedMod1(ev *ShapedEvaluator, input *rlwe.Ciphertext, plan mod1.Parameters, targetFractionalScale rlwe.Scale, deferLast bool, hook ShapedStageHook) (*rlwe.Ciphertext, error) {
	// An inverse (arcsine) polynomial consumes its own levels after all DA
	// rescales. There is no deferred final DA rescale for callers to consume.
	deferLast = deferLast && plan.Mod1InvPoly == nil
	ct := input.CopyNew()
	depth := plan.Mod1Poly.Depth() + plan.DoubleAngle
	if plan.Mod1InvPoly != nil {
		depth += plan.Mod1InvPoly.Depth()
	}
	if ct.Level() < depth {
		return nil, fmt.Errorf("insufficient EvalMod levels")
	}
	notify := func(name string, c *rlwe.Ciphertext) error {
		if hook != nil {
			return hook(name, c)
		}
		return nil
	}
	if err := notify("evalmod_input", ct); err != nil {
		return nil, err
	}
	target := targetFractionalScale
	if plan.Mod1InvPoly != nil && ev.InverseInputLogScale > 0 {
		target = rlwe.NewScale(math.Exp2(ev.InverseInputLogScale))
	}
	Q := ev.Params.Q()
	for i := 0; i < plan.DoubleAngle; i++ {
		idx := ct.Level() - plan.Mod1Poly.Depth() - plan.DoubleAngle + i + 1
		if idx < 1 || idx >= len(Q) {
			return nil, fmt.Errorf("invalid double-angle prime index %d", idx)
		}
		target = target.Mul(rlwe.NewScale(Q[idx]))
		target.Value.Sqrt(&target.Value)
	}
	if plan.Mod1Type == mod1.CosDiscrete || plan.Mod1Type == mod1.CosContinuous {
		offset := new(big.Float).Sub(&plan.Mod1Poly.B, &plan.Mod1Poly.A)
		offset.Mul(offset, new(big.Float).SetFloat64(plan.IntervalShrinkFactor()))
		offset.Quo(new(big.Float).SetFloat64(-0.5), offset)
		if err := ev.Add(ct, offset, ct); err != nil {
			return nil, err
		}
	}
	if err := notify("evalmod_shifted", ct); err != nil {
		return nil, err
	}
	pe := polynomial.NewEvaluator(ev.Params, ev.Evaluator)
	pe.Evaluator.Evaluator = ev
	res, err := pe.Evaluate(ct, plan.Mod1Poly, target)
	if err != nil {
		return nil, fmt.Errorf("shaped polynomial: %w", err)
	}
	if err = notify("evalmod_polynomial", res); err != nil {
		return nil, err
	}
	c := plan.Sqrt2Pi
	for j := 0; j < plan.DoubleAngle; j++ {
		c *= c
		if err = ev.MulRelin(res, res, res); err != nil {
			return nil, err
		}
		if err = ev.Add(res, res, res); err != nil {
			return nil, err
		}
		if err = ev.Add(res, -c, res); err != nil {
			return nil, err
		}
		if err = notify(fmt.Sprintf("evalmod_da_%d_before_rescale", j+1), res); err != nil {
			return nil, err
		}
		if !(deferLast && j+1 == plan.DoubleAngle) {
			if err = ev.Rescale(res, res); err != nil {
				return nil, err
			}
		}
		if err = notify(fmt.Sprintf("evalmod_da_%d", j+1), res); err != nil {
			return nil, err
		}
	}
	if plan.Mod1InvPoly != nil {
		if res, err = pe.Evaluate(res, *plan.Mod1InvPoly, targetFractionalScale); err != nil {
			return nil, fmt.Errorf("shaped inverse polynomial: %w", err)
		}
		if err = notify("evalmod_inverse_polynomial", res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// Mod1PlaintextOracle evaluates the exact compiled Chebyshev coefficients,
// including the input offset and DA constants, on normalized input t. The data
// target is plan.QDiff*Scaling*sin(2*pi*K*t)/(2*pi); guards use a different
// masked circuit whose zero input stays exactly zero.
func Mod1PlaintextOracle(plan mod1.Parameters, t float64) float64 {
	return real(Mod1ComplexPlaintextOracle(plan, complex(t, 0)))
}

// Mod1ComplexPlaintextOracle also propagates the small imaginary noise of an
// encrypted real slot, so tests can separate input noise from circuit noise.
func Mod1ComplexPlaintextOracle(plan mod1.Parameters, t complex128) complex128 {
	if plan.Mod1Type == mod1.CosDiscrete || plan.Mod1Type == mod1.CosContinuous {
		t -= complex(1/(4*plan.K), 0)
	}
	a, b := complex(1, 0), t
	y := complex(0, 0)
	for j, c := range plan.Mod1Poly.Coeffs {
		if j > 1 {
			a, b = b, 2*t*b-a
		}
		v := a
		if j > 0 {
			v = b
		}
		if c != nil {
			x, _ := c[0].Float64()
			xi, _ := c[1].Float64()
			y += complex(x, xi) * v
		}
	}
	c := plan.Sqrt2Pi
	for j := 0; j < plan.DoubleAngle; j++ {
		c *= c
		y = 2*y*y - complex(c, 0)
	}
	if plan.Mod1InvPoly != nil {
		z := complex(0, 0)
		for j := len(plan.Mod1InvPoly.Coeffs) - 1; j >= 0; j-- {
			z *= y
			if coefficient := plan.Mod1InvPoly.Coeffs[j]; coefficient != nil {
				r, _ := coefficient[0].Float64()
				i, _ := coefficient[1].Float64()
				z += complex(r, i)
			}
		}
		y = z
	}
	return y
}
