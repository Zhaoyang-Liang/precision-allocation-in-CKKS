package bench

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func profileMultiplier(p ckks.Parameters, m *ProfileMultiplier, precision uint) (*PublicMultiplier, []*big.Float, error) {
	if m == nil {
		return nil, []*big.Float{bf(ri(1), precision)}, nil
	}
	coeff, e := parseIntegerCoefficients(m.Coefficients)
	if e != nil {
		return nil, nil, e
	}
	if len(coeff) != 2*m.Period || p.N()%len(coeff) != 0 {
		return nil, nil, fmt.Errorf("invalid subring multiplier")
	}
	weights := make([]*big.Float, m.Period)
	for j, row := range m.Embeddings {
		lo, e := rat(row.Lower)
		if e != nil {
			return nil, nil, e
		}
		hi, e := rat(row.Upper)
		if e != nil {
			return nil, nil, e
		}
		if lo.Cmp(hi) > 0 || lo.Sign()*hi.Sign() <= 0 {
			return nil, nil, fmt.Errorf("invalid signed embedding interval")
		}
		weights[j] = bf(div(add(lo, hi), ri(2)), precision)
	}
	forward := &PublicMultiplier{Poly: integerPoly(p, coeff), Scale: scale(ri(1)), Report: ConstantReport{Purpose: "exact general subring multiplier; coefficients and period in profile config", Scale: "1"}}
	return forward, weights, nil
}

func profileValues(c *ProfileConfig, p ckks.Parameters, m ProfileBatchMap, weights []*big.Float, inputs [][]*big.Rat) []*bignum.Complex {
	values := make([]*bignum.Complex, p.MaxSlots())
	for j := range values {
		values[j] = bignum.ToComplex(0, c.Precision)
	}
	for _, v := range m.Values {
		x := bf(inputs[v.Group][v.Index], c.Precision)
		x.Quo(x, weights[v.Slot%len(weights)])
		values[v.Slot][0].Set(x)
	}
	return values
}

func encodeProfilePlain(c *ProfileConfig, b ProfileBranch, p ckks.Parameters, enc *ckks.Encoder, m ProfileBatchMap, weights []*big.Float, inputs [][]*big.Rat) (*rlwe.Plaintext, error) {
	pt := ckks.NewPlaintext(p, p.MaxLevel())
	pt.Scale = scale(pow2(b.ScaleBits))
	if e := enc.Encode(profileValues(c, p, m, weights, inputs), pt); e != nil {
		return nil, e
	}
	return pt, nil
}
