package lowbootstrap

import (
	"fmt"
	"math"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	commonlintrans "github.com/tuneinsight/lattigo/v6/circuits/common/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// NewShapedFiberMatrix shapes the plaintext-encoding error of a CtS matrix.
// Its ideal diagonals must vanish outside the data class s%R == 0. unitFull
// contains integer coefficients in the full degree-N ring (nil entries mean
// zero), belongs to the degree-2R subring, and has common positive data value
// focus. The caller establishes that it is a unit; invertibility is not needed
// by this public encoding routine. Inputs are neither retained nor modified.
//
// Let d_o be a diagonal and let j be its BSGS giant-step offset. Lattigo stores
// the encoding of tau_{-j}(d_o), then applies tau_j during evaluation. We encode
// tau_{-j}(d_o/focus) at the original scale S and multiply its QP integer
// polynomial by tau_{-j}(g), using exact NTT/Montgomery multiplication. Since
// d_o is supported on the common-focus data class, the resulting diagonal is
//
//	tau_{-j}(d_o) + tau_{-j}(g)*rho_{o,j}/S.
//
// After the giant rotation its encoding error is g*tau_j(rho_{o,j})/S. Using
// unrotated g on every stored diagonal would instead produce tau_j(g) and
// corrupt the ideal transform whenever j does not preserve the data class.
// Both Q and P limbs must be multiplied: the BSGS evaluator uses QP hoisting
// and ModDown. Two Montgomery operands produce one Montgomery result.
//
// This changes no matrix/ciphertext scale, consumes no modulus prime, and uses
// no evaluation keys. It shapes only diagonal quantization. Input error,
// ordinary baby/giant rotation KS noise and ModDown rounding are not thereby
// shaped. On data, the quantization contribution is bounded by
// |focus|/S * sum_o |sigma(rho_o)|*|sigma(tau_o(input))|; guard weights use the
// corresponding |sigma(g)|. Actual high-Q no-wrap and later guard recovery
// remain obligations of the caller. Approximate focus/diagonal source values
// also contribute deterministic numerical error; g is never reconstructed
// from floating-point embeddings.
func NewShapedFiberMatrix(params ckks.Parameters, diags lintrans.Diagonals[complex128], level int, scale rlwe.Scale, R int, unitFull []*big.Int, focus *big.Float) (lintrans.LinearTransformation, error) {
	empty := lintrans.LinearTransformation{}
	if level < 0 || level > params.MaxLevel() || scale.Value.Sign() <= 0 || scale.Value.IsInf() {
		return empty, fmt.Errorf("invalid shaped fiber level or scale")
	}
	if R < 1 || R&(R-1) != 0 || params.N()%(2*R) != 0 || len(unitFull) != params.N() {
		return empty, fmt.Errorf("invalid shaped fiber unit dimension or class count")
	}
	if focus == nil || focus.Sign() <= 0 || focus.IsInf() {
		return empty, fmt.Errorf("shaped fiber focus must be finite and positive")
	}
	full := make([]*big.Int, params.N())
	zero := new(big.Int)
	stride := params.N() / (2 * R)
	for i, c := range unitFull {
		full[i] = zero
		if c != nil {
			if c.Sign() != 0 && i%stride != 0 {
				return empty, fmt.Errorf("unit coefficient %d is outside the degree-%d subring", i, 2*R)
			}
			full[i] = c
		}
	}
	for i := 1; i < params.N(); i++ {
		if new(big.Int).Add(full[i], full[params.N()-i]).Sign() != 0 {
			return empty, fmt.Errorf("shaped fiber requires a real unit")
		}
	}
	// Check the supplied common embedding once, with enough precision for the
	// current ~40-bit suppressions. This catches inverted/shifted unit profiles.
	const validationPrecision = 256
	computed := new(big.Float).SetPrec(validationPrecision)
	for j := 0; j < 2*R; j++ {
		if c := full[j*stride]; c.Sign() != 0 {
			angle := new(big.Float).SetPrec(validationPrecision).Mul(bignum.Pi(validationPrecision), new(big.Float).SetInt64(int64(j)))
			angle.Quo(angle, new(big.Float).SetInt64(int64(2*R)))
			term := new(big.Float).SetPrec(validationPrecision).SetInt(c)
			term.Mul(term, bignum.Cos(angle))
			computed.Add(computed, term)
		}
	}
	if computed.Sign() <= 0 {
		return empty, fmt.Errorf("unit data embedding is not positive")
	}
	difference := new(big.Float).SetPrec(validationPrecision).Sub(computed, focus)
	difference.Abs(difference)
	relative := new(big.Float).SetPrec(validationPrecision).Quo(difference, computed)
	tolerance := new(big.Float).SetPrec(validationPrecision).SetMantExp(new(big.Float).SetInt64(1), -80)
	if relative.Cmp(tolerance) > 0 {
		return empty, fmt.Errorf("supplied shaped fiber focus does not match integer unit (relative error %g)", relative)
	}

	inverseDiags := make(lintrans.Diagonals[*bignum.Complex], len(diags))
	for offset, values := range diags {
		if len(values) != params.MaxSlots() {
			return empty, fmt.Errorf("shaped fiber diagonal %d has %d slots, want %d", offset, len(values), params.MaxSlots())
		}
		inverse := make([]*bignum.Complex, len(values))
		for s, v := range values {
			if math.IsNaN(real(v)) || math.IsNaN(imag(v)) || math.IsInf(real(v), 0) || math.IsInf(imag(v), 0) {
				return empty, fmt.Errorf("non-finite shaped fiber diagonal %d slot %d", offset, s)
			}
			if s%R != 0 && v != 0 {
				return empty, fmt.Errorf("shaped fiber diagonal %d has nonzero guard at slot %d", offset, s)
			}
			inverse[s] = bignum.ToComplex(v, 128)
			inverse[s][0].Quo(inverse[s][0], focus)
			inverse[s][1].Quo(inverse[s][1], focus)
		}
		inverseDiags[offset] = inverse
	}
	lt := lintrans.NewTransformation(params, lintrans.Parameters{
		DiagonalsIndexList: diags.DiagonalsIndexList(), LevelQ: level, LevelP: params.MaxLevelP(),
		Scale: scale, LogDimensions: params.LogMaxDimensions(), LogBabyStepGiantStepRatio: 1,
	})
	if err := lintrans.Encode(ckks.NewEncoder(params, 128), inverseDiags, lt); err != nil {
		return empty, fmt.Errorf("encode inverse-coordinate fiber matrix: %w", err)
	}
	ringQP := params.RingQP().AtLevel(lt.LevelQ, lt.LevelP)
	unit := ringQP.NewPoly()
	ringQP.RingQ.SetCoefficientsBigint(full, unit.Q)
	if ringQP.RingP != nil {
		ringQP.RingP.SetCoefficientsBigint(full, unit.P)
	}
	ringQP.NTT(unit, unit)
	ringQP.MForm(unit, unit)
	if lt.N1 == 0 {
		for _, pt := range lt.Vec {
			ringQP.MulCoeffsMontgomery(pt, unit, pt)
		}
		return lt, nil
	}
	index, _, _ := commonlintrans.LinearTransformation(lt).BSGSIndex()
	rotated := ringQP.NewPoly()
	for giant, babies := range index {
		ringQP.AutomorphismNTT(unit, params.GaloisElementForRotation(-giant), rotated)
		for _, baby := range babies {
			pt := lt.Vec[giant+baby]
			ringQP.MulCoeffsMontgomery(pt, rotated, pt)
		}
	}
	return lt, nil
}
