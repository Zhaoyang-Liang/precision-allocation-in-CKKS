package lowbootstrap

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// RingEntry performs genuine gadget key switching to an embedded leaf secret,
// followed by coefficient branch-zero extraction. No secret is retained here.
// This is the existing Lattigo operation, not a new projected-KS algorithm.
type RingEntry struct {
	Top, Leaf ckks.Parameters
	Key       *rlwe.EvaluationKey
	eval      *rlwe.Evaluator
}

// ValidateBaseTwoDecompositionCoverage rejects a truncated gadget basis in the
// local fork. Its digit allocation uses round(log2(qi)), but unsigned MaskVec
// decomposition must cover every bit of a canonical residue modulo the actual
// prime. In particular, a prime just above 2^k still needs k+1 bits.
func ValidateBaseTwoDecompositionCoverage(params rlwe.ParameterProvider, levelQ, levelP, baseTwo int) error {
	p := params.GetRLWEParameters()
	if levelQ < 0 || levelQ > p.MaxLevelQ() || levelP < -1 || levelP > p.MaxLevelP() {
		return fmt.Errorf("gadget coverage check: Q/P level exceeds parameter basis")
	}
	if baseTwo < 0 || baseTwo > 63 {
		return fmt.Errorf("gadget coverage check: base-two bits must be in [0,63]")
	}
	if baseTwo == 0 {
		return nil // Unmasked RNS decomposition does not have this truncation.
	}
	if levelP > 0 {
		return fmt.Errorf("gadget coverage check: this fork supports bit decomposition with at most one P prime")
	}
	digits := p.BaseTwoDecompositionVectorSize(levelQ, levelP, baseTwo)
	for i, q := range p.Q()[:levelQ+1] {
		required, covered := bits.Len64(q), digits[i]*baseTwo
		if covered < required {
			return fmt.Errorf("unsafe base-two decomposition: Q[%d]=%d requires %d bits, but base %d with %d allocated digits covers only %d bits; this fork rounds log2(qi) and would discard the highest residue bit; choose a base with sufficient coverage", i, q, required, baseTwo, digits[i], covered)
		}
	}
	return nil
}

func NewRingEntry(top, leaf ckks.Parameters, skTop, skLeaf *rlwe.SecretKey, levelQ, levelP, baseTwo int) (*RingEntry, error) {
	if top.LogN() <= leaf.LogN() || top.RingType() != ring.Standard || leaf.RingType() != ring.Standard {
		return nil, fmt.Errorf("entry requires Standard rings with top LogN > leaf LogN")
	}
	if levelQ < 0 || levelQ > top.MaxLevelQ() || levelQ > leaf.MaxLevelQ() || levelP < -1 || levelP > top.MaxLevelP() || levelP > leaf.MaxLevelP() {
		return nil, fmt.Errorf("requested evaluation-key level exceeds Q/P basis")
	}
	if leaf.MaxLevelQ() > top.MaxLevelQ() {
		return nil, fmt.Errorf("key generation requires leaf Q basis to be a top Q prefix; rebase the leaf secret to low parameters first")
	}
	for i, q := range leaf.Q() {
		if q != top.Q()[i] {
			return nil, fmt.Errorf("Q prime %d differs between top and leaf", i)
		}
	}
	for i := 0; i <= levelP; i++ {
		if top.P()[i] != leaf.P()[i] {
			return nil, fmt.Errorf("P prime %d differs between top and leaf", i)
		}
	}
	if err := ValidateBaseTwoDecompositionCoverage(top, levelQ, levelP, baseTwo); err != nil {
		return nil, fmt.Errorf("ring entry: %w", err)
	}
	if skTop == nil || skLeaf == nil || skTop.Value.Q.N() != top.N() || skLeaf.Value.Q.N() != leaf.N() {
		return nil, fmt.Errorf("secret dimensions do not match entry parameters")
	}
	if skTop.Value.Q.Level() < levelQ || skLeaf.Value.Q.Level() < levelQ {
		return nil, fmt.Errorf("secret Q basis is too short")
	}
	if skLeaf.Value.Q.Level() > top.MaxLevelQ() {
		return nil, fmt.Errorf("rebase the leaf secret to the low entry Q basis before key generation")
	}
	key := rlwe.NewKeyGenerator(top).GenEvaluationKeyNew(skTop, skLeaf, rlwe.EvaluationKeyParameters{
		LevelQ: &levelQ, LevelP: &levelP, BaseTwoDecomposition: &baseTwo,
	})
	return &RingEntry{Top: top, Leaf: leaf, Key: key, eval: rlwe.NewEvaluator(top, nil)}, nil
}

// Apply leaves the scale unchanged. For a full CKKS slot representation it
// reduces LogDimensions by the ring-degree gap, as RingPackingEvaluator does.
// Sparse metadata is clamped at zero; callers own their intended slot layout.
func (e *RingEntry) Apply(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if ct == nil || ct.MetaData == nil || ct.Degree() != 1 || ct.LogN() != e.Top.LogN() || ct.Level() > e.Key.LevelQ() {
		return nil, fmt.Errorf("entry expects a degree-one top ciphertext within the key Q level")
	}
	if ct.IsMontgomery {
		return nil, fmt.Errorf("entry expects ordinary ciphertext residues, not Montgomery residues")
	}
	out := rlwe.NewCiphertext(e.Leaf, 1, ct.Level())
	if err := e.eval.ApplyEvaluationKey(ct, e.Key, out); err != nil {
		return nil, err
	}
	out.LogDimensions.Cols = max(0, ct.LogDimensions.Cols-(e.Top.LogN()-e.Leaf.LogN()))
	return out, nil
}

// CenteredCoefficients reads a polynomial without changing it. Full CRT
// reconstruction is used; reading only limb zero is not a high-Q lift.
func CenteredCoefficients(params rlwe.ParameterProvider, poly ring.Poly, isNTT, isMontgomery bool) ([]*big.Int, error) {
	p := params.GetRLWEParameters()
	if poly.N() != p.N() || poly.Level() > p.MaxLevelQ() {
		return nil, fmt.Errorf("polynomial dimension or Q level mismatch")
	}
	r := p.RingQ().AtLevel(poly.Level())
	buf := poly.CopyNew()
	if isNTT {
		r.INTT(*buf, *buf)
	}
	if isMontgomery {
		r.IMForm(*buf, *buf)
	}
	coeffs := make([]*big.Int, p.N())
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	r.PolyToBigintCentered(*buf, 1, coeffs)
	return coeffs, nil
}

// PolynomialFromCoefficients reduces signed integers independently in every
// active RNS limb and then applies the requested representations.
func PolynomialFromCoefficients(params rlwe.ParameterProvider, coeffs []*big.Int, level int, isNTT, isMontgomery bool) (ring.Poly, error) {
	p := params.GetRLWEParameters()
	if level < 0 || level > p.MaxLevelQ() || len(coeffs) > p.N() {
		return ring.Poly{}, fmt.Errorf("coefficient count or Q level mismatch")
	}
	full := make([]*big.Int, p.N())
	zero := new(big.Int)
	for i := range full {
		full[i] = zero
		if i < len(coeffs) && coeffs[i] != nil {
			full[i] = coeffs[i]
		}
	}
	r := p.RingQ().AtLevel(level)
	out := r.NewPoly()
	r.SetCoefficientsBigint(full, out)
	if isNTT {
		r.NTT(out, out)
	}
	if isMontgomery {
		r.MForm(out, out)
	}
	return out, nil
}

// CenteredCiphertextComponents is public component lifting, not decryption.
func CenteredCiphertextComponents(params rlwe.ParameterProvider, ct *rlwe.Ciphertext) ([][]*big.Int, error) {
	if ct == nil || ct.MetaData == nil {
		return nil, fmt.Errorf("ciphertext metadata is required")
	}
	out := make([][]*big.Int, len(ct.Value))
	for i, poly := range ct.Value {
		var err error
		if out[i], err = CenteredCoefficients(params, poly, ct.IsNTT, ct.IsMontgomery); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MulNTTMontgomeryPolynomial multiplies by an already prepared integer
// polynomial. multiplier must be NTT+Montgomery; this condition is not encoded
// in ring.Poly itself. Metadata, level, degree and the input are preserved.
func MulNTTMontgomeryPolynomial(params rlwe.ParameterProvider, ct *rlwe.Ciphertext, multiplier ring.Poly) (*rlwe.Ciphertext, error) {
	p := params.GetRLWEParameters()
	if ct == nil || ct.MetaData == nil || ct.LogN() != p.LogN() || multiplier.N() != p.N() || multiplier.Level() < ct.Level() {
		return nil, fmt.Errorf("integer multiplier/ciphertext dimension or level mismatch")
	}
	r := p.RingQ().AtLevel(ct.Level())
	out := ct.CopyNew()
	for i := range out.Value {
		if !ct.IsNTT {
			r.NTT(out.Value[i], out.Value[i])
		}
		r.MulCoeffsMontgomery(out.Value[i], multiplier, out.Value[i])
		if !ct.IsNTT {
			r.INTT(out.Value[i], out.Value[i])
		}
	}
	return out, nil
}

// MulIntegerPolynomial is raw exact modular multiplication, without CKKS
// plaintext encoding or rescaling. The caller must account for semantic scale.
func MulIntegerPolynomial(params rlwe.ParameterProvider, ct *rlwe.Ciphertext, coeffs []*big.Int) (*rlwe.Ciphertext, error) {
	if ct == nil {
		return nil, fmt.Errorf("nil ciphertext")
	}
	poly, err := PolynomialFromCoefficients(params, coeffs, ct.Level(), true, true)
	if err != nil {
		return nil, err
	}
	return MulNTTMontgomeryPolynomial(params, ct, poly)
}

// RebaseSecretKey recreates the same ternary secret in a different Q/P basis.
// This is local secret-key preparation only. It creates NO public evaluation
// key; callers must never publish a high-Q sparse-target key accidentally.
func RebaseSecretKey(src, dst rlwe.ParameterProvider, sk *rlwe.SecretKey) (*rlwe.SecretKey, error) {
	s, d := src.GetRLWEParameters(), dst.GetRLWEParameters()
	if sk == nil || s.N() != d.N() || sk.Value.Q.N() != s.N() {
		return nil, fmt.Errorf("secret rebasing requires equal ring dimensions")
	}
	coeffs, err := CenteredCoefficients(src, sk.Value.Q, true, true)
	if err != nil {
		return nil, err
	}
	for _, c := range coeffs {
		if !c.IsInt64() || c.Int64() < -1 || c.Int64() > 1 {
			return nil, fmt.Errorf("secret rebasing only accepts centered ternary coefficients")
		}
	}
	out := rlwe.NewSecretKey(dst)
	d.RingQ().SetCoefficientsBigint(coeffs, out.Value.Q)
	d.RingQ().NTT(out.Value.Q, out.Value.Q)
	d.RingQ().MForm(out.Value.Q, out.Value.Q)
	if d.PCount() != 0 {
		d.RingP().SetCoefficientsBigint(coeffs, out.Value.P)
		d.RingP().NTT(out.Value.P, out.Value.P)
		d.RingP().MForm(out.Value.P, out.Value.P)
	}
	return out, nil
}
