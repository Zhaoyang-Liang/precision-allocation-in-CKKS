package lowbootstrap

import (
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type RingEntrySmokeConfig struct {
	TopLogN, LeafLogN, QBits, PBits, BaseTwo, TopWeight, LeafWeight int
}

type RingEntrySmokeReport struct {
	Config                RingEntrySmokeConfig `json:"config"`
	CiphertextStage       string               `json:"ciphertext_stage"`
	KeyBytes              int                  `json:"key_bytes"`
	ActualKeyLogQP        float64              `json:"actual_key_log_qp"`
	UnitInverseExact      bool                 `json:"unit_inverse_exact"`
	MaxKSAddedCoeffError  string               `json:"max_ks_added_coefficient_error"`
	ConstantKSAddedError  string               `json:"constant_ks_added_error"`
	ImaginaryKSAddedError string               `json:"imaginary_ks_added_error"`
	OutputLevel           int                  `json:"output_level"`
	OutputLogSlots        int                  `json:"output_log_slots"`
	ElapsedSeconds        float64              `json:"elapsed_seconds"`
	SecurityClaim         string               `json:"security_claim"`
}

// RunRingEntrySmoke uses genuine encryption and genuine gadget key switching.
// Decryption is used only after the evaluated stages to measure their errors.
// It does not simulate or replace any ciphertext operation with an oracle.
func RunRingEntrySmoke(c RingEntrySmokeConfig) (RingEntrySmokeReport, error) {
	start := time.Now()
	r := RingEntrySmokeReport{Config: c, CiphertextStage: "encrypt -> integer unit -> inverse unit -> real gadget KS -> Split0", SecurityClaim: "stage correctness only; no security or full-bootstrap claim"}
	top, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: c.TopLogN, LogQ: []int{c.QBits}, LogP: []int{c.PBits},
		LogDefaultScale: 24, Xs: ring.Ternary{H: c.TopWeight},
	})
	if err != nil {
		return r, err
	}
	leaf, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: c.LeafLogN, Q: top.Q(), P: top.P(),
		LogDefaultScale: 24, Xs: ring.Ternary{H: c.LeafWeight},
	})
	if err != nil {
		return r, err
	}
	skTop := rlwe.NewKeyGenerator(top).GenSecretKeyNew()
	skLeaf := rlwe.NewKeyGenerator(leaf).GenSecretKeyNew()
	entry, err := NewRingEntry(top, leaf, skTop, skLeaf, 0, 0, c.BaseTwo)
	if err != nil {
		return r, err
	}
	r.KeyBytes = entry.Key.BinarySize()
	r.ActualKeyLogQP = math.Log2(float64(top.Q()[0])) + math.Log2(float64(top.P()[0]))
	coeffs := make([]*big.Int, top.N())
	for i := range coeffs {
		coeffs[i] = big.NewInt(int64((i%17)-8) * (1 << 12))
	}
	pt := rlwe.NewPlaintext(top, 0)
	pt.Scale = rlwe.NewScale(1 << 24)
	pt.LogDimensions.Cols = top.LogN() - 1
	poly, err := PolynomialFromCoefficients(top, coeffs, 0, pt.IsNTT, false)
	if err != nil {
		return r, err
	}
	pt.Value.Copy(poly)
	ct, err := rlwe.NewEncryptor(top, skTop).EncryptNew(pt)
	if err != nil {
		return r, err
	}
	// Let U=X^(N/4). (U-U^3)^2=2, so (-1+U-U^3)(1+U-U^3)=1.
	g, gi := make([]*big.Int, top.N()), make([]*big.Int, top.N())
	g[0], gi[0] = big.NewInt(-1), big.NewInt(1)
	g[top.N()/4], gi[top.N()/4] = big.NewInt(1), big.NewInt(1)
	g[3*top.N()/4], gi[3*top.N()/4] = big.NewInt(-1), big.NewInt(-1)
	shaped, err := MulIntegerPolynomial(top, ct, g)
	if err != nil {
		return r, err
	}
	restored, err := MulIntegerPolynomial(top, shaped, gi)
	if err != nil {
		return r, err
	}
	r.UnitInverseExact = ciphertextEqualModQ(top, ct, restored)
	if !r.UnitInverseExact {
		return r, fmt.Errorf("integer unit/inverse did not recover the ciphertext modulo Q")
	}
	out, err := entry.Apply(restored)
	if err != nil {
		return r, err
	}
	before := rlwe.NewDecryptor(top, skTop).DecryptNew(restored)
	after := rlwe.NewDecryptor(leaf, skLeaf).DecryptNew(out)
	pre, err := CenteredCoefficients(top, before.Value, before.IsNTT, before.IsMontgomery)
	if err != nil {
		return r, err
	}
	post, err := CenteredCoefficients(leaf, after.Value, after.IsNTT, after.IsMontgomery)
	if err != nil {
		return r, err
	}
	maxErr, delta, q, halfQ := new(big.Int), new(big.Int), new(big.Int).SetUint64(top.Q()[0]), new(big.Int).SetUint64(top.Q()[0]/2)
	gap := top.N() / leaf.N()
	for i := range post {
		delta.Sub(post[i], pre[gap*i]).Mod(delta, q)
		if delta.Cmp(halfQ) > 0 {
			delta.Sub(delta, q)
		}
		if i == 0 {
			r.ConstantKSAddedError = delta.String()
		}
		if i == leaf.N()/2 {
			r.ImaginaryKSAddedError = delta.String()
		}
		delta.Abs(delta)
		if delta.Cmp(maxErr) > 0 {
			maxErr.Set(delta)
		}
	}
	r.MaxKSAddedCoeffError = maxErr.String()
	r.OutputLevel, r.OutputLogSlots = out.Level(), out.LogDimensions.Cols
	r.ElapsedSeconds = time.Since(start).Seconds()
	if maxErr.Cmp(big.NewInt(4096)) > 0 {
		return r, fmt.Errorf("KS added coefficient error %s exceeds smoke threshold 4096", maxErr)
	}
	return r, nil
}

func ciphertextEqualModQ(params ckks.Parameters, a, b *rlwe.Ciphertext) bool {
	if a.Degree() != b.Degree() || a.Level() != b.Level() || !a.MetaData.Equal(b.MetaData) {
		return false
	}
	for i := range a.Value {
		for l := range a.Value[i].Coeffs {
			q := params.Q()[l]
			for j, v := range a.Value[i].Coeffs[l] {
				if v%q != b.Value[i].Coeffs[l][j]%q {
					return false
				}
			}
		}
	}
	return true
}
