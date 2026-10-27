package lowbootstrap

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// SplitCoefficientBranches is public coefficient extraction only. For the
// resulting ciphertexts to share the leaf secret, ct must already be encrypted
// under that secret embedded by Y=X^(N/n). It does not perform a key switch.
func SplitCoefficientBranches(top, leaf ckks.Parameters, ct *rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	if ct == nil || ct.MetaData == nil || ct.LogN() != top.LogN() || top.LogN() <= leaf.LogN() || ct.IsMontgomery || ct.Level() > leaf.MaxLevel() {
		return nil, fmt.Errorf("invalid split input")
	}
	for i, q := range top.Q()[:ct.Level()+1] {
		if q != leaf.Q()[i] {
			return nil, fmt.Errorf("split Q mismatch")
		}
	}
	k := top.N() / leaf.N()
	result := make([]*rlwe.Ciphertext, k)
	for b := range result {
		result[b] = ckks.NewCiphertext(leaf, ct.Degree(), ct.Level())
		result[b].MetaData = ct.MetaData.CopyNew()
		result[b].LogDimensions.Cols = max(0, ct.LogDimensions.Cols-(top.LogN()-leaf.LogN()))
	}
	for component, p := range ct.Value {
		coeff := p.CopyNew()
		if ct.IsNTT {
			top.RingQ().AtLevel(ct.Level()).INTT(p, *coeff)
		}
		for limb := 0; limb <= ct.Level(); limb++ {
			for b := 0; b < k; b++ {
				for j := 0; j < leaf.N(); j++ {
					result[b].Value[component].Coeffs[limb][j] = coeff.Coeffs[limb][j*k+b]
				}
			}
		}
		if ct.IsNTT {
			for b := range result {
				leaf.RingQ().AtLevel(ct.Level()).NTT(result[b].Value[component], result[b].Value[component])
			}
		}
	}
	return result, nil
}

// ApplyAll performs one actual top-ring KS to the embedded sparse leaf secret,
// then retains every coefficient branch. No plaintext or branch is discarded.
func (e *RingEntry) ApplyAll(ct *rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	if ct == nil || ct.MetaData == nil || ct.Degree() != 1 || ct.LogN() != e.Top.LogN() || ct.Level() > e.Key.LevelQ() || ct.IsMontgomery {
		return nil, fmt.Errorf("invalid full ring entry")
	}
	switched := ckks.NewCiphertext(e.Top, 1, ct.Level())
	if err := e.eval.ApplyEvaluationKey(ct, e.Key, switched); err != nil {
		return nil, err
	}
	return SplitCoefficientBranches(e.Top, e.Leaf, switched)
}

// MergeCoefficientBranches implements sum_b X^b iota(ct_b), without a KS.
// Inputs must share a secret, scale and level. The result is under the embedded
// leaf secret; the caller must perform the advertised return key switch.
func MergeCoefficientBranches(top, leaf ckks.Parameters, cts []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if top.LogN() <= leaf.LogN() || len(cts) != top.N()/leaf.N() || cts[0] == nil {
		return nil, fmt.Errorf("invalid merge branch count")
	}
	first := cts[0]
	if first.Level() > top.MaxLevel() || first.Level() > leaf.MaxLevel() || first.IsMontgomery {
		return nil, fmt.Errorf("invalid merge level/representation")
	}
	for i, q := range leaf.Q()[:first.Level()+1] {
		if q != top.Q()[i] {
			return nil, fmt.Errorf("merge Q mismatch")
		}
	}
	out := ckks.NewCiphertext(top, first.Degree(), first.Level())
	out.MetaData = first.MetaData.CopyNew()
	out.LogDimensions.Cols = top.LogMaxSlots()
	k := len(cts)
	for b, ct := range cts {
		if ct == nil || ct.LogN() != leaf.LogN() || ct.Degree() != first.Degree() || ct.Level() != first.Level() || ct.IsNTT != first.IsNTT || ct.IsMontgomery || !ct.Scale.Equal(first.Scale) {
			return nil, fmt.Errorf("incompatible merge branch %d", b)
		}
		for component, p := range ct.Value {
			coeff := p.CopyNew()
			if ct.IsNTT {
				leaf.RingQ().AtLevel(ct.Level()).INTT(p, *coeff)
			}
			for limb := 0; limb <= ct.Level(); limb++ {
				for j := 0; j < leaf.N(); j++ {
					out.Value[component].Coeffs[limb][j*k+b] = coeff.Coeffs[limb][j]
				}
			}
		}
	}
	if out.IsNTT {
		for component := range out.Value {
			top.RingQ().AtLevel(out.Level()).NTT(out.Value[component], out.Value[component])
		}
	}
	return out, nil
}
