package neighbor

import (
	"fmt"
	"slices"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

// ProjectRelinearizationKeySingleP returns a READ-ONLY base-key view of ext.
// The caller must have generated ext for c.Extended and the same integer
// secret as the base context. Shape checks cannot establish key provenance.
//
// With one P prime and no bit decomposition, row i encrypts P*s^2 only in
// Q limb i. Dropping row 0 (qDiv) and Q limb 0 in every remaining row therefore
// preserves precisely the base gadget messages. P limbs are NOT dropped.
// The projected error is the same error, not an independent sample.
//
// All coefficient arrays alias ext; only container/slice headers are new.
// Do not mutate, resize, regenerate, or separately store/transmit the view.
// Store/transmit ext once and reconstruct the view at the recipient.
func (c *Context) ProjectRelinearizationKeySingleP(ext *rlwe.RelinearizationKey) (*rlwe.RelinearizationKey, error) {
	if c.Base.PCount() != 1 || c.Extended.PCount() != 1 || ext == nil {
		return nil, fmt.Errorf("shared projection requires one P prime and a nonnil key")
	}
	if ext.Seed != nil || ext.BaseTwoDecomposition != 0 || len(ext.Value) != c.Extended.QCount() {
		return nil, fmt.Errorf("shared projection requires full uncompressed no-bit-decomposition extended key")
	}
	for _, row := range ext.Value {
		if len(row) != 1 || len(row[0]) != 2 {
			return nil, fmt.Errorf("unexpected gadget digits/degree")
		}
		for _, p := range row[0] {
			if len(p.Q.Coeffs) != c.Extended.QCount() || len(p.P.Coeffs) != 1 {
				return nil, fmt.Errorf("unexpected gadget Q/P shape")
			}
			for _, limbs := range [][][]uint64{p.Q.Coeffs, p.P.Coeffs} {
				for _, a := range limbs {
					if len(a) != c.Base.N() {
						return nil, fmt.Errorf("unexpected gadget ring dimension")
					}
				}
			}
		}
	}
	out := new(rlwe.RelinearizationKey)
	out.Value = make(structs.Matrix[rlwe.VectorQP], c.Base.QCount())
	for i := range out.Value {
		out.Value[i] = make([]rlwe.VectorQP, 1)
		out.Value[i][0] = make(rlwe.VectorQP, 2)
		for k := range out.Value[i][0] {
			p := ext.Value[i+1][0][k]
			p.Q.Coeffs = slices.Clone(p.Q.Coeffs[1:])
			p.P.Coeffs = slices.Clone(p.P.Coeffs)
			out.Value[i][0][k] = p
		}
	}
	return out, nil
}

// CheckRelinearizationKeyView checks every coefficient-array alias, not just
// equality of values or a claimed byte saving. No coefficient data is copied.
func (c *Context) CheckRelinearizationKeyView(base, ext *rlwe.RelinearizationKey) error {
	want, err := c.ProjectRelinearizationKeySingleP(ext)
	if err != nil {
		return err
	}
	if base == nil || base.Seed != nil || base.BaseTwoDecomposition != 0 || len(base.Value) != len(want.Value) {
		return fmt.Errorf("invalid base key view")
	}
	for i, row := range want.Value {
		if len(base.Value[i]) != 1 || len(base.Value[i][0]) != 2 {
			return fmt.Errorf("invalid base gadget shape")
		}
		for k, p := range row[0] {
			got := base.Value[i][0][k]
			for j, limbs := range [][][]uint64{p.Q.Coeffs, p.P.Coeffs} {
				actual := got.Q.Coeffs
				if j == 1 {
					actual = got.P.Coeffs
				}
				if len(actual) != len(limbs) {
					return fmt.Errorf("base view limb count mismatch")
				}
				for l, a := range limbs {
					if len(actual[l]) != len(a) || &actual[l][0] != &a[0] {
						return fmt.Errorf("base coefficients are not shared at row %d, component %d, basis %d, limb %d", i, k, j, l)
					}
				}
			}
		}
	}
	return nil
}
