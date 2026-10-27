package bench

import "github.com/tuneinsight/lattigo/v6/core/rlwe"

// D(d)=2d+i(T(d+conj(d))-d+conj(d)). The input is never mutated.
// The SAME implementation is used by unit joint and ordinary compact split.
// Subsequent three rotate-adds and scale *=32 are shared with evaluate().
func pairedReorganize(b *branchRuntime, d *rlwe.Ciphertext, r *recorder) (*rlwe.Ciphertext, error) {
	add := func(x, y *rlwe.Ciphertext, subtract bool) (*rlwe.Ciphertext, error) {
		var out *rlwe.Ciphertext
		var err error
		kind := "ciphertext_add"
		if subtract {
			out, err = b.Evaluator.SubNew(x, y)
			kind = "ciphertext_subtract"
		} else {
			out, err = b.Evaluator.AddNew(x, y)
		}
		if err == nil {
			r.ops = append(r.ops, Operation{Kind: kind, Branch: b.Spec.ID, InputLevel: x.Level(), InputDegree: x.Degree()})
		}
		return out, err
	}
	c, err := b.Evaluator.ConjugateNew(d)
	if err != nil {
		return nil, err
	}
	r.ops = append(r.ops, Operation{Kind: "conjugate", Branch: b.Spec.ID, InputLevel: d.Level(), InputDegree: d.Degree(), KeySwitches: 1})
	a, err := add(d, c, false)
	if err != nil {
		return nil, err
	}
	step := rotations(b.Spec)[0]
	t, err := b.Evaluator.RotateNew(a, step)
	if err != nil {
		return nil, err
	}
	r.ops = append(r.ops, Operation{Kind: "rotate", Branch: b.Spec.ID, InputLevel: a.Level(), InputDegree: a.Degree(), Rotation: step, KeySwitches: 1})
	z, err := add(t, d, true)
	if err != nil {
		return nil, err
	}
	z, err = add(z, c, false)
	if err != nil {
		return nil, err
	}
	z, err = rawMultiply(b.P, z, b.Imaginary, nil, r, b.Spec.ID, "exact_i_monomial")
	if err != nil {
		return nil, err
	}
	twice, err := add(d, d, false)
	if err != nil {
		return nil, err
	}
	return add(twice, z, false)
}
