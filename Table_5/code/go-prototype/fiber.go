package lowbootstrap

import (
	"fmt"
	"math"
	"math/cmplx"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// FiberDiagonals implements the two maps of Small Batches, Lemmas 5 and 7.
// There are k independent complex messages, repeated every k*R slots, at
// positions s%R==0. Forward outputs partial sums whose normalized period-k
// trace equals A*z. Inverse expects a period-k input and returns B*x on data.
// The caller explicitly includes raw-trace normalization and ModUp scaling in
// gain. No secret or plaintext-dependent decision is used by these maps.
func FiberDiagonals(slots, k, R int, inverse bool, gain float64) (lintrans.Diagonals[complex128], error) {
	if slots < 1 || slots&(slots-1) != 0 || k < 1 || k&(k-1) != 0 || R < 1 || R&(R-1) != 0 || k%R != 0 || k*R > slots || math.IsNaN(gain) || math.IsInf(gain, 0) {
		return nil, fmt.Errorf("invalid fiber layout slots=%d k=%d R=%d", slots, k, R)
	}
	// A[c,j] = zeta^(5^c*j), zeta = exp(pi*i/(2k)). A* A = k I.
	a := func(c, j int) complex128 {
		e := powerMod(5, c, uint64(4*k))
		return cmplx.Exp(complex(0, math.Pi*float64((e*uint64(j))%uint64(4*k))/float64(2*k)))
	}
	diags := lintrans.Diagonals[complex128]{}
	if inverse {
		for o := 0; o < k; o++ {
			v := make([]complex128, slots)
			for s := 0; s < slots; s += R {
				v[s] = complex(gain/float64(k), 0) * cmplx.Conj(a((s+o)%k, (s/R)%k))
			}
			diags[o] = v
		}
	} else {
		for t := 0; t < R; t++ {
			for u := 0; u < k/R; u++ {
				o := (-t + R*u + slots) % slots
				v := make([]complex128, slots)
				for s := t; s < slots; s += R {
					j := ((s + o) % slots) / R % k
					v[s] = complex(gain*float64(R), 0) * a(s%k, j)
				}
				diags[o] = v
			}
		}
	}
	return diags, nil
}

// NewFiberMatrix uses ordinary high-precision diagonal encoding. Shaping is
// intentionally left to the final rescale at the replicated CtS output.
func NewFiberMatrix(params ckks.Parameters, diags lintrans.Diagonals[complex128], level int, scale rlwe.Scale) (lintrans.LinearTransformation, error) {
	if level < 0 || level > params.MaxLevel() {
		return lintrans.LinearTransformation{}, fmt.Errorf("invalid fiber matrix level")
	}
	lt := lintrans.NewTransformation(params, lintrans.Parameters{
		DiagonalsIndexList: diags.DiagonalsIndexList(), LevelQ: level, LevelP: params.MaxLevelP(),
		Scale: scale, LogDimensions: params.LogMaxDimensions(), LogBabyStepGiantStepRatio: 1,
	})
	if err := lintrans.Encode(ckks.NewEncoder(params, 128), diags, lt); err != nil {
		return lintrans.LinearTransformation{}, err
	}
	return lt, nil
}

// FiberTraceGaloisElements reduces a full slot vector to period k by raw sums.
// The accumulated factor is slots/k, not slots/(k*R).
func FiberTraceGaloisElements(params ckks.Parameters, k int) []uint64 {
	out := []uint64{}
	for stride := k; stride < params.MaxSlots(); stride *= 2 {
		out = append(out, params.GaloisElementForRotation(stride))
	}
	return out
}

func FiberRawTrace(eval *ckks.Evaluator, params ckks.Parameters, ct *rlwe.Ciphertext, k int) (*rlwe.Ciphertext, error) {
	if k < 1 || k&(k-1) != 0 || k > params.MaxSlots() {
		return nil, fmt.Errorf("invalid trace period")
	}
	out := ct.CopyNew()
	for stride := k; stride < params.MaxSlots(); stride *= 2 {
		rot, err := eval.RotateNew(out, stride)
		if err != nil {
			return nil, err
		}
		if err = eval.Add(out, rot, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}
