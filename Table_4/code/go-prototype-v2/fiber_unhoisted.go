package lowbootstrap

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	common "github.com/tuneinsight/lattigo/v6/circuits/common/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"sort"
)

// EvaluateFiberUnhoisted evaluates the same encoded BSGS diagonals using
// ordinary rotations. The fork's lazy hoisted product rejects bit gadgets.
// Matrix encoding, scale and level are unchanged; each rotation performs its
// own key switch and modulus down. All matrix polynomials remain read-only.
func EvaluateFiberUnhoisted(p ckks.Parameters, ev *ckks.Evaluator, input *rlwe.Ciphertext, lt lintrans.LinearTransformation) (*rlwe.Ciphertext, error) {
	if lt.N1 == 0 {
		return nil, fmt.Errorf("BSGS matrix required")
	}
	index, _, babies := common.LinearTransformation(lt).BSGSIndex()
	rotations := make(map[int]*rlwe.Ciphertext)
	for _, b := range babies {
		if b == 0 {
			rotations[b] = input
			continue
		}
		ct, err := ev.RotateNew(input, b)
		if err != nil {
			return nil, err
		}
		rotations[b] = ct
	}
	giants := make([]int, 0, len(index))
	for g := range index {
		giants = append(giants, g)
	}
	sort.Ints(giants)
	level := min(input.Level(), lt.LevelQ)
	rq := p.RingQ().AtLevel(level)
	var result *rlwe.Ciphertext
	for _, g := range giants {
		var group *rlwe.Ciphertext
		for _, b := range index[g] {
			in := rotations[b]
			diagonal, ok := lt.Vec[g+b]
			if !ok {
				return nil, fmt.Errorf("missing diagonal %d", g+b)
			}
			term := ckks.NewCiphertext(p, in.Degree(), level)
			term.MetaData = in.MetaData.CopyNew()
			term.Scale = in.Scale.Mul(lt.Scale)
			// The stored diagonal is NTT/Montgomery; the ciphertext is ordinary NTT.
			for c := range term.Value {
				rq.MulCoeffsMontgomery(in.Value[c], diagonal.Q, term.Value[c])
			}
			if group == nil {
				group = term
			} else if err := ev.Add(group, term, group); err != nil {
				return nil, err
			}
		}
		if g != 0 {
			var err error
			group, err = ev.RotateNew(group, g)
			if err != nil {
				return nil, err
			}
		}
		if result == nil {
			result = group
		} else if err := ev.Add(result, group, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}
