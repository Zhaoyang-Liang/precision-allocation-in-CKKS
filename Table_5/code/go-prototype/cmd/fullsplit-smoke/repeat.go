package main

import (
	"fmt"
	"math"
	"math/big"
	"math/cmplx"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

type repeatResult struct {
	Round, RefreshedBranches, InputLevel, OutputLevel                                int
	InputLogScale, OutputLogScale, Beta                                              float64
	Input, Output                                                                    metric
	InputLeafDataErrorMax, InputLeafGuardMax, EntryReadoutErrorMax, LeafDataErrorMax float64
	OnlineSeconds, EntrySeconds, LeafSeconds, MergeSeconds                           float64
	DomainCovered                                                                    bool
}

func squareLogicalSupport(zs []complex128, support int) ([]complex128, int, error) {
	if support < 1 || 2*(support-1) >= len(zs) {
		return nil, 0, fmt.Errorf("squaring exceeds the no-wrap repeated-leaf interface")
	}
	out := make([]complex128, len(zs))
	for i := 0; i < support; i++ {
		for j := 0; j < support; j++ {
			out[i+j] += zs[i] * zs[j]
		}
	}
	return out, 2*support - 1, nil
}

// All accesses to secrets and ideal messages below are diagnostic-only and
// occur after the timed online result has been computed.
func diagnoseRepeat(top, low, main ckks.Parameters, st, sl, sm *rlwe.SecretKey, input *rlwe.Ciphertext,
	want, zs []complex128, support int, beta float64, round int, c config, m *onlineResult) (repeatResult, error) {
	r := repeatResult{Round: round, RefreshedBranches: support, InputLevel: input.Level(), OutputLevel: m.returned.Level(),
		InputLogScale: scaleLog(input.Scale), OutputLogScale: scaleLog(m.returned.Scale), Beta: beta,
		OnlineSeconds: m.onlineSeconds, EntrySeconds: m.entrySeconds, LeafSeconds: m.leafSeconds, MergeSeconds: m.mergeSeconds, DomainCovered: true}
	if r.InputLevel != 0 || r.OutputLevel != 1 {
		return r, fmt.Errorf("repeat must refresh level0 to level1")
	}
	values, err := decode(top, st, input)
	if err != nil {
		return r, err
	}
	r.Input = stats(values, want, c.R, nil)
	values, err = decode(top, st, m.returned)
	if err != nil {
		return r, err
	}
	r.Output = stats(values, want, c.R, nil)
	pt := rlwe.NewDecryptor(top, st).DecryptNew(input)
	view := ckks.NewCiphertext(top, 0, input.Level())
	view.Value[0] = pt.Value
	view.MetaData = pt.MetaData.CopyNew()
	bs, err := lb.SplitCoefficientBranches(top, low, view)
	if err != nil {
		return r, err
	}
	for b := 0; b < support; b++ {
		v, err := plainView(low, bs[b])
		if err != nil {
			return r, err
		}
		metric := stats(v, leafExpected(low.MaxSlots(), c.R, zs[b]), c.R, nil)
		r.InputLeafDataErrorMax = math.Max(r.InputLeafDataErrorMax, metric.DataError)
		r.InputLeafGuardMax = math.Max(r.InputLeafGuardMax, metric.GuardMax)
		raw, carry, err := selectedLift(low, sl, m.leaves[b])
		if err != nil {
			return r, err
		}
		frac := [2]float64{}
		for lane := 0; lane < 2; lane++ {
			rem := new(big.Int).Sub(raw[lane], new(big.Int).Mul(big.NewInt(carry[lane]), new(big.Int).SetUint64(c.Q0)))
			f := new(big.Float).SetPrec(192).SetInt(rem)
			f.Quo(f, new(big.Float).SetPrec(192).SetUint64(c.Q0))
			frac[lane], _ = f.Float64()
			if math.Abs(float64(carry[lane])+frac[lane]-.25) > float64(c.K) {
				r.DomainCovered = false
			}
		}
		r.EntryReadoutErrorMax = math.Max(r.EntryReadoutErrorMax, cmplx.Abs(complex(beta*frac[0], beta*frac[1])-zs[b]))
		v, err = decode(main, sm, m.refreshed[b])
		if err != nil {
			return r, err
		}
		metric = stats(v, leafExpected(main.MaxSlots(), c.R, zs[b]), c.R, nil)
		r.LeafDataErrorMax = math.Max(r.LeafDataErrorMax, metric.DataError)
	}
	return r, nil
}
