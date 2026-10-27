package main

import (
	"fmt"
	"math"
	"math/cmplx"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

type stageMetric struct {
	Name                                   string
	Lane, Level                            int
	LogScale, DataMax, GuardMax, DataError float64
	HasReference                           bool
}

// Diagnostic-only deterministic reruns. Secret keys and plaintext oracles never
// enter refreshLeaves or onlineRun, and no diagnostics modify measured outputs.
func collectStages(engines []*leafEngine, leaves, outputs []*rlwe.Ciphertext,
	low, main ckks.Parameters, sk *rlwe.SecretKey, zs []complex128, c config, trial int, tr *trialResult) error {
	return runIndexed(len(leaves), c.Workers, func(b int) error {
		if tr.Branches[b].Skipped {
			return nil
		}
		e := engines[b]
		e.fused.SetRoundingSeed(c.Seed + int64(trial)*1000003 + int64(b))
		br := &tr.Branches[b]
		entryValue := zs[b] + complex(br.EntryErrorReal, br.EntryErrorImag)
		tin := [2]float64{(float64(br.CarryReal) + real(entryValue)/e.beta) / float64(c.K),
			(float64(br.CarryImag) + imag(entryValue)/e.beta) / float64(c.K)}
		ideal := complex(e.beta*lb.Mod1PlaintextOracle(e.plan, tin[0]), e.beta*lb.Mod1PlaintextOracle(e.plan, tin[1]))
		approxErr := ideal - entryValue
		br.IdealMod1ErrorReal, br.IdealMod1ErrorImag = real(approxErr), imag(approxErr)
		hook := func(lane int, name string, ct *rlwe.Ciphertext) error {
			v, err := decode(main, sk, ct)
			if err != nil {
				return err
			}
			m := stageMetric{Name: name, Lane: lane, Level: ct.Level(), LogScale: scaleLog(ct.Scale)}
			ref := complex(0, 0)
			if name == "fused" {
				m.HasReference = true
				ref = complex(tin[lane], 0)
			}
			if name == "final_rescale" || name == "final_scale_return" {
				m.HasReference = true
				ref = complex(e.beta*lb.Mod1PlaintextOracle(e.plan, tin[lane]), 0)
			}
			for j, x := range v {
				if j%c.R == 0 {
					m.DataMax = math.Max(m.DataMax, cmplx.Abs(x))
					if m.HasReference {
						m.DataError = math.Max(m.DataError, cmplx.Abs(x-ref))
					}
				} else {
					m.GuardMax = math.Max(m.GuardMax, cmplx.Abs(x))
				}
			}
			br.Stages = append(br.Stages, m)
			return nil
		}
		out, err := e.refreshWithHook(leaves[b], hook)
		if err != nil {
			return err
		}
		if !out.Equal(outputs[b]) {
			return fmt.Errorf("stage diagnostic rerun changed ciphertext")
		}
		v, err := decode(main, sk, out)
		if err != nil {
			return err
		}
		mean := complex(0, 0)
		count := 0
		for j, x := range v {
			if j%c.R == 0 {
				r := x - ideal
				br.CircuitVsEntryOracleMax = math.Max(br.CircuitVsEntryOracleMax, cmplx.Abs(r))
				mean += r
				count++
			}
		}
		mean /= complex(float64(count), 0)
		br.CircuitErrorMeanReal, br.CircuitErrorMeanImag = real(mean), imag(mean)
		return nil
	})
}
