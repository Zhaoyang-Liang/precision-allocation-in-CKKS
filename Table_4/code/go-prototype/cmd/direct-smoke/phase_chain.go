package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
	"math"
	"math/cmplx"
	"time"
)

type phaseChainStep struct {
	Index                                                         int
	Input, Factor, Product, Output                                modulusState
	FactorMetrics, OutputMetrics                                  metric
	Arithmetic                                                    lb.ShapedStats
	ExpectedMagnitude, FactorGenerationSeconds, ArithmeticSeconds float64
	MeetsTarget                                                   bool
}
type phaseChainResult struct {
	Scope, Error                                           string
	RequestedSteps, ExecutedSteps, ConsecutivePassingSteps int
	Initial, Final                                         modulusState
	InitialMetrics, FinalMetrics                           metric
	EveryOutputMeetsTarget                                 bool
	ArithmeticSeconds, FactorGenerationSeconds             float64
	Steps                                                  []phaseChainStep
}

// Constant-magnitude capacity probe, not an application benchmark. Each factor
// is a newly encrypted phase; rescale consumes the actual last Q prime. Secrets
// are used only for factor generation and diagnostics, never for ciphertext repair.
func runPhaseChain(p ckks.Parameters, sk *rlwe.SecretKey, ev *lb.ShapedEvaluator, input *rlwe.Ciphertext, z complex128, c config) (r phaseChainResult, err error) {
	defer func() {
		if err != nil {
			r.Error = err.Error()
		}
	}()
	r.Scope = "real ciphertext multiplications by independently encrypted unit phases; non-decaying reference; no scale metadata adjustment"
	square := c.ChainOperation == "square"
	if c.ChainOperation != "" && c.ChainOperation != "phase" && !square {
		return r, fmt.Errorf("unknown application chain operation")
	}
	if square {
		if math.Abs(cmplx.Abs(z)-1) > 1e-12 {
			return r, fmt.Errorf("squaring capacity probe requires unit-magnitude input")
		}
		r.Scope = "successive real ciphertext squaring; unit-magnitude reference; actual evolving scales; no scale metadata adjustment"
	}
	steps := c.ChainLength
	if steps == -1 {
		steps = input.Level()
	}
	if steps < 0 || steps > input.Level() {
		return r, fmt.Errorf("invalid chain length")
	}
	r.RequestedSteps = steps
	cur := input.CopyNew()
	r.Initial = state(p, cur)
	r.InitialMetrics, err = measure(p, sk, cur, z, c.R)
	if err != nil {
		return
	}
	r.EveryOutputMeetsTarget = r.InitialMetrics.MaxErrorBits >= float64(c.TargetBits)
	prefixOK := r.EveryOutputMeetsTarget
	enc := ckks.NewEncoder(p, 128)
	encryptor := rlwe.NewEncryptor(p, sk)
	phase := cmplx.Exp(complex(0, math.Pi/7))
	want := z
	for i := 1; i <= steps; i++ {
		row := phaseChainStep{Index: i, Input: state(p, cur)}
		start := time.Now()
		var factor *rlwe.Ciphertext
		factorWant := phase
		if square {
			factor = cur
			factorWant = want
		} else {
			pt := ckks.NewPlaintext(p, cur.Level())
			pt.Scale = rlwe.NewScale(p.Q()[cur.Level()]).Mul(rlwe.NewScale(math.Exp2(float64(c.OutputBits)))).Div(cur.Scale)
			values := make([]complex128, p.MaxSlots())
			for j := 0; j < len(values); j += c.R {
				values[j] = phase / ev.Focus
			}
			if err = enc.Encode(values, pt); err != nil {
				return
			}
			factor, err = encryptor.EncryptNew(pt)
			if err != nil {
				return
			}
			factor, err = lb.MulNTTMontgomeryPolynomial(p, factor, ev.UnitNTT)
			if err != nil {
				return
			}
			row.FactorGenerationSeconds = time.Since(start).Seconds()
		}
		row.Factor = state(p, factor)
		row.FactorMetrics, err = measure(p, sk, factor, factorWant, c.R)
		if err != nil {
			return
		}
		ev.Stats = lb.ShapedStats{}
		start = time.Now()
		var product *rlwe.Ciphertext
		product, err = ev.MulRelinNew(cur, factor)
		if err != nil {
			return
		}
		row.Product = state(p, product)
		if err = ev.Rescale(product, product); err != nil {
			return
		}
		row.ArithmeticSeconds = time.Since(start).Seconds()
		row.Arithmetic = ev.Stats
		row.Output = state(p, product)
		expectedScale := row.Input.LogScale + row.Factor.LogScale - math.Log2(float64(p.Q()[cur.Level()]))
		if product.Level() != cur.Level()-1 || math.Abs(row.Output.LogScale-expectedScale) > 1e-7 {
			return r, fmt.Errorf("incorrect real level/scale transition")
		}
		want *= factorWant
		row.ExpectedMagnitude = cmplx.Abs(want)
		row.OutputMetrics, err = measure(p, sk, product, want, c.R)
		if err != nil {
			return
		}
		row.MeetsTarget = row.OutputMetrics.MaxErrorBits >= float64(c.TargetBits)
		prefixOK = prefixOK && row.MeetsTarget
		if prefixOK {
			r.ConsecutivePassingSteps++
		}
		r.EveryOutputMeetsTarget = r.EveryOutputMeetsTarget && row.MeetsTarget
		r.ArithmeticSeconds += row.ArithmeticSeconds
		r.FactorGenerationSeconds += row.FactorGenerationSeconds
		r.Steps = append(r.Steps, row)
		r.ExecutedSteps++
		cur = product
	}
	r.Final = state(p, cur)
	r.FinalMetrics = r.InitialMetrics
	if len(r.Steps) > 0 {
		r.FinalMetrics = r.Steps[len(r.Steps)-1].OutputMetrics
	}
	return
}
