package main

import (
	"fmt"
	"math"
	"math/cmplx"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

// BoundedChainOptions describe an application-capacity probe. Every multiplier
// is an independently encrypted active-slot phase of modulus one, so the ideal
// signal does not decay and there is no metadata-only scale adjustment.
type BoundedChainOptions struct {
	Steps                     int
	PhaseRadians              float64
	ShapeFactor               bool
	R, OutputBits, TargetBits int
}
type ApplicationChainStep struct {
	Index                                                                       int
	Input, Factor, ProductBeforeRescale, Output                                 state
	InputMetrics, FactorMetrics, ProductMetrics, OutputMetrics                  metric
	ExpectedMaxMagnitude, ExpectedMeanMagnitude                                 float64
	MaxPhysicalInput, MaxPhysicalFactor, CanonicalProductHeadroomBits           float64
	FactorGenerationSeconds, MulRelinSeconds, RescaleSeconds, ArithmeticSeconds float64
	MeetsTarget                                                                 bool
	Arithmetic                                                                  lb.ShapedStats
}
type ApplicationChainResult struct {
	Scope, Error                                                   string
	Options                                                        BoundedChainOptions
	Initial, Final                                                 state
	InitialMetrics, FinalMetrics                                   metric
	RequestedSteps, ExecutedSteps                                  int
	InitialMeetsTarget, EveryOutputMeetsTarget, ReachedLevelZero   bool
	FactorGenerationSeconds, ArithmeticSeconds, DiagnosticsSeconds float64
	Steps                                                          []ApplicationChainStep
}

func vectorMax(v []complex128) float64 {
	m := 0.0
	for _, z := range v {
		m = math.Max(m, cmplx.Abs(z))
	}
	return m
}
func expectedMagnitudes(v []complex128, R int) (m, mean float64) {
	n := 0
	for i, z := range v {
		if i%R == 0 {
			a := cmplx.Abs(z)
			m = math.Max(m, a)
			mean += a
			n++
		}
	}
	mean /= float64(n)
	return
}

// RunBoundedApplicationChain does real ciphertext-ciphertext multiply, shaped
// relinearization and shaped rescale at every step. The known reference is
// provided separately from input. Secrets are used only to generate independent
// auxiliary ciphertexts and to measure errors; neither influences arithmetic.
func RunBoundedApplicationChain(p ckks.Parameters, sk *rlwe.SecretKey, ev *lb.ShapedEvaluator, input *rlwe.Ciphertext, wanted []complex128, o BoundedChainOptions) (res ApplicationChainResult, err error) {
	res.Options = o
	res.Scope = "independent fresh ciphertext multiplication by unit-modulus active-slot phase; constant signal magnitude; guards zero ideally"
	defer func() {
		if err != nil {
			res.Error = err.Error()
		}
	}()
	if input == nil || ev == nil || sk == nil || len(wanted) != p.MaxSlots() || o.R < 1 || p.MaxSlots()%o.R != 0 || o.Steps < -1 || o.OutputBits < 1 || math.IsNaN(o.PhaseRadians) || math.IsInf(o.PhaseRadians, 0) {
		return res, fmt.Errorf("invalid bounded chain input")
	}
	steps := o.Steps
	if steps == -1 {
		steps = input.Level()
	}
	if steps > input.Level() {
		return res, fmt.Errorf("requested %d multiplications but input level is %d", steps, input.Level())
	}
	res.RequestedSteps = steps
	current := input.CopyNew()
	want := append([]complex128(nil), wanted...)
	res.Initial = ctState(p, current)
	res.EveryOutputMeetsTarget = true
	measureStart := time.Now()
	initialValues, err := decode(p, sk, current)
	if err != nil {
		return res, err
	}
	res.InitialMetrics, err = metrics(initialValues, want, o.R)
	if err != nil {
		return res, err
	}
	res.InitialMeetsTarget = res.InitialMetrics.MaxErrorBits >= float64(o.TargetBits)
	res.DiagnosticsSeconds += time.Since(measureStart).Seconds()
	phase := cmplx.Exp(complex(0, o.PhaseRadians))
	factorWanted := make([]complex128, p.MaxSlots())
	for j := 0; j < len(factorWanted); j += o.R {
		factorWanted[j] = phase
	}
	encoder := ckks.NewEncoder(p, 128)
	encryptor := rlwe.NewEncryptor(p, sk)
	targetScale := rlwe.NewScale(math.Exp2(float64(o.OutputBits)))
	for index := 1; index <= steps; index++ {
		row := ApplicationChainStep{Index: index, Input: ctState(p, current)}
		d := time.Now()
		currentValues, e := decode(p, sk, current)
		if e != nil {
			return res, e
		}
		row.InputMetrics, e = metrics(currentValues, want, o.R)
		if e != nil {
			return res, e
		}
		res.DiagnosticsSeconds += time.Since(d).Seconds()
		// Delta_factor=q_last*Delta_target/Delta_current is a genuine plaintext
		// encoding scale. Its actual value is recorded and used by encryption.
		f := time.Now()
		factorScale := rlwe.NewScale(p.Q()[current.Level()]).Mul(targetScale).Div(current.Scale)
		pt := ckks.NewPlaintext(p, current.Level())
		pt.Scale = factorScale
		factorValues := append([]complex128(nil), factorWanted...)
		if o.ShapeFactor {
			for j := range factorValues {
				factorValues[j] /= ev.Focus
			}
		}
		if e = encoder.Encode(factorValues, pt); e != nil {
			return res, e
		}
		factor, e := encryptor.EncryptNew(pt)
		if e != nil {
			return res, e
		}
		if o.ShapeFactor {
			factor, e = lb.MulNTTMontgomeryPolynomial(p, factor, ev.UnitNTT)
			if e != nil {
				return res, e
			}
		}
		row.FactorGenerationSeconds = time.Since(f).Seconds()
		row.Factor = ctState(p, factor)
		d = time.Now()
		decodedFactor, e := decode(p, sk, factor)
		if e != nil {
			return res, e
		}
		row.FactorMetrics, e = metrics(decodedFactor, factorWanted, o.R)
		if e != nil {
			return res, e
		}
		row.MaxPhysicalInput, row.MaxPhysicalFactor = vectorMax(currentValues), vectorMax(decodedFactor)
		row.CanonicalProductHeadroomBits = row.Input.LogQ - row.Input.LogScale - row.Factor.LogScale - math.Log2(row.MaxPhysicalInput*row.MaxPhysicalFactor) - 1
		for j := range want {
			want[j] *= phase
		}
		row.ExpectedMaxMagnitude, row.ExpectedMeanMagnitude = expectedMagnitudes(want, o.R)
		res.DiagnosticsSeconds += time.Since(d).Seconds()
		ev.Stats = lb.ShapedStats{}
		t := time.Now()
		product, e := ev.MulRelinNew(current, factor)
		row.MulRelinSeconds = time.Since(t).Seconds()
		if e != nil {
			return res, e
		}
		row.ProductBeforeRescale = ctState(p, product)
		d = time.Now()
		row.ProductMetrics, e = measure(p, sk, product, want, o.R)
		if e != nil {
			return res, e
		}
		res.DiagnosticsSeconds += time.Since(d).Seconds()
		t = time.Now()
		if e = ev.Rescale(product, product); e != nil {
			return res, e
		}
		row.RescaleSeconds = time.Since(t).Seconds()
		row.ArithmeticSeconds = row.MulRelinSeconds + row.RescaleSeconds
		row.Arithmetic = ev.Stats
		row.Output = ctState(p, product)
		if product.Level() != current.Level()-1 {
			return res, fmt.Errorf("step%d consumed wrong level count", index)
		}
		if math.Abs(row.Output.LogScale-float64(o.OutputBits)) > 1e-8 {
			return res, fmt.Errorf("step%d actual scale %.12g differs from requested %d", index, row.Output.LogScale, o.OutputBits)
		}
		d = time.Now()
		row.OutputMetrics, e = measure(p, sk, product, want, o.R)
		if e != nil {
			return res, e
		}
		res.DiagnosticsSeconds += time.Since(d).Seconds()
		row.MeetsTarget = row.OutputMetrics.MaxErrorBits >= float64(o.TargetBits)
		res.EveryOutputMeetsTarget = res.EveryOutputMeetsTarget && row.MeetsTarget
		res.ArithmeticSeconds += row.ArithmeticSeconds
		res.FactorGenerationSeconds += row.FactorGenerationSeconds
		res.Steps = append(res.Steps, row)
		res.ExecutedSteps++
		current = product
	}
	res.Final = ctState(p, current)
	res.FinalMetrics = res.InitialMetrics
	if len(res.Steps) > 0 {
		res.FinalMetrics = res.Steps[len(res.Steps)-1].OutputMetrics
	}
	res.ReachedLevelZero = current.Level() == 0
	return res, nil
}
