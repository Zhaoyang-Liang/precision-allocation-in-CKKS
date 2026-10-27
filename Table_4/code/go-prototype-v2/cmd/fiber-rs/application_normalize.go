package main

import (
	"fmt"
	"math"
	"math/big"
	"math/cmplx"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

// InverseSqrtApplicationOptions specify a public domain, not a domain inferred
// from decrypted data. Input is x/InputDivisor. The reference x is used only for
// diagnostics. Defaults are (5 iterations, [0.5,2], c=3/4), or (7 iterations,
// [0.25,4], c=1/2). Both use InputDivisor=32 and consume 2*Iterations-1 levels.
type InverseSqrtApplicationOptions struct {
	Iterations, R, TargetBits            int
	InputDivisor, LowerBound, UpperBound float64
	SeedSquare, MinConstantLogScale      float64
}

type InverseSqrtApplicationStage struct {
	Name, Operation                       string
	Iteration                             int
	Inputs                                []state
	Output                                state
	CircuitMetrics                        metric
	HasExactFunctionMetrics               bool
	ExactFunctionMetrics                  metric
	IdealCircuitVsFunctionMaxError        float64
	ConstantLogScale                      float64
	HasEncodedConstant                    bool
	HasObservedProductHeadroom            bool
	ObservedCanonicalProductHeadroomBits  float64
	ArithmeticSeconds, DiagnosticsSeconds float64
}

type InverseSqrtApplicationResult struct {
	Scope, Error                                       string
	Options                                            InverseSqrtApplicationOptions
	Initial, Final                                     state
	InitialMetrics, FinalMetrics                       metric
	FinalCircuitMetrics                                metric
	RequiredLevels, ConsumedLevels                     int
	Completed, MeetsTarget                             bool
	InitialResidualLower, InitialResidualUpper         float64
	IdealTruncationBound, ActualReferenceTruncationMax float64
	MinObservedConstantLogScale                        float64
	SeedConstantEncodingMetrics                        metric
	ArithmeticSeconds, DiagnosticsSeconds              float64
	TotalSeconds                                       float64
	Arithmetic                                         lb.ShapedStats
	Stages                                             []InverseSqrtApplicationStage
}

// RunInverseSqrtApplication computes 1/sqrt(x) from a real bootstrap output
// x/32, in whichever ring p describes. It never refreshes, re-encrypts x, or
// edits ciphertext Scale. The seed sqrt(c) is a genuinely encoded high-scale
// public plaintext, multiplied and rescaled once in parallel with the first
// two-level residual update. All additive constants are PA-masked constants.
//
// With a=(1-c*x)/4, the recurrence is
//
//	a_next = a*a*(3*mask+4*a), y_next = y*(mask+2*a).
//
// The first y is sqrt(c)*(mask+2*a0). This avoids approximate plaintext
// multiplication by 1/2 or 1/4 at every iteration. c*InputDivisor/4 must be an
// integer, so the initial affine map uses an exact integer multiplication and
// a masked addition at the input's actual scale. The function is not safe for
// concurrent calls sharing ev, whose statistics and scratch buffers are mutable.
func RunInverseSqrtApplication(p ckks.Parameters, sk *rlwe.SecretKey, ev *lb.ShapedEvaluator, input *rlwe.Ciphertext, wantedX []complex128, o InverseSqrtApplicationOptions) (output *rlwe.Ciphertext, res InverseSqrtApplicationResult, err error) {
	started := time.Now()
	res.Scope = "real mean-square to inverse square root; public fixed domain; original x reference; integer residual circuit; no re-encryption or ciphertext scale relabeling"
	defer func() {
		res.TotalSeconds = time.Since(started).Seconds()
		if err != nil {
			res.Error = err.Error()
		}
		if ev != nil {
			res.Arithmetic = ev.Stats
		}
	}()
	if o.Iterations == 0 {
		o.Iterations = 7
	}
	if o.R == 0 && ev != nil {
		o.R = ev.R
	}
	if o.TargetBits == 0 {
		o.TargetBits = 20
	}
	if o.InputDivisor == 0 {
		o.InputDivisor = 32
	}
	if o.LowerBound == 0 && o.UpperBound == 0 {
		if o.Iterations == 5 {
			o.LowerBound, o.UpperBound = 0.5, 2
		} else {
			o.LowerBound, o.UpperBound = 0.25, 4
		}
	}
	if o.SeedSquare == 0 {
		if o.Iterations == 5 {
			o.SeedSquare = 0.75
		} else {
			o.SeedSquare = 0.5
		}
	}
	if o.MinConstantLogScale == 0 {
		o.MinConstantLogScale = 20
	}
	res.Options = o
	if input == nil || ev == nil || sk == nil || len(wantedX) != p.MaxSlots() || o.R < 1 || p.MaxSlots()%o.R != 0 || ev.R != o.R || ev.Params.N() != p.N() {
		return nil, res, fmt.Errorf("invalid inverse-sqrt application dimensions/evaluator")
	}
	if p.LevelsConsumedPerRescaling() != 1 || o.Iterations < 2 || o.InputDivisor <= 0 || o.LowerBound <= 0 || o.UpperBound < o.LowerBound || o.SeedSquare <= 0 || o.SeedSquare*o.UpperBound >= 3 || o.MinConstantLogScale < 0 {
		return nil, res, fmt.Errorf("invalid inverse-sqrt application public domain or scale policy")
	}
	for _, v := range []float64{o.InputDivisor, o.LowerBound, o.UpperBound, o.SeedSquare, o.MinConstantLogScale} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, res, fmt.Errorf("nonfinite inverse-sqrt option")
		}
	}
	seedMultiplier := o.SeedSquare * o.InputDivisor / 4
	if seedMultiplier != math.Trunc(seedMultiplier) || seedMultiplier < 1 || seedMultiplier > 1<<52 {
		return nil, res, fmt.Errorf("c*InputDivisor/4=%g must be an exact positive integer; nonintegral preparation needs an explicitly budgeted extra plaintext multiplication", seedMultiplier)
	}
	res.RequiredLevels = 2*o.Iterations - 1
	if input.Level() < res.RequiredLevels {
		return nil, res, fmt.Errorf("inverse sqrt needs %d actual levels, input has %d", res.RequiredLevels, input.Level())
	}
	ev.Stats = lb.ShapedStats{}
	res.MinObservedConstantLogScale = math.MaxFloat64
	res.Initial = ctState(p, input)
	wantInput := make([]complex128, len(wantedX))
	exact := make([]complex128, len(wantedX))
	for j, x := range wantedX {
		if j%o.R != 0 {
			if x != 0 {
				return nil, res, fmt.Errorf("reference guard %d is nonzero", j)
			}
			continue
		}
		if imag(x) != 0 || math.IsNaN(real(x)) || real(x) < o.LowerBound || real(x) > o.UpperBound {
			return nil, res, fmt.Errorf("reference data %d is outside declared real domain [%g,%g]", j, o.LowerBound, o.UpperBound)
		}
		wantInput[j], exact[j] = x/complex(o.InputDivisor, 0), complex(1/math.Sqrt(real(x)), 0)
	}
	res.InitialResidualLower = 1 - o.SeedSquare*o.UpperBound
	res.InitialResidualUpper = 1 - o.SeedSquare*o.LowerBound
	f := func(r float64) float64 { return r * r * (3 + r) / 4 }
	rho := math.Max(f(res.InitialResidualLower), f(res.InitialResidualUpper))
	for j := 1; j < o.Iterations; j++ {
		rho = f(rho)
	}
	if rho >= 1 {
		return nil, res, fmt.Errorf("declared seed/domain does not give a convergent residual bound")
	}
	res.IdealTruncationBound = rho / (math.Sqrt(o.LowerBound) * (1 + math.Sqrt(1-rho)))

	// References and decrypted values are confined to this diagnostic closure.
	record := func(name, op string, iteration int, ct *rlwe.Ciphertext, want []complex128, function bool, inputs []state, elapsed float64, constantScale *rlwe.Scale, headroom *float64) error {
		row := InverseSqrtApplicationStage{Name: name, Operation: op, Iteration: iteration, Inputs: inputs, Output: ctState(p, ct), ArithmeticSeconds: elapsed, HasExactFunctionMetrics: function}
		if constantScale != nil {
			row.HasEncodedConstant, row.ConstantLogScale = true, scaleLog(*constantScale)
			res.MinObservedConstantLogScale = math.Min(res.MinObservedConstantLogScale, row.ConstantLogScale)
		}
		if headroom != nil {
			row.HasObservedProductHeadroom, row.ObservedCanonicalProductHeadroomBits = true, *headroom
		}
		t := time.Now()
		values, e := decode(p, sk, ct)
		if e != nil {
			return e
		}
		if row.CircuitMetrics, e = metrics(values, want, o.R); e != nil {
			return e
		}
		if function {
			if row.ExactFunctionMetrics, e = metrics(values, exact, o.R); e != nil {
				return e
			}
			for j := 0; j < len(want); j += o.R {
				row.IdealCircuitVsFunctionMaxError = math.Max(row.IdealCircuitVsFunctionMaxError, cmplx.Abs(want[j]-exact[j]))
			}
		}
		row.DiagnosticsSeconds = time.Since(t).Seconds()
		res.ArithmeticSeconds += elapsed
		res.DiagnosticsSeconds += row.DiagnosticsSeconds
		res.Stages = append(res.Stages, row)
		return nil
	}
	checkConstantScale := func(s rlwe.Scale) error {
		if v := scaleLog(s); math.IsNaN(v) || math.IsInf(v, 0) || v < o.MinConstantLogScale {
			return fmt.Errorf("public constant actual logscale %.12g below required %.12g", v, o.MinConstantLogScale)
		}
		return nil
	}
	integer := func(name string, iteration int, ct *rlwe.Ciphertext, want []complex128, multiplier int64) (*rlwe.Ciphertext, []complex128, error) {
		t := time.Now()
		out, e := ev.Evaluator.MulNew(ct, big.NewInt(multiplier)) // Exact integer: no encoded low-scale coefficient.
		elapsed := time.Since(t).Seconds()
		if e != nil {
			return nil, nil, e
		}
		ref := append([]complex128(nil), want...)
		for j := range ref {
			ref[j] *= complex(float64(multiplier), 0)
		}
		if e = record(name, "exact integer multiply", iteration, out, ref, false, []state{ctState(p, ct)}, elapsed, nil, nil); e != nil {
			return nil, nil, e
		}
		return out, ref, nil
	}
	addMasked := func(name string, iteration int, ct *rlwe.Ciphertext, want []complex128, value float64) (*rlwe.Ciphertext, []complex128, error) {
		if e := checkConstantScale(ct.Scale); e != nil {
			return nil, nil, e
		}
		t := time.Now()
		out, e := ev.AddNew(ct, value)
		elapsed := time.Since(t).Seconds()
		if e != nil {
			return nil, nil, e
		}
		ref := append([]complex128(nil), want...)
		for j := 0; j < len(ref); j += o.R {
			ref[j] += complex(value, 0)
		}
		if e = record(name, "high-scale PA masked constant add", iteration, out, ref, false, []state{ctState(p, ct)}, elapsed, &ct.Scale, nil); e != nil {
			return nil, nil, e
		}
		return out, ref, nil
	}
	product := func(name string, iteration int, left, right *rlwe.Ciphertext, wl, wr []complex128, function bool) (*rlwe.Ciphertext, []complex128, error) {
		level := min(left.Level(), right.Level())
		if level < 1 {
			return nil, nil, fmt.Errorf("%s has no rescale level", name)
		}
		prepareStart := time.Now()
		l, r := left.CopyNew(), right.CopyNew()
		// Dropping unused primes is a real modulus projection and keeps scale.
		ev.DropLevel(l, l.Level()-level)
		ev.DropLevel(r, r.Level()-level)
		prepareSeconds := time.Since(prepareStart).Seconds()
		ref := make([]complex128, len(wl))
		for j := range ref {
			ref[j] = wl[j] * wr[j]
		}
		d := time.Now()
		lv, e := decode(p, sk, l)
		if e != nil {
			return nil, nil, e
		}
		rv, e := decode(p, sk, r)
		if e != nil {
			return nil, nil, e
		}
		res.DiagnosticsSeconds += time.Since(d).Seconds()
		var observed *float64
		if w := vectorMax(lv) * vectorMax(rv); w > 0 && !math.IsInf(w, 0) {
			h := logProduct(p.Q()[:level+1]) - scaleLog(l.Scale) - scaleLog(r.Scale) - math.Log2(w) - 1
			observed = &h // Observed centered-decoding proxy; not a certified lift/KS bound.
		}
		t := time.Now()
		out, e := ev.MulRelinNew(l, r)
		elapsed := time.Since(t).Seconds() + prepareSeconds
		if e != nil {
			return nil, nil, e
		}
		if e = record(name+"/before-rescale", "ct x ct with shaped relinearization", iteration, out, ref, function, []state{ctState(p, l), ctState(p, r)}, elapsed, nil, observed); e != nil {
			return nil, nil, e
		}
		expectedScale := l.Scale.Mul(r.Scale).Div(rlwe.NewScale(p.Q()[level]))
		t = time.Now()
		e = ev.Rescale(out, out)
		elapsed = time.Since(t).Seconds()
		if e != nil {
			return nil, nil, e
		}
		if out.Level() != level-1 || math.Abs(scaleLog(out.Scale)-scaleLog(expectedScale)) > 1e-8 {
			return nil, nil, fmt.Errorf("%s actual rescale level/scale mismatch", name)
		}
		if e = record(name, "shaped rescale with actual scale", iteration, out, ref, function, []state{ctState(p, l), ctState(p, r)}, elapsed, nil, observed); e != nil {
			return nil, nil, e
		}
		return out, ref, nil
	}

	if err = record("input", "bootstrap output x/InputDivisor", 0, input, wantInput, false, nil, 0, nil, nil); err != nil {
		return nil, res, err
	}
	res.InitialMetrics = res.Stages[len(res.Stages)-1].CircuitMetrics
	a, wa, err := integer("a0/integer", 0, input, wantInput, -int64(seedMultiplier))
	if err != nil {
		return nil, res, err
	}
	a, wa, err = addMasked("a0", 0, a, wa, 0.25)
	if err != nil {
		return nil, res, err
	}
	factor, wfactor, err := integer("y1/factor-integer", 1, a, wa, 2)
	if err != nil {
		return nil, res, err
	}
	factor, wfactor, err = addMasked("y1/factor", 1, factor, wfactor, 1)
	if err != nil {
		return nil, res, err
	}

	// This public seed has a genuine q_last plaintext scale. Its one rescale
	// lies alongside the two-level a0 -> a1 path, so it does not add a level to
	// the final critical path when Iterations >= 2.
	seedScale := rlwe.NewScale(p.Q()[factor.Level()])
	if err = checkConstantScale(seedScale); err != nil {
		return nil, res, err
	}
	seed := math.Sqrt(o.SeedSquare)
	t := time.Now()
	pt, err := ev.ShapedPlaintext(seed, factor.Level(), seedScale)
	if err != nil {
		return nil, res, err
	}
	seedEncodingTime := time.Since(t).Seconds()
	d := time.Now()
	publicCT := ckks.NewCiphertext(p, 0, pt.Level())
	publicCT.MetaData = pt.MetaData.CopyNew()
	// The scalar plaintext represents a periodic mask in the full ring.
	// Expand only the diagnostic decode view; do not change the actual seed plaintext.
	publicCT.LogDimensions = p.LogMaxDimensions()
	publicCT.Value[0].Copy(pt.Value)
	publicValues, err := decodePlain(p, publicCT)
	if err != nil {
		return nil, res, err
	}
	seedWant := make([]complex128, len(wantedX))
	for j := 0; j < len(seedWant); j += o.R {
		seedWant[j] = complex(seed, 0)
	}
	if res.SeedConstantEncodingMetrics, err = metrics(publicValues, seedWant, o.R); err != nil {
		return nil, res, err
	}
	res.DiagnosticsSeconds += time.Since(d).Seconds()
	wy := make([]complex128, len(wfactor))
	for j := range wy {
		wy[j] = wfactor[j] * complex(seed, 0)
	}
	t = time.Now()
	y, err := ev.MulNew(factor, pt)
	elapsed := time.Since(t).Seconds() + seedEncodingTime
	if err != nil {
		return nil, res, err
	}
	if err = record("y1/before-rescale", "genuine high-scale public seed multiply", 1, y, wy, true, []state{ctState(p, factor)}, elapsed, &seedScale, nil); err != nil {
		return nil, res, err
	}
	t = time.Now()
	err = ev.Rescale(y, y)
	elapsed = time.Since(t).Seconds()
	if err != nil {
		return nil, res, err
	}
	if y.Level() != input.Level()-1 || math.Abs(scaleLog(y.Scale)-scaleLog(factor.Scale)) > 1e-8 {
		return nil, res, fmt.Errorf("seed multiplication actual rescale mismatch")
	}
	if err = record("y1", "shaped rescale public seed", 1, y, wy, true, []state{ctState(p, factor)}, elapsed, nil, nil); err != nil {
		return nil, res, err
	}
	for iteration := 2; iteration <= o.Iterations; iteration++ {
		a2, wa2, e := product(fmt.Sprintf("a%d/square", iteration-1), iteration, a, a, wa, wa, false)
		if e != nil {
			return nil, res, e
		}
		cubic, wcubic, e := integer(fmt.Sprintf("a%d/factor-integer", iteration-1), iteration, a, wa, 4)
		if e != nil {
			return nil, res, e
		}
		cubic, wcubic, e = addMasked(fmt.Sprintf("a%d/factor", iteration-1), iteration, cubic, wcubic, 3)
		if e != nil {
			return nil, res, e
		}
		a, wa, e = product(fmt.Sprintf("a%d", iteration-1), iteration, a2, cubic, wa2, wcubic, false)
		if e != nil {
			return nil, res, e
		}
		factor, wfactor, e = integer(fmt.Sprintf("y%d/factor-integer", iteration), iteration, a, wa, 2)
		if e != nil {
			return nil, res, e
		}
		factor, wfactor, e = addMasked(fmt.Sprintf("y%d/factor", iteration), iteration, factor, wfactor, 1)
		if e != nil {
			return nil, res, e
		}
		y, wy, e = product(fmt.Sprintf("y%d", iteration), iteration, y, factor, wy, wfactor, true)
		if e != nil {
			return nil, res, e
		}
	}
	res.Final = ctState(p, y)
	res.ConsumedLevels = input.Level() - y.Level()
	if res.ConsumedLevels != res.RequiredLevels {
		return nil, res, fmt.Errorf("inverse sqrt consumed %d rather than %d levels", res.ConsumedLevels, res.RequiredLevels)
	}
	last := res.Stages[len(res.Stages)-1]
	res.FinalMetrics, res.FinalCircuitMetrics = last.ExactFunctionMetrics, last.CircuitMetrics
	res.ActualReferenceTruncationMax = last.IdealCircuitVsFunctionMaxError
	res.Completed = true
	res.MeetsTarget = res.FinalMetrics.MaxErrorBits >= float64(o.TargetBits)
	return y, res, nil
}
