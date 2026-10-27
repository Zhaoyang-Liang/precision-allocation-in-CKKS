package main

// Dense, real-valued N16 statistics frontend. No driver wiring lives here.
// Full-slot square/relinearization/reduction are ordinary CKKS; PA starts only
// at the final data mask. Secret access is confined to setup, encryption, and
// diagnostics, outside every online timer. Instances are sequential-use only.

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

type StatisticsFrontendResult struct {
	Scope, Error                                                             string
	Seed                                                                     int64
	R, Groups, SamplesPerGroup, TotalSamples                                 int
	Targets, IndependentMeanSquares                                          []float64
	TargetNormalizationMaxError, InputMaxMagnitude                           float64
	QPrimes, PPrimes                                                         []uint64
	RotationOffsets                                                          []int
	RelinearizationKeyLevel, RotationKeyLevel                                int
	RelinearizationKeyBytes, RotationKeyBytes, KeyBytes                      int
	FullLogQ, FullLogQP, MaskLogScale                                        float64
	Input, AfterSquare, BeforeMask, BeforeFinalRescale, Output               state
	InputMetrics, SquaredMetrics, SumDataMetrics, MaskMetrics, OutputMetrics metric
	MeanSquareMaxAbsError, MeanSquareWorstBits                               float64
	IdealOddBranchIsZero                                                     bool
	SetupSeconds, KeygenSeconds, MaskSetupSeconds                            float64
	InputGenerationSeconds, EncodingEncryptionSeconds, DiagnosticsSeconds    float64
	SquareRelinearizeSeconds, SquareRescaleSeconds, ReductionSeconds         float64
	MaskMultiplySeconds, FinalRescaleSeconds, OnlineSeconds                  float64
	FinalArithmetic                                                          lb.ShapedStats
}

type StatisticsFrontend struct {
	params                  ckks.Parameters
	sk                      *rlwe.SecretKey
	base                    *ckks.Evaluator
	shaped                  *lb.ShapedEvaluator
	mask                    *rlwe.Plaintext
	R, groups, samples      int
	rotations               []int
	inputScale, squareScale rlwe.Scale
	setup                   StatisticsFrontendResult
}

// NewStatisticsFrontend prepares reusable front-end keys and the final mask.
// unit/inverse are full top-ring integer coefficient vectors; focus is their
// common positive real data embedding. The caller establishes unit validity.
// It generates exactly one relinearization key at level3 and the required
// rotation keys at level2, with the same top ternary secret in a new Q basis.
// Returned ciphertexts share top.Q()[0:2] and the original top secret; no
// online decryption, re-encryption, secret replacement, or metadata scaling.
func NewStatisticsFrontend(top ckks.Parameters, skTop *rlwe.SecretKey, unit, inverse []*big.Int, R, k int, focus complex128) (f *StatisticsFrontend, err error) {
	start := time.Now()
	S := top.MaxSlots()
	if skTop == nil || top.MaxLevel() < 1 || R < 1 || R&(R-1) != 0 || k < 1 || k&(k-1) != 0 || k%R != 0 || k*R > S/2 || S%(k*R) != 0 || len(unit) != top.N() || len(inverse) != top.N() || imag(focus) != 0 || real(focus) <= 0 || math.IsInf(real(focus), 0) || math.IsNaN(real(focus)) {
		return nil, fmt.Errorf("invalid dense statistics frontend dimensions/unit")
	}
	used := make(map[uint64]bool)
	for _, q := range top.Q() {
		used[q] = true
	}
	for _, p := range top.P() {
		used[p] = true
	}
	gen := ring.NewNTTFriendlyPrimesGenerator(40, uint64(2*top.N()))
	qs := append([]uint64(nil), top.Q()[:2]...)
	for len(qs) < 4 {
		q, e := gen.NextUpstreamPrime()
		if e != nil {
			return nil, e
		}
		if !used[q] {
			used[q] = true
			qs = append(qs, q)
		}
	}
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: top.LogN(), Q: qs, P: append([]uint64(nil), top.P()...),
		Xs: top.Xs(), Xe: top.Xe(), LogDefaultScale: 40,
	})
	if err != nil {
		return nil, err
	}
	sk, err := lb.RebaseSecretKey(top, p, skTop)
	if err != nil {
		return nil, err
	}
	f = &StatisticsFrontend{params: p, sk: sk, R: R, groups: k, samples: S / k, inputScale: rlwe.NewScale(math.Exp2(40))}
	for stride := k * R; stride < S; stride *= 2 {
		f.rotations = append(f.rotations, stride)
	}
	for stride := 1; stride < R; stride *= 2 {
		f.rotations = append(f.rotations, stride)
	}
	gals := make([]uint64, len(f.rotations))
	for i, offset := range f.rotations {
		gals[i] = p.GaloisElementForRotation(offset)
	}
	kg := rlwe.NewKeyGenerator(p)
	lRelin, lRotate, lp := 3, 2, p.MaxLevelP()
	keyStart := time.Now()
	relin := kg.GenRelinearizationKeyNew(sk, rlwe.EvaluationKeyParameters{LevelQ: &lRelin, LevelP: &lp})
	rotkeys := kg.GenGaloisKeysNew(gals, sk, rlwe.EvaluationKeyParameters{LevelQ: &lRotate, LevelP: &lp})
	keySeconds := time.Since(keyStart).Seconds()
	f.base = ckks.NewEvaluator(p, rlwe.NewMemEvaluationKeySet(relin, rotkeys...))
	f.shaped, err = lb.NewShapedEvaluator(p, f.base, unit, inverse, R, focus)
	if err != nil {
		return nil, err
	}
	f.squareScale = f.inputScale.Mul(f.inputScale).Div(rlwe.NewScale(qs[3]))
	// S_pt = q2 * Delta_target / Delta_after_square. It is used by genuine
	// plaintext encoding and multiplication; ct.Scale is never overwritten.
	maskScale := rlwe.NewScale(qs[2]).Mul(f.inputScale).Div(f.squareScale)
	maskValues := make([]complex128, S)
	for j := 0; j < S; j += R {
		maskValues[j] = complex(1/(32*float64(f.samples)), 0)
	}
	maskStart := time.Now()
	f.mask, err = f.shaped.ShapedPlaintext(maskValues, 2, maskScale)
	if err != nil {
		return nil, err
	}
	maskDecoded := make([]complex128, S)
	if err = ckks.NewEncoder(p, 128).Decode(f.mask, maskDecoded); err != nil {
		return nil, err
	}
	maskMetrics, err := metrics(maskDecoded, maskValues, R)
	if err != nil {
		return nil, err
	}
	maskSeconds := time.Since(maskStart).Seconds()
	keyBytes := relin.BinarySize()
	for _, key := range rotkeys {
		keyBytes += key.BinarySize()
	}
	f.setup = StatisticsFrontendResult{
		Scope: "synthetic dense real samples -> genuine square/relinearize/rescale -> ordinary rotations/additions -> shaped data mask/(32*samples) -> shaped rescale; same top secret and shared q0,q1",
		R:     R, Groups: k, SamplesPerGroup: f.samples, TotalSamples: S,
		QPrimes: append([]uint64(nil), qs...), PPrimes: append([]uint64(nil), p.P()...), RotationOffsets: append([]int(nil), f.rotations...),
		RelinearizationKeyLevel: 3, RotationKeyLevel: 2,
		RelinearizationKeyBytes: relin.BinarySize(), RotationKeyBytes: keyBytes - relin.BinarySize(), KeyBytes: keyBytes,
		FullLogQ: p.LogQ(), FullLogQP: p.LogQP(), MaskLogScale: scaleLog(maskScale), MaskMetrics: maskMetrics,
		KeygenSeconds: keySeconds, MaskSetupSeconds: maskSeconds, SetupSeconds: time.Since(start).Seconds(),
	}
	return f, nil
}

// Run creates one varying synthetic dense input, executes the actual frontend,
// and independently measures it. targetXs are desired unscaled group MSEs, not
// online operands. References are recomputed from the actual generated samples.
// Run reuses cached keys; SetupSeconds in each result describes that same setup
// and must be charged once, not summed over trials. OnlineSeconds is the sum of
// timed homomorphic operations only. Input/reference generation and diagnostics
// cannot influence the online output.
func (f *StatisticsFrontend) Run(seed int64, targetXs []float64) (out *rlwe.Ciphertext, wantTop []complex128, res StatisticsFrontendResult, err error) {
	if f == nil {
		return nil, nil, res, fmt.Errorf("nil statistics frontend")
	}
	res = f.setup
	res.Seed = seed
	defer func() {
		if err != nil {
			res.Error = err.Error()
		}
	}()
	if len(targetXs) != f.groups {
		return nil, nil, res, fmt.Errorf("want %d target mean squares, got %d", f.groups, len(targetXs))
	}
	for _, x := range targetXs {
		if math.IsNaN(x) || math.IsInf(x, 0) || x < .25 || x > 4 {
			return nil, nil, res, fmt.Errorf("target mean square outside [.25,4]")
		}
	}
	genStart := time.Now()
	res.Targets = append([]float64(nil), targetXs...)
	S := f.params.MaxSlots()
	rng := rand.New(rand.NewSource(seed))
	values := make([]complex128, S)
	initialSquares := make([]float64, f.groups)
	for j := range values {
		x := .5 + rng.Float64()
		if rng.Intn(2) == 0 {
			x = -x
		}
		values[j] = complex(x, 0)
		initialSquares[(j/f.R)%f.groups] += x * x
	}
	for j := range values {
		g := (j / f.R) % f.groups
		values[j] *= complex(math.Sqrt(targetXs[g]*float64(f.samples)/initialSquares[g]), 0)
	}
	// Independent reference pass; never read targetXs as the online answer.
	squaredWant := make([]complex128, S)
	groupSums := make([]float64, f.groups)
	for j, z := range values {
		x := real(z)
		squaredWant[j] = complex(x*x, 0)
		groupSums[(j/f.R)%f.groups] += x * x
		res.InputMaxMagnitude = math.Max(res.InputMaxMagnitude, math.Abs(x))
	}
	res.IndependentMeanSquares = make([]float64, f.groups)
	for g, sum := range groupSums {
		res.IndependentMeanSquares[g] = sum / float64(f.samples)
		res.TargetNormalizationMaxError = math.Max(res.TargetNormalizationMaxError, math.Abs(res.IndependentMeanSquares[g]-targetXs[g]))
	}
	wantTop, sumWant := make([]complex128, S), make([]complex128, S)
	for j := 0; j < S; j += f.R {
		g := (j / f.R) % f.groups
		wantTop[j] = complex(res.IndependentMeanSquares[g]/32, 0)
		sumWant[j] = complex(groupSums[g], 0)
	}
	res.IdealOddBranchIsZero = true
	for j := 0; j < S/2; j++ {
		if wantTop[j] != wantTop[j+S/2] {
			res.IdealOddBranchIsZero = false
		}
	}
	if !res.IdealOddBranchIsZero {
		return nil, nil, res, fmt.Errorf("statistics reference is not in the even-branch subalgebra")
	}
	res.InputGenerationSeconds = time.Since(genStart).Seconds()
	encStart := time.Now()
	pt := ckks.NewPlaintext(f.params, 3)
	pt.Scale = f.inputScale
	if err = ckks.NewEncoder(f.params, 128).Encode(values, pt); err != nil {
		return nil, nil, res, err
	}
	input, err := rlwe.NewEncryptor(f.params, f.sk).EncryptNew(pt)
	if err != nil {
		return nil, nil, res, err
	}
	res.EncodingEncryptionSeconds = time.Since(encStart).Seconds()
	res.Input = ctState(f.params, input)

	// Full-slot input: ordinary CKKS arithmetic before any data mask.
	t := time.Now()
	squared, err := f.base.MulRelinNew(input, input)
	res.SquareRelinearizeSeconds = time.Since(t).Seconds()
	if err != nil {
		return nil, nil, res, err
	}
	t = time.Now()
	err = f.base.Rescale(squared, squared)
	res.SquareRescaleSeconds = time.Since(t).Seconds()
	if err != nil {
		return nil, nil, res, err
	}
	res.AfterSquare = ctState(f.params, squared)
	if squared.Level() != 2 || !squared.Scale.InDelta(f.squareScale, 60) {
		return nil, nil, res, fmt.Errorf("unexpected frontend square level/scale")
	}
	// Diagnostic preservation is excluded from online operations.
	d := time.Now()
	squaredDiagnostic := squared.CopyNew()
	res.DiagnosticsSeconds += time.Since(d).Seconds()
	sum := squared
	t = time.Now()
	for _, offset := range f.rotations {
		rotated, e := f.base.RotateNew(sum, offset)
		if e != nil {
			return nil, nil, res, e
		}
		if e = f.base.Add(sum, rotated, sum); e != nil {
			return nil, nil, res, e
		}
	}
	res.ReductionSeconds = time.Since(t).Seconds()
	res.BeforeMask = ctState(f.params, sum)
	f.shaped.Stats = lb.ShapedStats{}
	t = time.Now()
	masked, err := f.base.MulNew(sum, f.mask)
	res.MaskMultiplySeconds = time.Since(t).Seconds()
	if err != nil {
		return nil, nil, res, err
	}
	res.BeforeFinalRescale = ctState(f.params, masked)
	out = ckks.NewCiphertext(f.params, 1, 1)
	t = time.Now()
	err = f.shaped.Rescale(masked, out)
	res.FinalRescaleSeconds = time.Since(t).Seconds()
	if err != nil {
		return nil, nil, res, err
	}
	res.FinalArithmetic = f.shaped.Stats
	res.OnlineSeconds = res.SquareRelinearizeSeconds + res.SquareRescaleSeconds + res.ReductionSeconds + res.MaskMultiplySeconds + res.FinalRescaleSeconds
	res.Output = ctState(f.params, out)
	if out.Level() != 1 || math.Abs(scaleLog(out.Scale)-40) > 1e-9 {
		return nil, nil, res, fmt.Errorf("frontend output must have L1 and actual scale40")
	}

	// Post-run secret diagnostics only; never fed back into the ciphertext.
	d = time.Now()
	if res.InputMetrics, err = measure(f.params, f.sk, input, values, 1); err != nil {
		return nil, nil, res, err
	}
	if res.SquaredMetrics, err = measure(f.params, f.sk, squaredDiagnostic, squaredWant, 1); err != nil {
		return nil, nil, res, err
	}
	if res.SumDataMetrics, err = measure(f.params, f.sk, sum, sumWant, f.R); err != nil {
		return nil, nil, res, err
	}
	if res.OutputMetrics, err = measure(f.params, f.sk, out, wantTop, f.R); err != nil {
		return nil, nil, res, err
	}
	res.MeanSquareMaxAbsError = 32 * res.OutputMetrics.MaxAbsError
	res.MeanSquareWorstBits = bitsError(res.MeanSquareMaxAbsError)
	res.DiagnosticsSeconds += time.Since(d).Seconds()
	return out, wantTop, res, nil
}

// BuildStatisticsFrontend is the one-shot convenience wrapper. Prefer New...
// followed by Run for paired runs/trials so setup and evaluation keys are reused.
func BuildStatisticsFrontend(top ckks.Parameters, skTop *rlwe.SecretKey, unit, inverse []*big.Int, R, k int, focus complex128, seed int64, targets []float64) (*rlwe.Ciphertext, []complex128, StatisticsFrontendResult, error) {
	f, err := NewStatisticsFrontend(top, skTop, unit, inverse, R, k, focus)
	if err != nil {
		return nil, nil, StatisticsFrontendResult{Error: err.Error()}, err
	}
	return f.Run(seed, targets)
}
