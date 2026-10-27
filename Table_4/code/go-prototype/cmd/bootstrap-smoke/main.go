package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/cmplx"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

type unitSpec struct {
	R          int      `json:"R"`
	Coeffs     []string `json:"polynomial_coefficients_ascending"`
	Inverse    []string `json:"inverse_coefficients_ascending"`
	Focus      string   `json:"focus_embedding_real"`
	Embeddings []string `json:"embeddings_real"`
}
type config struct {
	InitialReal, InitialImag                                                   float64
	LogN, Logn, R, QBits, EMBits, Degree, DA, Rounds, OutputBits, InputBits, K int
	MainPBits, MainBaseTwo                                                     int
	TopPBits, OutputPrimeBits, EntryBase, BoundaryBase, TargetBits, RatioBits  int
	EntryNoP, SmallChain, Continuous                                           bool
	Readout                                                                    string
	UnitFile                                                                   string
	SquareBetween                                                              bool
}
type stage struct {
	Name                                                                string `json:"name"`
	Round                                                               int    `json:"round"`
	Level                                                               int    `json:"level"`
	LogScale, LogQ, DataError, GuardMax, ImaginaryMax, DataMax, Seconds float64
	DataErrorBits                                                       float64
	HasReference                                                        bool
}
type roundResult struct {
	DataMeanErrorAbs, DataErrorEnergy, GuardEnergy, SquareOldObservableBound float64
	Index                                                                    int
	ExpectedReal, ExpectedImag                                               float64
	CarryReal, CarryImag                                                     int64
	Beta                                                                     float64
	FractionalOracleErrorReal, FractionalOracleErrorImag                     float64
	SelectedFractionReal, SelectedFractionImag                               float64
	RecoveredInputReal, RecoveredInputImag                                   float64
	InputEntryErrorReal, InputEntryErrorImag                                 float64
	PureApproxOracleErrorReal, PureApproxOracleErrorImag                     float64
	FHEEvalErrorReal, FHEEvalErrorImag                                       float64
	CarryCentersCovered, PolynomialDomainCovered, FractionalRadiusCovered    bool
	ApproximationInputCovered                                                bool
	LeafDataError, LeafGuardMax, ReturnedDataError, ReturnedGuardMax         float64
	RecoveredObservableError, NextReadBound                                  float64
	Data20, GuardHalf, NextRead20                                            bool
	DataTarget, ObservableTarget                                             bool
	NextReadClassBound                                                       float64
	OutputQBits, InputQBits, RestoredModulusBits                             float64
}
type applicationStep struct {
	ObservableDiagnosticsAvailable                                           bool
	RecoveredObservableError, FreshObservableError, ObservablePosteriorBound float64
	ObservablePosteriorBoundPass                                             bool
	AfterRound, InputLevel, OutputLevel                                      int
	ExpectedReal, ExpectedImag                                               float64
	InputLogScale, OutputLogScale                                            float64
	DataError, GuardMax, NextReadBound                                       float64
}
type result struct {
	Scope, Status, Error, Host, GOOS, GOARCH, Started                                         string
	Config                                                                                    config
	MainQBits, MainQPBits, IncomingQPBits, ReturnQPBits, UnitFocus, GuardInverseWeight, Alpha float64
	QPrimes, PPrimes                                                                          []uint64
	MainH, EphemeralH, TopH, EntryBaseTwo, ReturnBaseTwo, KeyGenerationCount                  int
	MainSecurityTableCap, EntrySecurityTableCap                                               int
	ReferenceTableFits                                                                        bool
	ApproximationMessageRatioBits, MaxInterpolatedCarry                                       int
	ApproximationFractionalRadius                                                             float64
	Stages                                                                                    []stage
	Rounds                                                                                    []roundResult
	ShapedStats                                                                               lb.ShapedStats
	ApplicationShapedStats                                                                    lb.ShapedStats
	ApplicationSteps                                                                          []applicationStep
	ApplicationKeyGenerationCount, ApplicationRelinKeyBytes, ApplicationBaseTwo               int
	ApplicationQPBits                                                                         float64
	MainEvaluationKeyBytes, IncomingKeyBytes, ReturnKeyBytes                                  int
	KeygenSeconds, TotalSeconds                                                               float64
}

func f64(s string) float64 {
	v, e := strconv.ParseFloat(s, 64)
	if e != nil {
		panic(e)
	}
	return v
}
func embed(c []string, n int) []*big.Int {
	a := make([]*big.Int, n)
	for i := range a {
		a[i] = new(big.Int)
	}
	for j, v := range c {
		x, ok := new(big.Int).SetString(v, 10)
		if !ok {
			panic("bad unit")
		}
		a[j*n/len(c)] = x
	}
	return a
}
func logProduct(xs []uint64) float64 {
	v := 0.0
	for _, x := range xs {
		v += math.Log2(float64(x))
	}
	return v
}
func scaleLog(s rlwe.Scale) float64 { v, _ := s.Value.Float64(); return math.Log2(v) }
func bitsError(e float64) float64 {
	if e == 0 {
		return 999
	}
	return -math.Log2(e)
}

func decode(p ckks.Parameters, sk *rlwe.SecretKey, c *rlwe.Ciphertext) ([]complex128, error) {
	pt := rlwe.NewDecryptor(p, sk).DecryptNew(c)
	v := make([]complex128, p.MaxSlots())
	err := ckks.NewEncoder(p, 128).Decode(pt, v)
	return v, err
}
func measure(res *result, p ckks.Parameters, sk *rlwe.SecretKey, c *rlwe.Ciphertext, name string, round, R int, expected complex128, reference bool, start time.Time) (stage, []complex128, error) {
	vals, err := decode(p, sk, c)
	if err != nil {
		return stage{}, nil, err
	}
	s := stage{Name: name, Round: round, Level: c.Level(), LogScale: scaleLog(c.Scale), LogQ: logProduct(p.Q()[:c.Level()+1]), HasReference: reference, Seconds: time.Since(start).Seconds()}
	for j, v := range vals {
		if math.IsNaN(real(v)) || math.IsNaN(imag(v)) || math.IsInf(cmplx.Abs(v), 0) {
			return s, vals, fmt.Errorf("nonfinite decoded stage %s", name)
		}
		if j%R == 0 {
			s.DataMax = math.Max(s.DataMax, cmplx.Abs(v))
			s.ImaginaryMax = math.Max(s.ImaginaryMax, math.Abs(imag(v)))
			if reference {
				s.DataError = math.Max(s.DataError, cmplx.Abs(v-expected))
			}
		} else {
			s.GuardMax = math.Max(s.GuardMax, cmplx.Abs(v))
		}
	}
	if reference {
		s.DataErrorBits = bitsError(s.DataError)
	}
	res.Stages = append(res.Stages, s)
	fmt.Printf("stage=%s round=%d level=%d logScale=%.3f dataMax=%.6g guard=%.6g errorBits=%.3f elapsed=%.2f\n", name, round, s.Level, s.LogScale, s.DataMax, s.GuardMax, s.DataErrorBits, s.Seconds)
	return s, vals, nil
}

func selectedLift(p ckks.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext) ([2]*big.Int, [2]int64, error) {
	var raw [2]*big.Int
	var carry [2]int64
	c, e := lb.CenteredCiphertextComponents(p, ct)
	if e != nil {
		return raw, carry, e
	}
	s, e := lb.CenteredCoefficients(p, sk.Value.Q, true, true)
	if e != nil {
		return raw, carry, e
	}
	pt := rlwe.NewDecryptor(p, sk).DecryptNew(ct)
	mu, e := lb.CenteredCoefficients(p, pt.Value, pt.IsNTT, pt.IsMontgomery)
	if e != nil {
		return raw, carry, e
	}
	q := new(big.Int).SetUint64(p.Q()[0])
	term := new(big.Int)
	for k, pos := range []int{0, p.N() / 2} {
		raw[k] = new(big.Int).Set(c[0][pos])
		for j, sj := range s {
			if sj.Sign() == 0 {
				continue
			}
			i := pos - j
			neg := i < 0
			if neg {
				i += p.N()
			}
			term.Mul(c[1][i], sj)
			if neg {
				raw[k].Sub(raw[k], term)
			} else {
				raw[k].Add(raw[k], term)
			}
		}
		delta := new(big.Int).Sub(raw[k], mu[pos])
		quot, rem := new(big.Int), new(big.Int)
		quot.QuoRem(delta, q, rem)
		if rem.Sign() != 0 || !quot.IsInt64() {
			return raw, carry, fmt.Errorf("nonintegral carry")
		}
		carry[k] = quot.Int64()
	}
	return raw, carry, nil
}

func run(c config, res *result) error {
	start := time.Now()
	defer func() { res.TotalSeconds = time.Since(start).Seconds() }()
	if c.LogN <= c.Logn || c.Logn < 5 || c.Rounds < 1 || c.DA < 1 || c.MainBaseTwo < 0 || c.MainBaseTwo > 63 {
		return fmt.Errorf("invalid dimensions/round count, or DA < 1 (deferred final rescale requires a double-angle step)")
	}
	if c.Readout != "inverse" && c.Readout != "identity" {
		return fmt.Errorf("readout must be inverse or identity")
	}
	data, err := os.ReadFile(c.UnitFile)
	if err != nil {
		return err
	}
	var units []unitSpec
	if err = json.Unmarshal(data, &units); err != nil {
		return err
	}
	var u unitSpec
	for _, x := range units {
		if x.R == c.R {
			u = x
		}
	}
	if u.R == 0 {
		return fmt.Errorf("unit R=%d absent", c.R)
	}
	gf := f64(u.Focus)
	res.UnitFocus = gf
	guards := make([]float64, c.R)
	for i, x := range u.Embeddings {
		guards[i] = f64(x)
		if i > 0 {
			res.GuardInverseWeight += math.Abs(gf / guards[i])
		}
	}
	topH := min(1024, 1<<c.LogN)
	mainH := min(1024, 1<<c.Logn)
	sparseH := min(32, 1<<c.Logn)
	res.TopH, res.MainH, res.EphemeralH = topH, mainH, sparseH
	boundaryBaseTwo := c.BoundaryBase
	res.EntryBaseTwo, res.ReturnBaseTwo = c.EntryBase, boundaryBaseTwo
	// q0 and qout are the only Q primes that must support both ring degrees.
	g0 := ring.NewNTTFriendlyPrimesGenerator(uint64(c.QBits), uint64(2<<c.LogN))
	q0, err := g0.NextDownstreamPrime()
	if err != nil {
		return err
	}
	gout := ring.NewNTTFriendlyPrimesGenerator(uint64(c.OutputPrimeBits), uint64(2<<c.LogN))
	qout, err := gout.NextDownstreamPrime()
	if err != nil {
		return err
	}
	var topP []uint64
	if c.TopPBits > 0 {
		pg := ring.NewNTTFriendlyPrimesGenerator(uint64(c.TopPBits), uint64(2<<c.LogN))
		pp, e := pg.NextUpstreamPrime()
		if e != nil {
			return e
		}
		topP = []uint64{pp}
	}
	top, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: []uint64{q0, qout}, P: topP, LogDefaultScale: c.InputBits, Xs: ring.Ternary{H: topH}})
	if err != nil {
		return err
	}
	entryTop := top
	entryP := top.P()
	if c.EntryNoP {
		entryP = nil
		entryTop, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: top.Q(), LogDefaultScale: c.InputBits, Xs: ring.Ternary{H: topH}})
		if err != nil {
			return err
		}
	}
	low, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: top.Q()[:1], P: entryP, LogDefaultScale: c.InputBits, Xs: ring.Ternary{H: sparseH}})
	if err != nil {
		return err
	}
	typ := mod1.CosDiscrete
	if c.Continuous {
		typ = mod1.CosContinuous
	}
	emLiteral := mod1.ParametersLiteral{LogScale: c.EMBits, Mod1Type: typ, LogMessageRatio: c.RatioBits, K: c.K, Mod1Degree: c.Degree, DoubleAngle: c.DA}
	res.ApproximationMessageRatioBits = c.RatioBits
	res.ApproximationFractionalRadius = math.Exp2(-float64(c.RatioBits))
	res.MaxInterpolatedCarry = c.K - 1
	if c.Continuous {
		res.MaxInterpolatedCarry = c.K
	}
	depth := emLiteral.Depth()
	var ps []uint64
	if c.MainPBits > 0 {
		pg := ring.NewNTTFriendlyPrimesGenerator(uint64(c.MainPBits), uint64(2<<c.Logn))
		pp, e := pg.NextUpstreamPrime()
		if e != nil {
			return e
		}
		ps = []uint64{pp}
	}
	qs := []uint64{q0, qout}
	used := map[uint64]bool{q0: true, qout: true}
	for _, p := range ps {
		used[p] = true
	}
	if c.SmallChain {
		for p := uint64(2<<c.Logn) + 1; len(qs) < depth+2; p += uint64(2 << c.Logn) {
			if !used[p] && ring.IsPrime(p) {
				qs = append(qs, p)
				used[p] = true
			}
		}
	} else {
		pg := ring.NewNTTFriendlyPrimesGenerator(uint64(c.EMBits), uint64(2<<c.Logn))
		for len(qs) < depth+2 {
			p, e := pg.NextUpstreamPrime()
			if e != nil {
				return e
			}
			if !used[p] {
				qs = append(qs, p)
				used[p] = true
			}
		}
	}
	main, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: qs, P: ps, LogDefaultScale: c.EMBits, Xs: ring.Ternary{H: mainH}})
	if err != nil {
		return err
	}
	res.QPrimes, res.PPrimes = qs, ps
	// Check the actual generated primes before any key generation. The fork's
	// rounded LogQi can otherwise underallocate digits at an exact base boundary.
	if err = lb.ValidateBaseTwoDecompositionCoverage(main, main.MaxLevelQ(), main.MaxLevelP(), c.MainBaseTwo); err != nil {
		return fmt.Errorf("main relin/Galois/branch keys: %w", err)
	}
	if err = lb.ValidateBaseTwoDecompositionCoverage(top, top.MaxLevelQ(), top.MaxLevelP(), boundaryBaseTwo); err != nil {
		return fmt.Errorf("entry/return/application keys: %w", err)
	}
	res.MainQBits = logProduct(main.Q())
	res.MainQPBits = res.MainQBits + logProduct(main.P())
	res.IncomingQPBits = math.Log2(float64(top.Q()[0])) + logProduct(low.P())
	res.ReturnQPBits = logProduct(top.Q()) + logProduct(top.P())
	if c.Logn == 14 {
		res.MainSecurityTableCap = 424
		res.EntrySecurityTableCap = 77
	}
	if c.Logn == 13 {
		res.MainSecurityTableCap = 211
		res.EntrySecurityTableCap = 37
	}
	res.ReferenceTableFits = res.MainQPBits <= float64(res.MainSecurityTableCap) && res.IncomingQPBits <= float64(res.EntrySecurityTableCap)
	emLiteral.LevelQ = main.MaxLevel()
	qdiff := float64(main.Q()[0]) / math.Exp2(math.Round(math.Log2(float64(main.Q()[0]))))
	emLiteral.Scaling = 1 / qdiff
	plan, err := mod1.NewParametersFromLiteral(main, emLiteral)
	if err != nil {
		return err
	}
	fmt.Printf("params N=%d n=%d R=%d q=%.5f mainQP=%.5f entryQP=%.5f tableFits=%t depth=%d polyDegree=%d\n", top.N(), main.N(), c.R, math.Log2(float64(top.Q()[0])), res.MainQPBits, res.IncomingQPBits, res.ReferenceTableFits, depth, plan.Mod1Poly.Degree())
	unitTop, inverseTop := embed(u.Coeffs, top.N()), embed(u.Inverse, top.N())
	unitLeaf, inverseLeaf := embed(u.Coeffs, main.N()), embed(u.Inverse, main.N())
	keyStart := time.Now()
	skTop := rlwe.NewKeyGenerator(top).GenSecretKeyWithHammingWeightNew(topH)
	skLow := rlwe.NewKeyGenerator(low).GenSecretKeyWithHammingWeightNew(sparseH)
	skMain := rlwe.NewKeyGenerator(main).GenSecretKeyWithHammingWeightNew(mainH)
	entry, err := lb.NewRingEntry(entryTop, low, skTop, skLow, 0, low.MaxLevelP(), c.EntryBase)
	if err != nil {
		return err
	}
	sparseHigh, err := lb.RebaseSecretKey(low, main, skLow)
	if err != nil {
		return err
	}
	kg := rlwe.NewKeyGenerator(main)
	mainKeyParams := rlwe.EvaluationKeyParameters{BaseTwoDecomposition: &c.MainBaseTwo}
	relin := kg.GenRelinearizationKeyNew(skMain, mainKeyParams)
	galEls := lb.FusedGaloisElements(main, c.R)
	galKeys := kg.GenGaloisKeysNew(galEls, skMain, mainKeyParams)
	evalKeys := rlwe.NewMemEvaluationKeySet(relin, galKeys...)
	base := ckks.NewEvaluator(main, evalKeys)
	shaped, err := lb.NewShapedEvaluator(main, base, unitLeaf, inverseLeaf, c.R, complex(gf, 0))
	if err != nil {
		return err
	}
	alpha := new(big.Float).SetPrec(192).SetFloat64(math.Exp2(float64(c.EMBits)) / (2 * float64(c.R) * gf * float64(top.Q()[0]) * float64(c.K)))
	res.Alpha, _ = alpha.Float64()
	fused, err := lb.NewFusedRecovery(main, c.R, alpha, rlwe.NewScale(math.Exp2(float64(c.EMBits))), unitLeaf, sparseHigh, skMain, evalKeys, 20261023, mainKeyParams)
	if err != nil {
		return err
	}
	retLeaf, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: top.Q(), P: top.P(), LogDefaultScale: c.OutputBits, Xs: ring.Ternary{H: mainH}})
	if err != nil {
		return err
	}
	retSecret, err := lb.RebaseSecretKey(main, retLeaf, skMain)
	if err != nil {
		return err
	}
	returnBaseTwo := boundaryBaseTwo
	retKey := rlwe.NewKeyGenerator(top).GenEvaluationKeyNew(retSecret, skTop, rlwe.EvaluationKeyParameters{BaseTwoDecomposition: &returnBaseTwo})
	retEval := rlwe.NewEvaluator(top, nil)
	res.KeyGenerationCount = 2 + 1 + len(galKeys) + c.R
	res.IncomingKeyBytes = entry.Key.BinarySize()
	res.ReturnKeyBytes = retKey.BinarySize()
	res.MainEvaluationKeyBytes = relin.BinarySize()
	for _, key := range galKeys {
		res.MainEvaluationKeyBytes += key.BinarySize()
	}
	for _, key := range fused.BranchKeys {
		res.MainEvaluationKeyBytes += key.BinarySize()
	}
	var application *lb.ShapedEvaluator
	if c.SquareBetween && c.Rounds > 1 {
		appBaseTwo := boundaryBaseTwo
		appRelin := rlwe.NewKeyGenerator(top).GenRelinearizationKeyNew(skTop, rlwe.EvaluationKeyParameters{BaseTwoDecomposition: &appBaseTwo})
		appBase := ckks.NewEvaluator(top, rlwe.NewMemEvaluationKeySet(appRelin))
		application, err = lb.NewShapedEvaluator(top, appBase, unitTop, inverseTop, c.R, complex(gf, 0))
		if err != nil {
			return err
		}
		res.ApplicationKeyGenerationCount = 1
		res.ApplicationRelinKeyBytes = appRelin.BinarySize()
		res.ApplicationBaseTwo = appBaseTwo
		res.ApplicationQPBits = logProduct(top.Q()) + logProduct(top.P())
		res.KeyGenerationCount++
	}
	res.KeygenSeconds = time.Since(keyStart).Seconds()
	fmt.Printf("keys=%d keygen_seconds=%.3f\n", res.KeyGenerationCount, res.KeygenSeconds)
	// Fresh input uses ordinary encoding/encryption first, followed by exact g.
	// It is a synthetic low-level PA input, not an application benchmark.
	z := complex(c.InitialReal, c.InitialImag)
	inputValues := make([]complex128, top.MaxSlots())
	for j := 0; j < len(inputValues); j += c.R {
		inputValues[j] = z / complex(gf, 0)
	}
	pt := ckks.NewPlaintext(top, 0)
	pt.Scale = rlwe.NewScale(math.Exp2(float64(c.InputBits)))
	if err = ckks.NewEncoder(top, 128).Encode(inputValues, pt); err != nil {
		return err
	}
	current, err := rlwe.NewEncryptor(top, skTop).EncryptNew(pt)
	if err != nil {
		return err
	}
	current, err = lb.MulIntegerPolynomial(top, current, unitTop)
	if err != nil {
		return err
	}
	if _, _, err = measure(res, top, skTop, current, "input", 0, c.R, z, true, start); err != nil {
		return err
	}
	topBase := ckks.NewEvaluator(top, nil)
	for index := 1; index <= c.Rounds; index++ {
		// Repeated-refresh diagnostic: discard the fresh output prime between
		// rounds only in the default mode. The optional application mode must
		// consume it in the actual square/relinearize/rescale below.
		if current.Level() > 0 {
			if c.SquareBetween {
				return fmt.Errorf("square-between left an unexpected level %d before refresh %d", current.Level(), index)
			}
			topBase.DropLevel(current, current.Level())
		}
		inScale, _ := current.Scale.Value.Float64()
		readFactor := gf
		if c.Readout == "identity" {
			readFactor = 1
		}
		beta := float64(top.Q()[0]) * float64(c.R) * readFactor / inScale
		ordinary := current.CopyNew()
		if c.Readout != "identity" {
			ordinary, err = lb.MulIntegerPolynomial(top, current, inverseTop)
		}
		if err != nil {
			return err
		}
		leaf, err := entry.Apply(ordinary)
		if err != nil {
			return err
		}
		raw, carries, err := selectedLift(low, skLow, leaf)
		if err != nil {
			return err
		}
		rr := roundResult{Index: index, ExpectedReal: real(z), ExpectedImag: imag(z), CarryReal: carries[0], CarryImag: carries[1], Beta: beta, InputQBits: math.Log2(float64(top.Q()[0]))}
		rr.CarryCentersCovered = carries[0] > -int64(c.K) && carries[0] < int64(c.K) && carries[1] > -int64(c.K) && carries[1] < int64(c.K)
		if c.Continuous {
			rr.CarryCentersCovered = math.Abs(float64(carries[0])-0.25) <= float64(c.K) && math.Abs(float64(carries[1])-0.25) <= float64(c.K)
		}
		// Measurement only: remove the measured integer carry exactly before
		// converting to float, avoiding raw/q - carry cancellation.
		var selectedFraction, recoveredInput [2]float64
		qInt := new(big.Int).SetUint64(top.Q()[0])
		for lane := range raw {
			remainder := new(big.Int).Sub(raw[lane], new(big.Int).Mul(big.NewInt(carries[lane]), qInt))
			frac := new(big.Float).SetPrec(192).SetInt(remainder)
			frac.Quo(frac, new(big.Float).SetPrec(192).SetInt(qInt))
			selectedFraction[lane], _ = frac.Float64()
			recoveredInput[lane] = beta * selectedFraction[lane]
		}
		rr.SelectedFractionReal, rr.SelectedFractionImag = selectedFraction[0], selectedFraction[1]
		rr.RecoveredInputReal, rr.RecoveredInputImag = recoveredInput[0], recoveredInput[1]
		rr.InputEntryErrorReal = math.Abs(recoveredInput[0] - real(z))
		rr.InputEntryErrorImag = math.Abs(recoveredInput[1] - imag(z))
		rr.FractionalRadiusCovered = math.Abs(selectedFraction[0]) <= res.ApproximationFractionalRadius && math.Abs(selectedFraction[1]) <= res.ApproximationFractionalRadius
		rr.PolynomialDomainCovered = math.Abs(float64(carries[0])+selectedFraction[0]-0.25) <= float64(c.K) && math.Abs(float64(carries[1])+selectedFraction[1]-0.25) <= float64(c.K)
		rr.ApproximationInputCovered = rr.CarryCentersCovered && rr.FractionalRadiusCovered && rr.PolynomialDomainCovered
		fmt.Printf("round=%d beta=%.8f carry=(%d,%d)\n", index, beta, carries[0], carries[1])
		fmt.Printf("range round=%d carry_centers=%t fraction_radius=%t max_fraction=%.8g allowed=%.8g\n", index, rr.CarryCentersCovered, rr.FractionalRadiusCovered, math.Max(math.Abs(selectedFraction[0]), math.Abs(selectedFraction[1])), res.ApproximationFractionalRadius)
		re, im, err := fused.Apply(low, leaf)
		if err != nil {
			return err
		}
		expected := make([]float64, 2)
		for k := range raw {
			x, _ := new(big.Float).SetInt(raw[k]).Float64()
			expected[k] = x / float64(top.Q()[0]) / float64(c.K)
		}
		for k, ct := range []*rlwe.Ciphertext{re, im} {
			if _, _, err = measure(res, main, skMain, ct, fmt.Sprintf("fused_%d", k), index, c.R, complex(expected[k], 0), true, start); err != nil {
				return err
			}
		}
		var final [2]*rlwe.Ciphertext
		for lane, ct := range []*rlwe.Ciphertext{re, im} {
			hook := func(name string, x *rlwe.Ciphertext) error {
				_, _, e := measure(res, main, skMain, x, fmt.Sprintf("em%d_%s", lane, name), index, c.R, 0, false, start)
				return e
			}
			out, err := lb.EvaluateShapedMod1(shaped, ct, plan, rlwe.NewScale(beta*math.Exp2(float64(c.OutputBits))), true, hook)
			if err != nil {
				return err
			}
			out.Scale = out.Scale.Div(rlwe.NewScale(beta))
			if err = shaped.Rescale(out, out); err != nil {
				return err
			}
			final[lane] = out
			want := real(z)
			if lane == 1 {
				want = imag(z)
			}
			oracle := lb.Mod1PlaintextOracle(plan, expected[lane]) * beta
			if lane == 0 {
				rr.FractionalOracleErrorReal = math.Abs(oracle - want)
				rr.PureApproxOracleErrorReal = math.Abs(oracle - recoveredInput[lane])
			} else {
				rr.FractionalOracleErrorImag = math.Abs(oracle - want)
				rr.PureApproxOracleErrorImag = math.Abs(oracle - recoveredInput[lane])
			}
			// Keep the legacy total oracle-vs-original field above, but separate
			// prior/input error, plaintext approximation, and encrypted arithmetic.
			_, laneValues, err := measure(res, main, skMain, out, fmt.Sprintf("output_%d", lane), index, c.R, complex(want, 0), true, start)
			if err != nil {
				return err
			}
			fheError := 0.0
			for j := 0; j < len(laneValues); j += c.R {
				fheError = math.Max(fheError, cmplx.Abs(laneValues[j]-complex(oracle, 0)))
			}
			if lane == 0 {
				rr.FHEEvalErrorReal = fheError
			} else {
				rr.FHEEvalErrorImag = fheError
			}
		}
		plusI := make([]*big.Int, main.N())
		for i := range plusI {
			plusI[i] = new(big.Int)
		}
		plusI[main.N()/2].SetInt64(1)
		imagCT, err := lb.MulIntegerPolynomial(main, final[1], plusI)
		if err != nil {
			return err
		}
		combined, err := base.AddNew(final[0], imagCT)
		if err != nil {
			return err
		}
		st, _, err := measure(res, main, skMain, combined, "leaf_output", index, c.R, z, true, start)
		if err != nil {
			return err
		}
		rr.LeafDataError = st.DataError
		rr.LeafGuardMax = st.GuardMax
		invReturn, err := lb.MulIntegerPolynomial(main, combined, inverseLeaf)
		if err != nil {
			return err
		}
		returned := ckks.NewCiphertext(top, 1, combined.Level())
		if err = retEval.ApplyEvaluationKey(invReturn, retKey, returned); err != nil {
			return err
		}
		returned.LogDimensions.Cols = top.LogMaxSlots()
		returned, err = lb.MulIntegerPolynomial(top, returned, unitTop)
		if err != nil {
			return err
		}
		st, vals, err := measure(res, top, skTop, returned, "returned_output", index, c.R, z, true, start)
		if err != nil {
			return err
		}
		rr.ReturnedDataError = st.DataError
		rr.ReturnedGuardMax = st.GuardMax
		rr.OutputQBits = st.LogQ
		rr.RestoredModulusBits = st.LogQ - rr.InputQBits
		observed := complex(0, 0)
		for j, v := range vals {
			weight := gf / guards[j%c.R]
			if c.Readout == "identity" {
				weight = 1
			}
			observed += complex(weight, 0) * v
		}
		observed *= complex(float64(c.R)/float64(len(vals)), 0)
		rr.RecoveredObservableError = cmplx.Abs(observed - z)
		hg := res.GuardInverseWeight
		if c.Readout == "identity" {
			hg = float64(c.R - 1)
		}
		rr.NextReadBound = st.DataError + hg*st.GuardMax
		classMax := make([]float64, c.R)
		for j, v := range vals {
			if j%c.R != 0 {
				classMax[j%c.R] = math.Max(classMax[j%c.R], cmplx.Abs(v))
			}
		}
		rr.NextReadClassBound = st.DataError
		dataMean := complex(0, 0)
		exactSquareObservable := complex(0, 0)
		normWeight := float64(c.R) / float64(len(vals))
		for j, v := range vals {
			if j%c.R == 0 {
				d := v - z
				dataMean += complex(normWeight, 0) * d
				rr.DataErrorEnergy += normWeight * cmplx.Abs(d) * cmplx.Abs(d)
			} else {
				rr.GuardEnergy += normWeight * cmplx.Abs(v) * cmplx.Abs(v)
			}
			exactSquareObservable += complex(normWeight, 0) * v * v
		}
		rr.DataMeanErrorAbs = cmplx.Abs(dataMean)
		rr.SquareOldObservableBound = 2*cmplx.Abs(z)*rr.DataMeanErrorAbs + rr.DataErrorEnergy + rr.GuardEnergy
		for j := 1; j < c.R; j++ {
			w := math.Abs(gf / guards[j])
			if c.Readout == "identity" {
				w = 1
			}
			rr.NextReadClassBound += w * classMax[j]
		}
		rr.DataTarget = st.DataError <= math.Exp2(-float64(c.TargetBits))
		rr.ObservableTarget = rr.RecoveredObservableError <= math.Exp2(-float64(c.TargetBits))
		rr.Data20 = st.DataError <= math.Exp2(-20)
		rr.GuardHalf = st.GuardMax <= 0.5
		rr.NextRead20 = rr.NextReadBound <= math.Exp2(-20)
		res.Rounds = append(res.Rounds, rr)
		current = returned
		if c.SquareBetween && index < c.Rounds {
			if application == nil || current.Level() != 1 {
				return fmt.Errorf("square-between requires one fresh output prime, got level %d", current.Level())
			}
			app := applicationStep{AfterRound: index, InputLevel: current.Level(), InputLogScale: scaleLog(current.Scale)}
			nextExpected := z * z
			squared, e := application.MulRelinNew(current, current)
			if e != nil {
				return fmt.Errorf("application square/relinearize: %w", e)
			}
			if e = application.Rescale(squared, squared); e != nil {
				return fmt.Errorf("application rescale: %w", e)
			}
			// Preserve the actual scale S^2/qout. The next beta is calculated
			// from this metadata; it is never forced back to 2^OutputBits.
			st, appVals, e := measure(res, top, skTop, squared, "application_square", index, c.R, nextExpected, true, start)
			if e != nil {
				return e
			}
			app.ExpectedReal, app.ExpectedImag = real(nextExpected), imag(nextExpected)
			app.OutputLevel, app.OutputLogScale = squared.Level(), st.LogScale
			app.DataError, app.GuardMax = st.DataError, st.GuardMax
			app.NextReadBound = st.DataError + hg*st.GuardMax
			if c.Readout == "identity" {
				app.ObservableDiagnosticsAvailable = true
				appObservable := complex(0, 0)
				for _, v := range appVals {
					appObservable += complex(normWeight, 0) * v
				}
				app.RecoveredObservableError = cmplx.Abs(appObservable - nextExpected)
				app.FreshObservableError = cmplx.Abs(appObservable - exactSquareObservable)
				app.ObservablePosteriorBound = rr.SquareOldObservableBound + app.FreshObservableError
				app.ObservablePosteriorBoundPass = app.ObservablePosteriorBound <= math.Exp2(-float64(c.TargetBits))
			}
			res.ApplicationSteps = append(res.ApplicationSteps, app)
			current, z = squared, nextExpected
		}
	}
	res.ShapedStats = shaped.Stats
	if application != nil {
		res.ApplicationShapedStats = application.Stats
	}
	return nil
}

func main() {
	var c config
	var out string
	flag.IntVar(&c.LogN, "logN", 15, "")
	flag.IntVar(&c.Logn, "logn", 14, "")
	flag.IntVar(&c.R, "R", 4, "")
	flag.IntVar(&c.QBits, "qbits", 50, "entry q bits; defaults to 52 for R=8 if omitted")
	flag.IntVar(&c.EMBits, "embits", 32, "")
	flag.IntVar(&c.MainPBits, "main-pbits", 53, "main-leaf auxiliary-prime bits")
	flag.IntVar(&c.MainBaseTwo, "main-basetwo", 0, "main-leaf gadget base-two bits; zero preserves default RNS decomposition")
	flag.IntVar(&c.Degree, "degree", 47, "")
	flag.IntVar(&c.DA, "da", 3, "")
	flag.IntVar(&c.Rounds, "rounds", 1, "")
	flag.IntVar(&c.K, "K", 16, "")
	flag.IntVar(&c.InputBits, "inputbits", 20, "")
	flag.IntVar(&c.OutputBits, "outputbits", 20, "")
	flag.BoolVar(&c.SquareBetween, "square-between", false, "perform a real top-ring shaped square, relinearization and rescale between refreshes")
	flag.StringVar(&c.UnitFile, "units", "units.json", "")
	flag.StringVar(&out, "out", "smoke.json", "")
	flag.IntVar(&c.TopPBits, "top-pbits", 24, "top return/application P; zero means no P")
	flag.IntVar(&c.OutputPrimeBits, "output-prime-bits", 20, "output application prime size")
	flag.IntVar(&c.EntryBase, "entry-base", 14, "entry-only bit decomposition")
	flag.IntVar(&c.BoundaryBase, "boundary-base", 14, "return/application bit decomposition")
	flag.IntVar(&c.TargetBits, "target-bits", 20, "reported absolute precision target")
	flag.IntVar(&c.RatioBits, "ratio-bits", 13, "EvalMod fractional-domain bits")
	flag.BoolVar(&c.EntryNoP, "entry-no-p", false, "entry key only uses Q; separate evaluator parameters")
	flag.BoolVar(&c.SmallChain, "small-chain", false, "explicit smallest distinct leaf NTT EM primes")
	flag.BoolVar(&c.Continuous, "continuous", false, "continuous cosine approximation")
	flag.StringVar(&c.Readout, "readout", "inverse", "inverse or identity integer readout")
	flag.Float64Var(&c.InitialReal, "real", 0.375, "initial synthetic message real part")
	flag.Float64Var(&c.InitialImag, "imag", -0.25, "initial synthetic message imaginary part")
	flag.Parse()
	qBitsExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "qbits" {
			qBitsExplicit = true
		}
	})
	if c.R == 8 && !qBitsExplicit {
		c.QBits = 52
	}
	host, _ := os.Hostname()
	res := result{Scope: "Experimental full ciphertext path: integer readout, actual ring KS+Split0, fused lift/trace, shaped EvalMod, focused return. Synthetic input and repeated-refresh diagnostic; no application timing or security certification.", Status: "running", Config: c, Host: host, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Started: time.Now().UTC().Format(time.RFC3339)}
	if c.SquareBetween {
		res.Scope = "Experimental full ciphertext path with actual top-ring shaped square/relinearize/rescale between refreshes. Synthetic single-message input; no application benchmark or security certification."
	}
	err := run(c, &res)
	if err != nil {
		res.Status = "execution_failed"
		res.Error = err.Error()
	} else {
		res.Status = "executed"
	}
	if e := os.MkdirAll(filepath.Dir(out), 0755); e != nil {
		panic(e)
	}
	b, e := json.MarshalIndent(res, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(out, append(b, '\n'), 0644); e != nil {
		panic(e)
	}
	fmt.Printf("status=%s results=%s\n", res.Status, out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
