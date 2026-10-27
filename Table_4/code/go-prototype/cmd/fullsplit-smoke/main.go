package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
	"math"
	"math/big"
	"math/cmplx"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type unitSpec struct {
	R       int      `json:"R"`
	Coeffs  []string `json:"polynomial_coefficients_ascending"`
	Inverse []string `json:"inverse_coefficients_ascending"`
	Focus   string   `json:"focus_embedding_real"`
}
type config struct {
	PruneOnly                                                                                  bool
	AllowSubunitCoefficientScale                                                               bool
	FusedPower                                                                                 int
	Mod1Family                                                                                 string
	Degree, DoubleAngle, RepeatRounds                                                          int
	SmallP                                                                                     uint64
	CompareEntry                                                                               bool
	Messages                                                                                   int
	ComparePrune                                                                               bool
	Powers                                                                                     string
	StageDiagnostics                                                                           bool
	Workers                                                                                    int
	VerifySerial                                                                               bool
	LogN, Logn, R, Trials, TargetBits, ScaleBits, EMBits, K, MainBase, EntryBase, BoundaryBase int
	Q0, Qout, TopP, MainP                                                                      uint64
	UnitFile                                                                                   string
	Seed                                                                                       int64
	CheckSquare                                                                                bool
}
type metric struct{ DataError, DataErrorBits, GuardMax, DataMax, ObservableError float64 }
type branchResult struct {
	ReadoutSeconds, EvalModSeconds                                         float64
	Arithmetic                                                             lb.ShapedStats
	Skipped                                                                bool
	CircuitErrorMeanReal, CircuitErrorMeanImag                             float64
	EntryErrorReal, EntryErrorImag, IdealMod1ErrorReal, IdealMod1ErrorImag float64
	CircuitVsEntryOracleMax, ReturnPointwiseMax                            float64
	Stages                                                                 []stageMetric
	Index                                                                  int
	MessageReal, MessageImag                                               float64
	EntryObservableError                                                   float64
	CarryReal, CarryImag                                                   int64
	DomainCovered                                                          bool
	MainOutput                                                             metric
	RecoveredAfterMerge                                                    metric
	BootstrapSeconds                                                       float64
}
type trialResult struct {
	ParallelOnlineSeconds                                                                                                 float64
	TimingOrder                                                                                                           string
	Repeats                                                                                                               []repeatResult
	EntryP                                                                                                                uint64
	EntryKeyBytes                                                                                                         int
	Pruned                                                                                                                bool
	UsefulMessages                                                                                                        int
	UnitPower                                                                                                             int
	Error                                                                                                                 string
	UnitFocus, WorkerSetupSeconds                                                                                         float64
	SumBranchSeconds, SerialOnlineSeconds, SerialLeafSeconds, Speedup                                                     float64
	SerialChecked, SerialCiphertextsEqual                                                                                 bool
	Index, BranchCount, RefreshedBranches, OutputLevel, ApplicationOutputLevel                                            int
	Input, Output, Application                                                                                            metric
	OutputLogScale, OutputLogQ, RestoredBits                                                                              float64
	EntrySplitSeconds, AllLeafBootstrapSeconds, MergeReturnSeconds, OnlineSeconds, ApplicationSeconds, DiagnosticsSeconds float64
	Branches                                                                                                              []branchResult
}
type result struct {
	CasesExecuted, CasesFailed, CasesMeetingTarget                   int
	OrdinaryEntryKeyBytes, SmallPEntryCachedKeyBytes                 int
	Workers, GOMAXPROCS                                              int
	WorkerSetupSeconds                                               float64
	Scope, Status, Error, Host, GOOS, GOARCH, Started                string
	Config                                                           config
	BranchCount, TopH, EphemeralH, MainH, MainKeyCount               int
	QPrimes, PPrimes                                                 []uint64
	MainQBits, MainQPBits, EntryQPBits, ReturnQPBits, Beta           float64
	MainReferenceCap, EntryReferenceCap                              int
	ReferenceTableFits                                               bool
	KeygenSeconds, TotalSeconds                                      float64
	MainKeyBytes, EntryKeyBytes, ReturnKeyBytes, ApplicationKeyBytes int
	Trials                                                           []trialResult
}

func stats(v, w []complex128, R int, z *complex128) metric {
	m := metric{}
	obs := complex(0, 0)
	for j, x := range v {
		if j%R == 0 {
			m.DataError = math.Max(m.DataError, cmplx.Abs(x-w[j]))
			m.DataMax = math.Max(m.DataMax, cmplx.Abs(x))
		} else {
			m.GuardMax = math.Max(m.GuardMax, cmplx.Abs(x))
		}
		obs += x
	}
	m.DataErrorBits = bitsError(m.DataError)
	if z != nil {
		m.ObservableError = cmplx.Abs(obs*complex(float64(R)/float64(len(v)), 0) - *z)
	}
	return m
}
func leafExpected(n, R int, z complex128) []complex128 {
	v := make([]complex128, n)
	for j := 0; j < n; j += R {
		v[j] = z
	}
	return v
}
func plainView(p ckks.Parameters, ct *rlwe.Ciphertext) ([]complex128, error) {
	pt := ckks.NewPlaintext(p, ct.Level())
	pt.MetaData = ct.MetaData.CopyNew()
	pt.Value = ct.Value[0]
	v := make([]complex128, p.MaxSlots())
	err := ckks.NewEncoder(p, 128).Decode(pt, v)
	return v, err
}

func run(c config, res *result) error {
	start := time.Now()
	defer func() { res.TotalSeconds = time.Since(start).Seconds() }()
	if c.LogN <= c.Logn || c.Trials < 1 || c.R != 8 || c.Workers < 1 {
		return fmt.Errorf("requires LogN>Logn, Trials>=1, R8, Workers>=1")
	}
	raw, err := os.ReadFile(c.UnitFile)
	if err != nil {
		return err
	}
	var units []unitSpec
	if err = json.Unmarshal(raw, &units); err != nil {
		return err
	}
	var u unitSpec
	for _, a := range units {
		if a.R == c.R {
			u = a
		}
	}
	if u.R == 0 {
		return fmt.Errorf("missing unit")
	}
	powers, err := parsePowers(c.Powers)
	if err != nil {
		return err
	}
	inputUnit := u
	gf := f64(u.Focus)
	topH, mainH, sparseH := min(1024, 1<<c.LogN), min(1024, 1<<c.Logn), min(32, 1<<c.Logn)
	res.TopH, res.MainH, res.EphemeralH = topH, mainH, sparseH
	if c.Q0 == c.Qout || c.TopP == c.Q0 || c.TopP == c.Qout {
		return fmt.Errorf("duplicate top primes")
	}
	for _, q := range []uint64{c.Q0, c.Qout, c.TopP} {
		if !ring.IsPrime(q) || (q-1)%uint64(2<<c.LogN) != 0 {
			return fmt.Errorf("top prime %d incompatible with LogN%d", q, c.LogN)
		}
	}
	top, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: []uint64{c.Q0, c.Qout}, P: []uint64{c.TopP}, LogDefaultScale: c.ScaleBits, Xs: ring.Ternary{H: topH}})
	if err != nil {
		return err
	}
	entryTop, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: top.Q(), LogDefaultScale: c.ScaleBits, Xs: ring.Ternary{H: topH}})
	if err != nil {
		return err
	}
	low, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: top.Q()[:1], LogDefaultScale: c.ScaleBits, Xs: ring.Ternary{H: sparseH}})
	if err != nil {
		return err
	}
	family := mod1.CosContinuous
	if c.Mod1Family == "discrete" {
		family = mod1.CosDiscrete
	} else if c.Mod1Family != "continuous" {
		return fmt.Errorf("unknown Mod1 family")
	}
	lit := mod1.ParametersLiteral{LogScale: c.EMBits, Mod1Type: family, LogMessageRatio: 4, K: c.K, Mod1Degree: c.Degree, DoubleAngle: c.DoubleAngle}
	qs := []uint64{c.Q0, c.Qout}
	used := map[uint64]bool{c.Q0: true, c.Qout: true, c.MainP: true}
	// Small-ring tests reuse the N13 prime schedule (still NTT-compatible).
	step := uint64(2 << max(c.Logn, 13))
	for q := step + 1; len(qs) < lit.Depth()+2; q += step {
		if !used[q] && ring.IsPrime(q) {
			qs = append(qs, q)
			used[q] = true
		}
	}
	main, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: qs, P: []uint64{c.MainP}, LogDefaultScale: c.EMBits, Xs: ring.Ternary{H: mainH}})
	if err != nil {
		return err
	}
	if err = lb.ValidateBaseTwoDecompositionCoverage(main, main.MaxLevel(), main.MaxLevelP(), c.MainBase); err != nil {
		return err
	}
	if err = lb.ValidateBaseTwoDecompositionCoverage(top, top.MaxLevel(), top.MaxLevelP(), c.BoundaryBase); err != nil {
		return err
	}
	res.QPrimes, res.PPrimes = main.Q(), main.P()
	res.MainQBits = logProduct(main.Q())
	res.MainQPBits = res.MainQBits + logProduct(main.P())
	res.EntryQPBits = math.Log2(float64(c.Q0))
	res.ReturnQPBits = logProduct(top.Q()) + logProduct(top.P())
	res.Beta = float64(c.Q0) * float64(c.R) / math.Exp2(float64(c.ScaleBits))
	res.BranchCount = top.N() / main.N()
	if c.Messages == 0 {
		c.Messages = res.BranchCount
	}
	if c.Messages < 1 || c.Messages > res.BranchCount {
		return fmt.Errorf("invalid message count")
	}
	res.Workers, res.GOMAXPROCS = min(c.Workers, res.BranchCount), runtime.GOMAXPROCS(0)
	if res.Workers > res.GOMAXPROCS {
		return fmt.Errorf("workers exceed GOMAXPROCS")
	}
	if c.Logn == 13 {
		res.MainReferenceCap, res.EntryReferenceCap = 211, 37
		res.ReferenceTableFits = res.MainQPBits <= 211 && res.EntryQPBits <= 37
	}
	lit.LevelQ = main.MaxLevel()
	lit.Scaling = math.Exp2(math.Round(math.Log2(float64(c.Q0)))) / float64(c.Q0)
	inputUT := embed(inputUnit.Coeffs, top.N())
	ut, it := embed(u.Coeffs, top.N()), embed(u.Inverse, top.N())
	ul, il := embed(u.Coeffs, main.N()), embed(u.Inverse, main.N())
	fmt.Printf("N=%d n=%d full_branches=%d mainQP=%.8f entryQP=%.8f beta=%.8f target=%dbit\n", top.N(), main.N(), res.BranchCount, res.MainQPBits, res.EntryQPBits, res.Beta, c.TargetBits)
	keyStart := time.Now()
	st := rlwe.NewKeyGenerator(top).GenSecretKeyWithHammingWeightNew(topH)
	sl := rlwe.NewKeyGenerator(low).GenSecretKeyWithHammingWeightNew(sparseH)
	sm := rlwe.NewKeyGenerator(main).GenSecretKeyWithHammingWeightNew(mainH)
	ordinaryEntry, err := lb.NewRingEntry(entryTop, low, st, sl, 0, -1, c.EntryBase)
	if err != nil {
		return err
	}
	var entry interface {
		ApplyAll(*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error)
	} = ordinaryEntry
	var smallEntry *lb.SmallPEntry
	res.OrdinaryEntryKeyBytes = ordinaryEntry.Key.BinarySize()
	if c.SmallP != 0 {
		smallEntry, err = lb.NewSmallPEntry(entryTop, low, st, sl, c.SmallP, c.Qout)
		if err != nil {
			return err
		}
		res.SmallPEntryCachedKeyBytes = smallEntry.CachedKeyBytes()
		res.EntryQPBits += math.Log2(float64(c.SmallP))
		res.ReferenceTableFits = res.MainQPBits <= float64(res.MainReferenceCap) && res.EntryQPBits <= float64(res.EntryReferenceCap)
		entry = smallEntry
	}
	sparseHigh, err := lb.RebaseSecretKey(low, main, sl)
	if err != nil {
		return err
	}
	kg := rlwe.NewKeyGenerator(main)
	kp := rlwe.EvaluationKeyParameters{BaseTwoDecomposition: &c.MainBase}
	relin := kg.GenRelinearizationKeyNew(sm, kp)
	gals := kg.GenGaloisKeysNew(lb.FusedGaloisElements(main, c.R), sm, kp)
	keys := rlwe.NewMemEvaluationKeySet(relin, gals...)
	base := ckks.NewEvaluator(main, keys)
	alpha := new(big.Float).SetPrec(192).SetFloat64(math.Exp2(float64(c.EMBits)) / (2 * float64(c.R) * gf * float64(c.Q0) * float64(c.K)))
	fused, err := lb.NewFusedRecovery(main, c.R, alpha, rlwe.NewScale(math.Exp2(float64(c.EMBits))), ul, sparseHigh, sm, keys, c.Seed, kp)
	if err != nil {
		return err
	}
	retLeaf, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: top.Q(), P: top.P(), LogDefaultScale: c.ScaleBits, Xs: ring.Ternary{H: mainH}})
	if err != nil {
		return err
	}
	sr, err := lb.RebaseSecretKey(main, retLeaf, sm)
	if err != nil {
		return err
	}
	retKey := rlwe.NewKeyGenerator(top).GenEvaluationKeyNew(sr, st, rlwe.EvaluationKeyParameters{BaseTwoDecomposition: &c.BoundaryBase})
	retEval := rlwe.NewEvaluator(top, nil)
	res.MainKeyCount = 1 + len(gals) + len(fused.BranchKeys)
	res.MainKeyBytes = relin.BinarySize()
	for _, k := range gals {
		res.MainKeyBytes += k.BinarySize()
	}
	for _, k := range fused.BranchKeys {
		res.MainKeyBytes += k.BinarySize()
	}
	res.EntryKeyBytes, res.ReturnKeyBytes = max(res.OrdinaryEntryKeyBytes, res.SmallPEntryCachedKeyBytes), retKey.BinarySize()
	var app *lb.ShapedEvaluator
	var appBase *ckks.Evaluator
	if c.CheckSquare {
		rk := rlwe.NewKeyGenerator(top).GenRelinearizationKeyNew(st, rlwe.EvaluationKeyParameters{BaseTwoDecomposition: &c.BoundaryBase})
		res.ApplicationKeyBytes = rk.BinarySize()
		appBase = ckks.NewEvaluator(top, rlwe.NewMemEvaluationKeySet(rk))
		app, err = lb.NewShapedEvaluator(top, appBase, ut, it, c.R, complex(gf, 0))
		if err != nil {
			return err
		}
	}
	res.KeygenSeconds = time.Since(keyStart).Seconds()
	fmt.Printf("keygen_seconds=%.4f main_key_bytes=%d\n", res.KeygenSeconds, res.MainKeyBytes)
	plusI := make([]*big.Int, main.N())
	for i := range plusI {
		plusI[i] = new(big.Int)
	}
	plusI[main.N()/2].SetInt64(1)
	var engines []*leafEngine
	configureUnit := func(power int) (float64, error) {
		setup := time.Now()
		current, e := unitPower(inputUnit, power)
		if e != nil {
			return 0, e
		}
		gf = f64(current.Focus)
		ut, it = embed(current.Coeffs, top.N()), embed(current.Inverse, top.N())
		ul, il = embed(current.Coeffs, main.N()), embed(current.Inverse, main.N())
		alpha = new(big.Float).SetPrec(192).SetFloat64(math.Exp2(float64(c.EMBits)) / (2 * float64(c.R) * gf * float64(c.Q0) * float64(c.K)))
		fusedUnit, fusedAlpha := ul, alpha
		if c.FusedPower >= 0 {
			fu, e := unitPower(inputUnit, c.FusedPower)
			if e != nil {
				return 0, e
			}
			fusedUnit = embed(fu.Coeffs, main.N())
			fusedAlpha = new(big.Float).SetPrec(192).SetFloat64(math.Exp2(float64(c.EMBits)) / (2 * float64(c.R) * f64(fu.Focus) * float64(c.Q0) * float64(c.K)))
		}
		engines = make([]*leafEngine, res.BranchCount)
		for b := range engines {
			shaped, e := lb.NewShapedEvaluator(main, base.ShallowCopy(), ul, il, c.R, complex(gf, 0))
			if e != nil {
				return 0, e
			}
			shaped.AllowSubunitCoefficientScale = c.AllowSubunitCoefficientScale
			plan, e := mod1.NewParametersFromLiteral(main, lit)
			if e != nil {
				return 0, e
			}
			engines[b] = &leafEngine{low: low, main: main, shaped: shaped,
				fused: fused.ShallowCopy(c.Seed + int64(b)), plan: plan,
				plusI: plusI, beta: res.Beta, scaleBits: c.ScaleBits, laneShapes: [2]*lb.ShapedEvaluator{lb.ForkShapedEvaluator(shaped), lb.ForkShapedEvaluator(shaped)}}
			engines[b].fused.Unit = fusedUnit
			engines[b].fused.Alpha = new(big.Float).SetPrec(192).Set(fusedAlpha)
		}
		if c.CheckSquare {
			app, e = lb.NewShapedEvaluator(top, appBase, ut, it, c.R, complex(gf, 0))
			if e != nil {
				return 0, e
			}
		}
		return time.Since(setup).Seconds(), nil
	}
	// This closure captures only public parameters, evaluation keys and scratch
	// buffers. No secret key or diagnostic is used by the online computation.
	activeMessages := c.Messages
	onlineRun := func(ct *rlwe.Ciphertext, workers, trial int, prune bool) (*onlineResult, error) {
		for b, engine := range engines {
			engine.fused.SetRoundingSeed(c.Seed + int64(trial)*1000003 + int64(b))
			engine.laneWorkers = workers
		}
		r := &onlineResult{}
		online := time.Now()
		stage := time.Now()
		var e error
		if r.leaves, e = entry.ApplyAll(ct); e != nil {
			return nil, e
		}
		r.entrySeconds = time.Since(stage).Seconds()
		stage = time.Now()
		if r.refreshed, r.durations, e = refreshKnownSupport(r.leaves, engines, workers, activeMessages, prune); e != nil {
			return nil, e
		}
		r.leafSeconds = time.Since(stage).Seconds()
		r.readoutTimes = make([]float64, len(engines))
		r.evalModTimes = make([]float64, len(engines))
		for b, engine := range engines {
			r.readoutTimes[b] = engine.readoutSeconds
			r.evalModTimes[b] = engine.evalModSeconds
		}
		stage = time.Now()
		ordinary := make([]*rlwe.Ciphertext, len(r.refreshed))
		for b, leaf := range r.refreshed {
			if ordinary[b], e = lb.MulIntegerPolynomial(main, leaf, il); e != nil {
				return nil, e
			}
		}
		merged, e := lb.MergeCoefficientBranches(top, retLeaf, ordinary)
		if e != nil {
			return nil, e
		}
		r.returned = ckks.NewCiphertext(top, 1, merged.Level())
		if e = retEval.ApplyEvaluationKey(merged, retKey, r.returned); e != nil {
			return nil, e
		}
		if r.returned, e = lb.MulIntegerPolynomial(top, r.returned, ut); e != nil {
			return nil, e
		}
		r.returned.LogDimensions.Cols = top.LogMaxSlots()
		r.mergeSeconds = time.Since(stage).Seconds()
		r.onlineSeconds = time.Since(online).Seconds()
		return r, nil
	}
	// Decode a public monomial once to obtain the encoder's exact slot order.
	mono := ckks.NewCiphertext(top, 0, 0)
	mono.Value[0].Coeffs[0][1] = 1
	top.RingQ().AtLevel(0).NTT(mono.Value[0], mono.Value[0])
	mono.Scale = rlwe.NewScale(1)
	roots, err := plainView(top, mono)
	if err != nil {
		return err
	}
	for trial := 0; trial < c.Trials; trial++ {
		trInput := metric{}
		rng := rand.New(rand.NewSource(c.Seed + int64(trial)))
		zs := make([]complex128, res.BranchCount)
		inputBranches := make([]*rlwe.Ciphertext, res.BranchCount)
		for b := range zs {
			zs[b] = complex(.7*(rng.Float64()-.5), .7*(rng.Float64()-.5))
			if b >= c.Messages {
				zs[b] = 0
			}
			if b == 0 {
				zs[b] = complex(.375, -.25)
			}
			pt := ckks.NewPlaintext(low, 0)
			pt.Scale = rlwe.NewScale(math.Exp2(float64(c.ScaleBits)))
			if err = ckks.NewEncoder(low, 128).Encode(leafExpected(low.MaxSlots(), c.R, zs[b]/complex(f64(inputUnit.Focus), 0)), pt); err != nil {
				return err
			}
			inputBranches[b] = ckks.NewCiphertext(low, 0, 0)
			inputBranches[b].Value[0] = pt.Value
			inputBranches[b].MetaData = pt.MetaData.CopyNew()
		}
		packed, err := lb.MergeCoefficientBranches(top, low, inputBranches)
		if err != nil {
			return err
		}
		pt := ckks.NewPlaintext(top, 0)
		pt.Value = packed.Value[0]
		pt.MetaData = packed.MetaData.CopyNew()
		ct, err := rlwe.NewEncryptor(top, st).EncryptNew(pt)
		if err != nil {
			return err
		}
		ct, err = lb.MulIntegerPolynomial(top, ct, inputUT)
		if err != nil {
			return err
		}
		want := make([]complex128, top.MaxSlots())
		for j := 0; j < len(want); j += c.R {
			pow := complex(1, 0)
			for b := range zs {
				want[j] += pow * zs[b]
				pow *= roots[j]
			}
		}
		iv, err := decode(top, st, ct)
		if err != nil {
			return err
		}
		trInput = stats(iv, want, c.R, nil)
		if trInput.DataError > 1e-3 {
			return fmt.Errorf("input packing mismatch: max error %g", trInput.DataError)
		}
		entryCases := []uint64{c.SmallP}
		if c.CompareEntry && c.SmallP != 0 {
			entryCases = []uint64{0, c.SmallP}
		}
		for _, entryP := range entryCases {
			entry = ordinaryEntry
			entryBytes := res.OrdinaryEntryKeyBytes
			if entryP != 0 {
				entry = smallEntry
				entryBytes = res.SmallPEntryCachedKeyBytes
			}
			for _, power := range powers {
				modes := []bool{false}
				if c.PruneOnly {
					modes = []bool{true}
				}
				if c.ComparePrune && !c.PruneOnly {
					modes = append(modes, true)
				}
				for _, prune := range modes {
					tr := trialResult{EntryP: entryP, EntryKeyBytes: entryBytes, Index: trial + 1, BranchCount: res.BranchCount, ApplicationOutputLevel: -1, Input: trInput, UnitPower: power, Pruned: prune, UsefulMessages: c.Messages}
					setupSeconds, e := configureUnit(power)
					if e != nil {
						return e
					}
					tr.WorkerSetupSeconds, tr.UnitFocus = setupSeconds, gf
					// Timed online section: no secret-key access, decryption, or oracle checks.
					var measured, serial *onlineResult
					var err error
					savedProcs := runtime.GOMAXPROCS(0)
					order := []int{1, 2}
					tr.TimingOrder = "serial,parallel"
					if trial%2 == 1 {
						order = []int{2, 1}
						tr.TimingOrder = "parallel,serial"
					}
					if !c.VerifySerial {
						order = []int{res.Workers}
					}
					if c.VerifySerial && savedProcs < 2 {
						return fmt.Errorf("paired timing requires two cores")
					}
					for _, mode := range order {
						runtime.GOMAXPROCS(mode)
						runtime.GC()
						var sample *onlineResult
						sample, err = onlineRun(ct, mode, trial, prune)
						if err != nil {
							break
						}
						if mode == 1 && c.VerifySerial {
							serial = sample
						} else {
							measured = sample
						}
					}
					runtime.GOMAXPROCS(savedProcs)
					if err != nil {
						tr.Error = err.Error()
						res.Trials = append(res.Trials, tr)
						fmt.Printf("trial=%d power=%d failed=%s\n", tr.Index, power, tr.Error)
						continue
					}
					leaves, refreshed, returned := measured.leaves, measured.refreshed, measured.returned
					tr.EntrySplitSeconds, tr.AllLeafBootstrapSeconds = measured.entrySeconds, measured.leafSeconds
					tr.MergeReturnSeconds, tr.OnlineSeconds = measured.mergeSeconds, measured.onlineSeconds
					tr.RefreshedBranches = len(refreshed)
					if prune {
						tr.RefreshedBranches = c.Messages
					}
					tr.Branches = make([]branchResult, len(leaves))
					for b, duration := range measured.durations {
						tr.SumBranchSeconds += duration
						tr.Branches[b] = branchResult{ReadoutSeconds: measured.readoutTimes[b], EvalModSeconds: measured.evalModTimes[b], Arithmetic: engines[b].shaped.Stats, Index: b, MessageReal: real(zs[b]), MessageImag: imag(zs[b]), BootstrapSeconds: duration, Skipped: prune && b >= c.Messages}
					}
					if c.VerifySerial {
						tr.SerialChecked = true
						tr.SerialCiphertextsEqual = returned.Equal(serial.returned)
						for b := range refreshed {
							tr.SerialCiphertextsEqual = tr.SerialCiphertextsEqual && refreshed[b].Equal(serial.refreshed[b])
						}
						if !tr.SerialCiphertextsEqual {
							return fmt.Errorf("serial/parallel ciphertext mismatch")
						}
						tr.SerialOnlineSeconds, tr.SerialLeafSeconds = serial.onlineSeconds, serial.leafSeconds
						tr.ParallelOnlineSeconds = measured.onlineSeconds
						tr.Speedup = serial.onlineSeconds / measured.onlineSeconds
						fmt.Printf("serial_check=exact_match workers=%d parallel=%.6f serial=%.6f speedup=%.4f\n", res.Workers, measured.onlineSeconds, serial.onlineSeconds, tr.Speedup)
					}
					tr.OutputLevel = returned.Level()
					tr.OutputLogScale = scaleLog(returned.Scale)
					tr.OutputLogQ = logProduct(top.Q()[:returned.Level()+1])
					tr.RestoredBits = tr.OutputLogQ - math.Log2(float64(c.Q0))
					if returned.Level() != 1 {
						return fmt.Errorf("expected output level1, got %d", returned.Level())
					}
					// All following secret-key operations are validation only.
					diag := time.Now()
					ov, err := decode(top, st, returned)
					if err != nil {
						return err
					}
					tr.Output = stats(ov, want, c.R, nil)
					decrypted := rlwe.NewDecryptor(top, st).DecryptNew(returned)
					view := ckks.NewCiphertext(top, 0, returned.Level())
					view.Value[0] = decrypted.Value
					view.MetaData = decrypted.MetaData.CopyNew()
					recovered, err := lb.SplitCoefficientBranches(top, retLeaf, view)
					if err != nil {
						return err
					}
					for b := range leaves {
						raw, carry, err := selectedLift(low, sl, leaves[b])
						if err != nil {
							return err
						}
						frac := [2]float64{}
						for lane := 0; lane < 2; lane++ {
							rem := new(big.Int).Sub(raw[lane], new(big.Int).Mul(big.NewInt(carry[lane]), new(big.Int).SetUint64(c.Q0)))
							v := new(big.Float).SetPrec(192).SetInt(rem)
							v.Quo(v, new(big.Float).SetPrec(192).SetUint64(c.Q0))
							frac[lane], _ = v.Float64()
						}
						tr.Branches[b].CarryReal, tr.Branches[b].CarryImag = carry[0], carry[1]
						tr.Branches[b].EntryObservableError = cmplx.Abs(complex(res.Beta*frac[0], res.Beta*frac[1]) - zs[b])
						entryError := complex(res.Beta*frac[0], res.Beta*frac[1]) - zs[b]
						tr.Branches[b].EntryErrorReal, tr.Branches[b].EntryErrorImag = real(entryError), imag(entryError)
						tr.Branches[b].DomainCovered = math.Abs(float64(carry[0])+frac[0]-.25) <= float64(c.K) && math.Abs(float64(carry[1])+frac[1]-.25) <= float64(c.K)
						v, err := decode(main, sm, refreshed[b])
						if err != nil {
							return err
						}
						tr.Branches[b].MainOutput = stats(v, leafExpected(main.MaxSlots(), c.R, zs[b]), c.R, &zs[b])
						mainValues := v
						v, err = plainView(retLeaf, recovered[b])
						if err != nil {
							return err
						}
						tr.Branches[b].RecoveredAfterMerge = stats(v, leafExpected(main.MaxSlots(), c.R, zs[b]), c.R, &zs[b])
						for j := range v {
							tr.Branches[b].ReturnPointwiseMax = math.Max(tr.Branches[b].ReturnPointwiseMax, cmplx.Abs(v[j]-mainValues[j]))
						}
					}
					if c.StageDiagnostics {
						if e := collectStages(engines, leaves, refreshed, low, main, sm, zs, c, trial, &tr); e != nil {
							return e
						}
					}
					tr.DiagnosticsSeconds = time.Since(diag).Seconds()
					if c.CheckSquare {
						ts := time.Now()
						sq, err := app.MulRelinNew(returned, returned)
						if err != nil {
							return err
						}
						if err = app.Rescale(sq, sq); err != nil {
							return err
						}
						tr.ApplicationSeconds = time.Since(ts).Seconds()
						tr.ApplicationOutputLevel = sq.Level()
						aw := make([]complex128, len(want))
						for j := range aw {
							aw[j] = want[j] * want[j]
						}
						av, err := decode(top, st, sq)
						if err != nil {
							return err
						}
						tr.Application = stats(av, aw, c.R, nil)
						if c.RepeatRounds > 0 {
							if 2*(c.Messages-1) >= res.BranchCount {
								return fmt.Errorf("repeat-square interface requires no branch exponent wrap")
							}
							current, expected, support := sq, aw, c.Messages
							logical := append([]complex128(nil), zs...)
							for round := 1; round <= c.RepeatRounds; round++ {
								logical, support, err = squareLogicalSupport(logical, support)
								if err != nil {
									return err
								}
								activeMessages = support
								betaNow := float64(c.Q0) * float64(c.R) / current.Scale.Float64()
								for _, engine := range engines {
									engine.beta = betaNow
								}
								m, err := onlineRun(current, res.Workers, trial+1000*round, true)
								if err != nil {
									return err
								}
								rr, err := diagnoseRepeat(top, low, main, st, sl, sm, current, expected, logical, support, betaNow, round, c, m)
								if err != nil {
									return err
								}
								tr.Repeats = append(tr.Repeats, rr)
								fmt.Printf("repeat=%d support=%d input_logscale=%.6f beta=%.6f output_level=%d online=%.6f bits=%.6f\n", round, support, rr.InputLogScale, betaNow, rr.OutputLevel, rr.OnlineSeconds, rr.Output.DataErrorBits)
								if round < c.RepeatRounds {
									current, err = app.MulRelinNew(m.returned, m.returned)
									if err != nil {
										return err
									}
									if err = app.Rescale(current, current); err != nil {
										return err
									}
									next := make([]complex128, len(expected))
									for j, x := range expected {
										next[j] = x * x
									}
									expected = next
								}
							}
							activeMessages = c.Messages
							for _, engine := range engines {
								engine.beta = res.Beta
							}
						}
					}
					res.Trials = append(res.Trials, tr)
					fmt.Printf("trial=%d entryP=%d power=%d pruned=%t branches=%d output_level=%d online_seconds=%.6f split=%.6f leafs=%.6f merge=%.6f merged_bits=%.4f guard=%.6g app_level=%d\n", tr.Index, tr.EntryP, tr.UnitPower, tr.Pruned, tr.RefreshedBranches, tr.OutputLevel, tr.OnlineSeconds, tr.EntrySplitSeconds, tr.AllLeafBootstrapSeconds, tr.MergeReturnSeconds, tr.Output.DataErrorBits, tr.Output.GuardMax, tr.ApplicationOutputLevel)
				} // full versus pruned: same ciphertext and keys
			} // unit powers: same ciphertext and all keys
		} // entry methods: same input, same secrets and leaf/return keys
	}
	return nil
}

func main() {
	c := config{}
	flag.BoolVar(&c.PruneOnly, "prune-only", false, "refresh only the public message-support branches")
	var out string
	flag.BoolVar(&c.AllowSubunitCoefficientScale, "allow-subunit-coefficient-scale", false, "allow true shaped coefficient encoding at scale below one; experimental")
	flag.IntVar(&c.FusedPower, "fused-power", -1, "separate unit power for fused readout; -1 follows internal power")
	flag.StringVar(&c.Mod1Family, "mod1-family", "continuous", "continuous or discrete cosine approximation")
	flag.IntVar(&c.Degree, "degree", 31, "EvalMod polynomial degree")
	flag.IntVar(&c.DoubleAngle, "double-angle", 3, "EvalMod double-angle count")
	flag.IntVar(&c.RepeatRounds, "repeat-rounds", 0, "actual square then refresh rounds on a public no-wrap prefix support")
	flag.Uint64Var(&c.SmallP, "entry-small-p", 0, "experimental non-NTT auxiliary entry prime; 0 disables")
	flag.BoolVar(&c.CompareEntry, "compare-entry", false, "paired ordinary and small-P entry with identical input and downstream keys")
	flag.IntVar(&c.Messages, "messages", 0, "public prefix branch support; 0 means all branches")
	flag.BoolVar(&c.ComparePrune, "compare-prune", false, "paired full-versus-known-zero-branch pruning")
	flag.StringVar(&c.Powers, "powers", "1", "comma-separated exact powers of unit; same input and keys")
	flag.BoolVar(&c.StageDiagnostics, "stage-diagnostics", true, "rerun outside timer with per-stage diagnostics")
	flag.IntVar(&c.Workers, "workers", 1, "concurrent leaf refreshes")
	flag.BoolVar(&c.VerifySerial, "verify-serial", true, "every-trial same-input one-core serial/two-core EvalMod-lane timing and exact ciphertext check")
	flag.IntVar(&c.LogN, "logN", 16, "")
	flag.IntVar(&c.Logn, "logn", 13, "")
	flag.IntVar(&c.R, "R", 8, "")
	flag.IntVar(&c.Trials, "trials", 3, "")
	flag.IntVar(&c.TargetBits, "target-bits", 5, "")
	flag.IntVar(&c.ScaleBits, "scale-bits", 22, "")
	flag.IntVar(&c.EMBits, "embits", 20, "")
	flag.IntVar(&c.K, "K", 17, "")
	flag.IntVar(&c.MainBase, "main-base", 9, "")
	flag.IntVar(&c.EntryBase, "entry-base", 1, "")
	flag.IntVar(&c.BoundaryBase, "boundary-base", 5, "")
	flag.Uint64Var(&c.Q0, "q0", 14155777, "")
	flag.Uint64Var(&c.Qout, "qout", 5767169, "")
	flag.Uint64Var(&c.TopP, "top-p", 786433, "")
	flag.Uint64Var(&c.MainP, "main-p", 65537, "")
	flag.Int64Var(&c.Seed, "seed", 20261024, "")
	flag.StringVar(&c.UnitFile, "units", "units-weak.json", "")
	flag.BoolVar(&c.CheckSquare, "check-square", true, "")
	flag.StringVar(&out, "out", "fullsplit.json", "")
	flag.Parse()
	host, _ := os.Hostname()
	res := result{Scope: "Public logical prefix support is an input contract. Pruned branches are replaced by exact public zero ciphertexts without secret-dependent decisions; full and pruned cases have identical useful payload. Paired unit-power sweep: all powers share identical trial input ciphertext and cryptographic keys; input unit is fixed at power1, internal/output units vary. Stage diagnostics are separate deterministic reruns outside online timing. Full coefficient split into N/n branches, one independently selectable complex message per branch, only public active branches bootstrapped in prune-only mode, all branches merged, one return KS. SSE h32; shared leaf main keys, independent evaluator buffers per branch, schedule-independent rounding seeds. AllLeafBootstrapSeconds is wall time; SumBranchSeconds sums overlapping branch wall durations. Serial verification uses each identical trial input and keys; parallel mode uses two independent EvalMod lanes, outside parallel timings. Online timing excludes keygen/encryption/decryption/oracle diagnostics. Finite-sample experiment; no security certification.", Status: "running", Host: host, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Started: time.Now().UTC().Format(time.RFC3339), Config: c}
	if err := run(c, &res); err != nil {
		res.Status = "execution_failed"
		res.Error = err.Error()
	} else {
		res.Status = "executed"
	}
	for _, t := range res.Trials {
		if t.Error != "" {
			res.CasesFailed++
			continue
		}
		res.CasesExecuted++
		if t.OutputLevel == 1 && t.Output.DataErrorBits >= float64(c.TargetBits) {
			res.CasesMeetingTarget++
		}
	}
	if res.CasesFailed > 0 && res.Status == "executed" {
		res.Status = "executed_with_case_failures"
		res.Error = fmt.Sprintf("%d trial cases failed; inspect per-trial Error", res.CasesFailed)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		panic(err)
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(out, append(b, '\n'), 0644); err != nil {
		panic(err)
	}
	fmt.Printf("status=%s error=%s result=%s\n", res.Status, res.Error, out)
	if res.Status != "executed" {
		os.Exit(1)
	}
}
