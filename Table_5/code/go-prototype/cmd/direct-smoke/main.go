package main

// Direct same-ring PA bootstrap. No ring-entry projection, Split, Merge, or
// cross-dimension key switch is called by this executable.
import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/cmplx"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

type unitSpec struct {
	R       int      `json:"R"`
	Coeffs  []string `json:"polynomial_coefficients_ascending"`
	Inverse []string `json:"inverse_coefficients_ascending"`
	Focus   string   `json:"focus_embedding_real"`
}
type config struct {
	PairedTiming                                                                          bool
	LaneWorkers                                                                           int
	ChainOperation                                                                        string
	DryRun, EnforceReference, UnitCircle                                                  bool
	ChainLength                                                                           int
	LogN, R, Power, Trials, TargetBits                                                    int
	FreshLevel, OutputLevel, InputBits, OutputBits, EMBits, OutputPrimeBits               int
	Degree, DoubleAngle, InverseDegree, K, RatioBits, MainH, SparseH, MainBase, EntryBase int
	InverseInputBits                                                                      int
	Q0, Qout, MainP, SmallP, WorkPrime                                                    uint64
	QChain, ChainMode, Mod1Family, UnitFile                                               string
	Seed                                                                                  int64
	Amplitude                                                                             float64
	CheckSquare, AllowSubunit, Diagnostics                                                bool
}
type modulusState struct {
	Level          int
	LogQ, LogScale float64
	QPrimes        []uint64
}
type metric struct {
	MaxAbsError, MeanAbsError, RMSError, MaxErrorBits, MeanErrorBits, RMSBits, GuardMax, DataMax float64
	DataSlots                                                                                    int
}
type stage struct {
	Lane    int
	Name    string
	State   modulusState
	Metrics metric
}
type trial struct {
	SerialOnlineSeconds, ParallelOnlineSeconds, ReadoutSeconds, EvalModSeconds             float64
	PairedCiphertextsEqual                                                                 bool
	TimingOrder                                                                            string
	ApplicationChain                                                                       phaseChainResult
	Index                                                                                  int
	Error                                                                                  string
	MessageReal, MessageImag                                                               float64
	Fresh, PreBootstrap, InternalMaximum, Output, AfterSquare                              modulusState
	FreshMetrics, PreBootstrapMetrics, OutputMetrics, SquareMetrics                        metric
	FreshQGreaterThanOutputQ, PreBootstrapQGreaterThanOutputQ, InternalQGreaterThanOutputQ bool
	RefreshedModulusBits                                                                   float64
	Beta                                                                                   float64
	Carries                                                                                [2]int64
	Fractions, EntryError, PureApproximationError                                          [2]float64
	CarryDomainCovered, FractionalDomainCovered, MeetsTarget, SquareMeetsTarget            bool
	EntrySeconds, RefreshSeconds, OnlineSeconds, SquareSeconds, DiagnosticsSeconds         float64
	Arithmetic                                                                             lb.ShapedStats
	Stages                                                                                 []stage
}
type result struct {
	OracleMaxScalarError                                                    float64
	OracleCarryRadius                                                       int
	Status, Error, Scope, Host, Started                                     string
	Config                                                                  config
	RingSwitching                                                           bool
	EntryMethod, SecretDescription, PayloadDescription                      string
	QPrimes, PPrimes                                                        []uint64
	MainQBits, MainQPBits, EntryQPBits                                      float64
	MainReferenceCap, EntryReferenceCap                                     int
	ReferenceTableFits                                                      bool
	EvalModDepth, PolynomialDepth, InverseDepth, ActualMod1Degree, KeyCount int
	UnitFocus, FocusSuppressionBits                                         float64
	MainKeyBytes, EntryKeyBytes                                             int
	KeygenSeconds, TotalSeconds                                             float64
	GOMAXPROCS, CasesExecuted, CasesFailed, CasesMeetingTarget              int
	Trials                                                                  []trial
}

func state(p ckks.Parameters, ct *rlwe.Ciphertext) modulusState {
	return modulusState{Level: ct.Level(), LogQ: logProduct(p.Q()[:ct.Level()+1]), LogScale: scaleLog(ct.Scale), QPrimes: append([]uint64(nil), p.Q()[:ct.Level()+1]...)}
}
func stats(v []complex128, z complex128, R int) metric {
	m := metric{}
	for j, x := range v {
		if j%R == 0 {
			e := cmplx.Abs(x - z)
			m.MaxAbsError = math.Max(m.MaxAbsError, e)
			m.MeanAbsError += e
			m.RMSError += e * e
			m.DataMax = math.Max(m.DataMax, cmplx.Abs(x))
			m.DataSlots++
		} else {
			m.GuardMax = math.Max(m.GuardMax, cmplx.Abs(x))
		}
	}
	m.MeanAbsError /= float64(m.DataSlots)
	m.RMSError = math.Sqrt(m.RMSError / float64(m.DataSlots))
	m.MaxErrorBits = bitsError(m.MaxAbsError)
	m.MeanErrorBits = bitsError(m.MeanAbsError)
	m.RMSBits = bitsError(m.RMSError)
	return m
}
func measure(p ckks.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, z complex128, R int) (metric, error) {
	v, e := decode(p, sk, ct)
	if e != nil {
		return metric{}, e
	}
	for _, x := range v {
		if math.IsNaN(cmplx.Abs(x)) || math.IsInf(cmplx.Abs(x), 0) {
			return metric{}, fmt.Errorf("nonfinite decode")
		}
	}
	return stats(v, z, R), nil
}
func parameters(c config) (ckks.Parameters, mod1.ParametersLiteral, error) {
	family := mod1.CosContinuous
	if c.Mod1Family == "discrete" {
		family = mod1.CosDiscrete
	} else if c.Mod1Family != "continuous" {
		return ckks.Parameters{}, mod1.ParametersLiteral{}, fmt.Errorf("unknown Mod1 family")
	}
	lit := mod1.ParametersLiteral{LogScale: c.EMBits, Mod1Type: family, LogMessageRatio: c.RatioBits, K: c.K, Mod1Degree: c.Degree, DoubleAngle: c.DoubleAngle, Mod1InvDegree: c.InverseDegree}
	qs := []uint64{}
	used := map[uint64]bool{c.MainP: true}
	if c.QChain != "" {
		for _, s := range strings.Split(c.QChain, ",") {
			q, e := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
			if e != nil {
				return ckks.Parameters{}, lit, e
			}
			qs = append(qs, q)
		}
	} else {
		qs = append(qs, c.Q0)
		used[c.Q0] = true
		if c.OutputLevel >= 1 {
			qs = append(qs, c.Qout)
			used[c.Qout] = true
		}
		outGen := ring.NewNTTFriendlyPrimesGenerator(uint64(c.OutputPrimeBits), uint64(2<<c.LogN))
		for len(qs) < c.OutputLevel+1 {
			q, e := outGen.NextUpstreamPrime()
			if e != nil {
				return ckks.Parameters{}, lit, e
			}
			if !used[q] {
				qs = append(qs, q)
				used[q] = true
			}
		}
		if c.ChainMode == "small" {
			for q := uint64(2<<c.LogN) + 1; len(qs) < lit.Depth()+c.OutputLevel+1; q += uint64(2 << c.LogN) {
				if !used[q] && ring.IsPrime(q) {
					qs = append(qs, q)
					used[q] = true
				}
			}
		} else if c.ChainMode == "uniform" {
			pg := ring.NewNTTFriendlyPrimesGenerator(uint64(c.EMBits), uint64(2<<c.LogN))
			for len(qs) < lit.Depth()+c.OutputLevel+1 {
				q, e := pg.NextUpstreamPrime()
				if e != nil {
					return ckks.Parameters{}, lit, e
				}
				if !used[q] {
					qs = append(qs, q)
					used[q] = true
				}
			}
		} else {
			return ckks.Parameters{}, lit, fmt.Errorf("chain must be small or uniform")
		}
	}
	if len(qs) != lit.Depth()+c.OutputLevel+1 {
		return ckks.Parameters{}, lit, fmt.Errorf("need %d Q primes (depth %d + output level %d + 1), got %d", lit.Depth()+c.OutputLevel+1, lit.Depth(), c.OutputLevel, len(qs))
	}
	ps := []uint64{}
	if c.MainP != 0 {
		ps = append(ps, c.MainP)
	}
	p, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: qs, P: ps, LogDefaultScale: c.EMBits, Xs: ring.Ternary{H: c.MainH}})
	lit.LevelQ = len(qs) - 1
	lit.Scaling = math.Exp2(math.Round(math.Log2(float64(qs[0])))) / float64(qs[0])
	return p, lit, e
}
func run(c config, res *result) (err error) {
	start := time.Now()
	defer func() { res.TotalSeconds = time.Since(start).Seconds() }()
	if c.LogN < 5 || c.R < 1 || c.R&(c.R-1) != 0 || c.R > (1<<(c.LogN-1)) || c.Power < 0 || c.Power > 6 || c.Trials < 1 || c.OutputLevel < 0 || c.FreshLevel < 0 || c.DoubleAngle < 0 || c.InputBits < 1 || c.OutputBits < 1 || c.Amplitude <= 0 {
		return fmt.Errorf("invalid dimensions/levels/scales")
	}
	raw, e := os.ReadFile(c.UnitFile)
	if e != nil {
		return e
	}
	var units []unitSpec
	if e = json.Unmarshal(raw, &units); e != nil {
		return e
	}
	var u unitSpec
	for _, v := range units {
		if v.R == c.R {
			u = v
			break
		}
	}
	if u.R == 0 {
		return fmt.Errorf("R%d absent from units", c.R)
	}
	u, e = unitPower(u, c.Power)
	if e != nil {
		return e
	}
	gf := f64(u.Focus)
	main, lit, e := parameters(c)
	if e != nil {
		return e
	}
	if c.FreshLevel > main.MaxLevel() {
		return fmt.Errorf("fresh level exceeds main chain")
	}
	if c.QChain != "" {
		c.Q0 = main.Q()[0]
	}
	if e = lb.ValidateBaseTwoDecompositionCoverage(main, main.MaxLevel(), main.MaxLevelP(), c.MainBase); e != nil {
		return e
	}
	low, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: main.Q()[:1], LogDefaultScale: c.InputBits, Xs: ring.Ternary{H: c.SparseH}})
	if e != nil {
		return e
	}
	entryP, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: main.Q()[:1], LogDefaultScale: c.InputBits, Xs: ring.Ternary{H: c.MainH}})
	if e != nil {
		return e
	}
	plan, e := mod1.NewParametersFromLiteral(main, lit)
	if e != nil {
		return e
	}
	res.Config = c
	res.RingSwitching = false
	res.Scope = "direct same-ring single-message PA bootstrap with same-ring SSE; no Split/Merge/cross-ring KS"
	res.PayloadDescription = fmt.Sprintf("one independent complex message repeated in %d of %d canonical slots; %d PA classes, focus class j mod R = 0", main.MaxSlots()/c.R, main.MaxSlots(), c.R)
	res.SecretDescription = fmt.Sprintf("fixed-total-H main secret H=%d, same-ring ephemeral SSE secret H=%d; independent random signs; not uniform dense", c.MainH, c.SparseH)
	res.QPrimes, res.PPrimes = main.Q(), main.P()
	res.MainQBits = logProduct(main.Q())
	res.MainQPBits = res.MainQBits + logProduct(main.P())
	res.EntryQPBits = math.Log2(float64(main.Q()[0]))
	if c.SmallP != 0 {
		res.EntryQPBits += math.Log2(float64(c.SmallP))
	}
	res.UnitFocus = gf
	res.FocusSuppressionBits = -math.Log2(gf)
	res.EvalModDepth = lit.Depth()
	res.PolynomialDepth = plan.Mod1Poly.Depth()
	res.ActualMod1Degree = plan.Mod1Poly.Degree()
	if plan.Mod1InvPoly != nil {
		res.InverseDepth = plan.Mod1InvPoly.Depth()
	}
	if c.LogN == 13 {
		caps := map[int]int{32: 37, 64: 112, 128: 167, 192: 186, 256: 196, 512: 208, 1024: 211, 2048: 213}
		res.MainReferenceCap = caps[c.MainH]
		res.EntryReferenceCap = caps[c.SparseH]
		res.ReferenceTableFits = res.MainReferenceCap > 0 && res.EntryReferenceCap > 0 && res.MainQPBits <= float64(res.MainReferenceCap) && res.EntryQPBits <= float64(res.EntryReferenceCap)
	}
	res.OracleCarryRadius = c.K - 1
	betaOracle := float64(main.Q()[0]) * float64(c.R) / math.Exp2(float64(c.InputBits))
	for carry := -res.OracleCarryRadius; carry <= res.OracleCarryRadius; carry++ {
		for j := 0; j <= 64; j++ {
			x := c.Amplitude * (float64(j)/32 - 1)
			y := betaOracle * lb.Mod1PlaintextOracle(plan, (float64(carry)+x/betaOracle)/float64(c.K))
			res.OracleMaxScalarError = math.Max(res.OracleMaxScalarError, math.Abs(y-x))
		}
	}
	if c.DryRun {
		return nil
	}
	if c.EnforceReference && !res.ReferenceTableFits {
		return fmt.Errorf("outside reference screen: main %.6f/%d, entry %.6f/%d", res.MainQPBits, res.MainReferenceCap, res.EntryQPBits, res.EntryReferenceCap)
	}
	if c.ChainLength < -1 || c.ChainLength > c.OutputLevel {
		return fmt.Errorf("invalid application chain length")
	}
	unit, inverse := embed(u.Coeffs, main.N()), embed(u.Inverse, main.N())
	keyStart := time.Now()
	kg := rlwe.NewKeyGenerator(main)
	sm := kg.GenSecretKeyWithHammingWeightNew(c.MainH)
	sl := rlwe.NewKeyGenerator(low).GenSecretKeyWithHammingWeightNew(c.SparseH)
	sparseHigh, e := lb.RebaseSecretKey(low, main, sl)
	if e != nil {
		return e
	}
	var entry func(*rlwe.Ciphertext) (*rlwe.Ciphertext, error)
	if c.SmallP != 0 {
		se, e := lb.NewSmallPEntry(entryP, low, sm, sl, c.SmallP, c.WorkPrime)
		if e != nil {
			return e
		}
		entry = se.ApplyTop
		res.EntryKeyBytes = se.CachedKeyBytes()
		res.EntryMethod = "same-ring auxiliary-P SSE key switch; non-NTT P, exact public CRT products"
	} else {
		base := c.EntryBase
		lq, lp := 0, -1
		if e = lb.ValidateBaseTwoDecompositionCoverage(entryP, lq, lp, base); e != nil {
			return e
		}
		key := rlwe.NewKeyGenerator(entryP).GenEvaluationKeyNew(sm, sl, rlwe.EvaluationKeyParameters{LevelQ: &lq, LevelP: &lp, BaseTwoDecomposition: &base})
		ev := rlwe.NewEvaluator(entryP, nil)
		entry = func(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
			out := ct.CopyNew()
			e := ev.ApplyEvaluationKey(ct, key, out)
			return out, e
		}
		res.EntryKeyBytes = key.BinarySize()
		res.EntryMethod = "same-ring no-P binary SSE key switch"
	}
	kp := rlwe.EvaluationKeyParameters{BaseTwoDecomposition: &c.MainBase}
	relin := kg.GenRelinearizationKeyNew(sm, kp)
	gals := kg.GenGaloisKeysNew(lb.FusedGaloisElements(main, c.R), sm, kp)
	keys := rlwe.NewMemEvaluationKeySet(relin, gals...)
	base := ckks.NewEvaluator(main, keys)
	shaped, e := lb.NewShapedEvaluator(main, base, unit, inverse, c.R, complex(gf, 0))
	if e != nil {
		return e
	}
	shaped.AllowSubunitCoefficientScale = c.AllowSubunit
	shaped.InverseInputLogScale = float64(c.InverseInputBits)
	alpha := new(big.Float).SetPrec(192).SetFloat64(math.Exp2(float64(c.EMBits)) / (2 * float64(c.R) * gf * float64(main.Q()[0]) * float64(c.K)))
	fused, e := lb.NewFusedRecovery(main, c.R, alpha, rlwe.NewScale(math.Exp2(float64(c.EMBits))), unit, sparseHigh, sm, keys, c.Seed, kp)
	if e != nil {
		return e
	}
	res.MainKeyBytes = relin.BinarySize()
	for _, k := range gals {
		res.MainKeyBytes += k.BinarySize()
	}
	for _, k := range fused.BranchKeys {
		res.MainKeyBytes += k.BinarySize()
	}
	res.KeyCount = 1 + len(gals) + len(fused.BranchKeys) + 1
	res.KeygenSeconds = time.Since(keyStart).Seconds()
	res.GOMAXPROCS = runtime.GOMAXPROCS(0)
	laneShapes := [2]*lb.ShapedEvaluator{lb.ForkShapedEvaluator(shaped), lb.ForkShapedEvaluator(shaped)}
	plusI := make([]*big.Int, main.N())
	for j := range plusI {
		plusI[j] = new(big.Int)
	}
	plusI[main.N()/2].SetInt64(1)
	rng := rand.New(rand.NewSource(c.Seed))
	fmt.Printf("direct N=%d R=%d depth=%d main_logQP=%.8f entry_logQP=%.8f output_level=%d keygen=%.3f\n", main.N(), c.R, lit.Depth(), res.MainQPBits, res.EntryQPBits, c.OutputLevel, res.KeygenSeconds)
	for index := 0; index < c.Trials; index++ {
		tr := trial{Index: index + 1}
		z := complex((rng.Float64()*2-1)*c.Amplitude, (rng.Float64()*2-1)*c.Amplitude)
		if c.UnitCircle {
			// Eight fixed phase points include axes and diagonals. Later trials
			// use random phases; all have the requested nonzero magnitude.
			theta := float64(index) * math.Pi / 4
			if index >= 8 {
				theta = 2 * math.Pi * rng.Float64()
			}
			z = complex(c.Amplitude, 0) * cmplx.Exp(complex(0, theta))
		}
		tr.MessageReal, tr.MessageImag = real(z), imag(z)
		trialErr := func() error {
			values := make([]complex128, main.MaxSlots())
			for j := 0; j < len(values); j += c.R {
				values[j] = z / complex(gf, 0)
			}
			pt := ckks.NewPlaintext(main, c.FreshLevel)
			pt.Scale = rlwe.NewScale(math.Exp2(float64(c.InputBits)))
			if e := ckks.NewEncoder(main, 128).Encode(values, pt); e != nil {
				return e
			}
			ct, e := rlwe.NewEncryptor(main, sm).EncryptNew(pt)
			if e != nil {
				return e
			}
			ct, e = lb.MulIntegerPolynomial(main, ct, unit)
			if e != nil {
				return e
			}
			tr.Fresh = state(main, ct)
			tr.FreshMetrics, e = measure(main, sm, ct, z, c.R)
			if e != nil {
				return e
			}
			// Deliberate modulus dropping models an already-exhausted input, not an
			// application history. Fresh and pre-bootstrap states remain separate.
			if ct.Level() > 0 {
				base.DropLevel(ct, ct.Level())
			}
			tr.PreBootstrap = state(main, ct)
			tr.PreBootstrapMetrics, e = measure(main, sm, ct, z, c.R)
			if e != nil {
				return e
			}
			tr.Beta = float64(main.Q()[0]) * float64(c.R) / ct.Scale.Float64()
			tr.InternalMaximum = modulusState{Level: main.MaxLevel(), LogQ: res.MainQBits, LogScale: float64(c.EMBits), QPrimes: append([]uint64(nil), main.Q()...)}
			entryStart := time.Now()
			lowCT, e := entry(ct)
			if e != nil {
				return e
			}
			tr.EntrySeconds = time.Since(entryStart).Seconds()
			fused.SetRoundingSeed(c.Seed + int64(index)*1000003)
			shaped.Stats = lb.ShapedStats{}
			refresh := func(hook func(int, string, *rlwe.Ciphertext) error) (*rlwe.Ciphertext, error) {
				readoutStart := time.Now()
				re, im, e := fused.Apply(low, lowCT)
				tr.ReadoutSeconds = time.Since(readoutStart).Seconds()
				evalStart := time.Now()
				if e != nil {
					return nil, e
				}
				lanes := []*rlwe.Ciphertext{re, im}
				workers := c.LaneWorkers
				if hook != nil {
					workers = 1
				}
				for _, sh := range laneShapes {
					sh.Stats = lb.ShapedStats{}
				}
				e = lb.RunTwoLanes(workers, func(lane int) error {
					v := lanes[lane]
					shaped := laneShapes[lane]
					var e error
					var sh lb.ShapedStageHook
					if hook != nil {
						if e = hook(lane, "fused", v); e != nil {
							return e
						}
						sh = func(name string, ct *rlwe.Ciphertext) error { return hook(lane, name, ct) }
					}
					lanes[lane], e = lb.EvaluateShapedMod1(shaped, v, plan, rlwe.NewScale(tr.Beta*math.Exp2(float64(c.OutputBits))), true, sh)
					if e != nil {
						return e
					}
					lanes[lane].Scale = lanes[lane].Scale.Div(rlwe.NewScale(tr.Beta))
					if plan.DoubleAngle > 0 && plan.Mod1InvPoly == nil {
						if e = shaped.Rescale(lanes[lane], lanes[lane]); e != nil {
							return e
						}
					}
					return nil
				})
				if e != nil {
					return nil, e
				}
				for _, sh := range laneShapes {
					lb.AddShapedStats(&shaped.Stats, sh.Stats)
				}
				tr.EvalModSeconds = time.Since(evalStart).Seconds()
				imCT, e := lb.MulIntegerPolynomial(main, lanes[1], plusI)
				if e != nil {
					return nil, e
				}
				return base.AddNew(lanes[0], imCT)
			}

			bootstrapRun := func(workers int) (*rlwe.Ciphertext, error) {
				c.LaneWorkers = workers
				entryStart = time.Now()
				lowCT, e = entry(ct)
				tr.EntrySeconds = time.Since(entryStart).Seconds()
				if e != nil {
					return nil, e
				}
				fused.SetRoundingSeed(c.Seed + int64(index)*1000003)
				shaped.Stats = lb.ShapedStats{}
				refreshStart := time.Now()
				out, err := refresh(nil)
				tr.RefreshSeconds = time.Since(refreshStart).Seconds()
				tr.OnlineSeconds = tr.EntrySeconds + tr.RefreshSeconds
				tr.Arithmetic = shaped.Stats
				return out, err
			}
			var out *rlwe.Ciphertext
			if c.PairedTiming {
				savedProcs := runtime.GOMAXPROCS(0)
				if savedProcs < 2 {
					return fmt.Errorf("paired lane timing requires two CPU cores")
				}
				order := []int{1, 2}
				tr.TimingOrder = "serial,parallel"
				if index%2 == 1 {
					order = []int{2, 1}
					tr.TimingOrder = "parallel,serial"
				}
				var serial, parallel *rlwe.Ciphertext
				var serialTime float64
				var parallelTrial trial
				for _, mode := range order {
					runtime.GOMAXPROCS(mode)
					runtime.GC()
					out, e = bootstrapRun(mode)
					if e != nil {
						runtime.GOMAXPROCS(savedProcs)
						return e
					}
					if mode == 1 {
						serial = out
						serialTime = tr.OnlineSeconds
					} else {
						parallel = out
						parallelTrial = tr
					}
				}
				runtime.GOMAXPROCS(savedProcs)
				tr = parallelTrial
				tr.SerialOnlineSeconds, tr.ParallelOnlineSeconds = serialTime, tr.OnlineSeconds
				tr.PairedCiphertextsEqual = serial.Equal(parallel)
				if !tr.PairedCiphertextsEqual {
					return fmt.Errorf("serial/parallel ciphertext mismatch")
				}
				out = parallel
			} else {
				out, e = bootstrapRun(c.LaneWorkers)
				if e != nil {
					return e
				}
			}
			tr.Output = state(main, out)
			if out.Level() != c.OutputLevel {
				return fmt.Errorf("unexpected output level %d, wanted %d", out.Level(), c.OutputLevel)
			}
			tr.OutputMetrics, e = measure(main, sm, out, z, c.R)
			if e != nil {
				return e
			}
			tr.MeetsTarget = tr.OutputMetrics.MaxErrorBits >= float64(c.TargetBits)
			if c.ChainLength != 0 {
				tr.ApplicationChain, e = runPhaseChain(main, sm, shaped, out, z, c)
				if e != nil {
					return e
				}
			}
			tr.FreshQGreaterThanOutputQ = tr.Fresh.LogQ > tr.Output.LogQ+1e-9
			tr.PreBootstrapQGreaterThanOutputQ = tr.PreBootstrap.LogQ > tr.Output.LogQ+1e-9
			tr.InternalQGreaterThanOutputQ = tr.InternalMaximum.LogQ > tr.Output.LogQ+1e-9
			tr.RefreshedModulusBits = tr.Output.LogQ - tr.PreBootstrap.LogQ
			if c.CheckSquare {
				if out.Level() == 0 {
					return fmt.Errorf("cannot square/rescale at output level 0; disable check-square")
				}
				s := time.Now()
				sq, e := shaped.MulRelinNew(out, out)
				if e != nil {
					return e
				}
				if e = shaped.Rescale(sq, sq); e != nil {
					return e
				}
				tr.SquareSeconds = time.Since(s).Seconds()
				tr.AfterSquare = state(main, sq)
				tr.SquareMetrics, e = measure(main, sm, sq, z*z, c.R)
				if e != nil {
					return e
				}
				tr.SquareMeetsTarget = tr.SquareMetrics.MaxErrorBits >= float64(c.TargetBits)
			}
			diagStart := time.Now()
			raw, carries, e := selectedLift(low, sl, lowCT)
			if e != nil {
				return e
			}
			tr.Carries = carries
			tr.CarryDomainCovered = true
			tr.FractionalDomainCovered = true
			for lane := range raw {
				remainder := new(big.Int).Sub(raw[lane], new(big.Int).Mul(big.NewInt(carries[lane]), new(big.Int).SetUint64(main.Q()[0])))
				frac, _ := new(big.Float).Quo(new(big.Float).SetInt(remainder), new(big.Float).SetUint64(main.Q()[0])).Float64()
				tr.Fractions[lane] = frac
				want := real(z)
				if lane == 1 {
					want = imag(z)
				}
				recovered := tr.Beta * frac
				tr.EntryError[lane] = math.Abs(recovered - want)
				tr.PureApproximationError[lane] = math.Abs(tr.Beta*lb.Mod1PlaintextOracle(plan, (float64(carries[lane])+frac)/float64(c.K)) - recovered)
				tr.CarryDomainCovered = tr.CarryDomainCovered && math.Abs(float64(carries[lane])+frac-0.25) <= float64(c.K)
				tr.FractionalDomainCovered = tr.FractionalDomainCovered && math.Abs(frac) <= math.Exp2(-float64(c.RatioBits))
			}
			if c.Diagnostics {
				fused.SetRoundingSeed(c.Seed + int64(index)*1000003)
				diag, e := refresh(func(lane int, name string, x *rlwe.Ciphertext) error {
					expected := 0.0
					if name == "fused" {
						expected = (float64(carries[lane]) + tr.Fractions[lane]) / float64(c.K)
					}
					m, e := measure(main, sm, x, complex(expected, 0), c.R)
					if e != nil {
						return e
					}
					tr.Stages = append(tr.Stages, stage{Lane: lane, Name: name, State: state(main, x), Metrics: m})
					return nil
				})
				if e != nil {
					return e
				}
				if !diag.Equal(out) {
					return fmt.Errorf("diagnostic rerun ciphertext differs from timed ciphertext")
				}
			}
			tr.DiagnosticsSeconds = time.Since(diagStart).Seconds()
			return nil
		}()
		res.CasesExecuted++
		if trialErr != nil {
			tr.Error = trialErr.Error()
			res.CasesFailed++
		} else if tr.MeetsTarget {
			res.CasesMeetingTarget++
		}
		res.Trials = append(res.Trials, tr)
		fmt.Printf("trial=%d output_level=%d output_logQ=%.8f max_error_bits=%.6f online=%.6f error=%s\n", tr.Index, tr.Output.Level, tr.Output.LogQ, tr.OutputMetrics.MaxErrorBits, tr.OnlineSeconds, tr.Error)
	}
	if res.CasesFailed > 0 {
		return fmt.Errorf("%d of %d trials failed execution", res.CasesFailed, res.CasesExecuted)
	}
	return nil
}
func main() {
	var c config
	flag.BoolVar(&c.PairedTiming, "paired-timing", false, "same-input one-core serial and two-core EvalMod-lane parallel timing")
	flag.IntVar(&c.LaneWorkers, "lane-workers", 1, "EvalMod lane workers")
	var output string
	flag.StringVar(&c.ChainOperation, "chain-operation", "phase", "phase: fresh encrypted factors; square: successive true squaring, requires unit-circle magnitude one")
	flag.BoolVar(&c.DryRun, "dry-run", false, "parameter ledger only; no keys or HE")
	flag.BoolVar(&c.EnforceReference, "enforce-reference", false, "reject outside recorded sparse-secret reference screens; not security certification")
	flag.BoolVar(&c.UnitCircle, "unit-circle", false, "fixed then random complex phases with magnitude amplitude")
	flag.IntVar(&c.ChainLength, "chain-length", 0, "0 off; -1 consumes all output levels with independent encrypted phase factors")
	flag.IntVar(&c.LogN, "logn", 13, "same ring dimension at every stage")
	flag.IntVar(&c.R, "r", 8, "PA class count, also 1/R occupied canonical slots")
	flag.IntVar(&c.Power, "power", 1, "exact power of selected integer unit")
	flag.IntVar(&c.Trials, "trials", 3, "")
	flag.IntVar(&c.TargetBits, "target-bits", 20, "reported worst-slot absolute-error precision target")
	flag.IntVar(&c.FreshLevel, "fresh-level", 0, "actual fresh encryption level, before deliberate modulus dropping to level0")
	flag.IntVar(&c.OutputLevel, "output-level", 1, "actual requested output RNS level")
	flag.IntVar(&c.InputBits, "input-bits", 21, "")
	flag.IntVar(&c.OutputBits, "output-bits", 21, "")
	flag.IntVar(&c.EMBits, "em-bits", 20, "")
	flag.IntVar(&c.OutputPrimeBits, "output-prime-bits", 21, "bit target for additional output primes")
	flag.IntVar(&c.Degree, "degree", 31, "")
	flag.IntVar(&c.DoubleAngle, "double-angle", 3, "")
	flag.IntVar(&c.InverseDegree, "inverse-degree", 0, "arcsin degree; consumes extra polynomial depth")
	flag.IntVar(&c.InverseInputBits, "inverse-input-bits", 0, "actual intermediate sine scale before arcsin; 0 preserves old target")
	flag.IntVar(&c.K, "k", 17, "")
	flag.IntVar(&c.RatioBits, "ratio-bits", 4, "")
	flag.IntVar(&c.MainH, "main-h", 1024, "")
	flag.IntVar(&c.SparseH, "sparse-h", 32, "")
	flag.IntVar(&c.MainBase, "main-base", 9, "")
	flag.IntVar(&c.EntryBase, "entry-base", 1, "")
	flag.Uint64Var(&c.Q0, "q0", 7340033, "")
	flag.Uint64Var(&c.Qout, "qout", 786433, "")
	flag.Uint64Var(&c.MainP, "main-p", 65537, "")
	flag.Uint64Var(&c.SmallP, "entry-p", 8191, "0 uses ordinary no-P same-ring SSE")
	flag.Uint64Var(&c.WorkPrime, "work-prime", 5767169, "public CRT arithmetic modulus only, not an RLWE sample")
	flag.StringVar(&c.QChain, "q-chain", "", "explicit comma-separated Q primes overriding automatic Q generation")
	flag.StringVar(&c.ChainMode, "chain", "small", "small (smallest admissible primes) or uniform (near EM bits)")
	flag.StringVar(&c.Mod1Family, "mod1-family", "continuous", "")
	flag.StringVar(&c.UnitFile, "units", "units-weak.json", "")
	flag.Int64Var(&c.Seed, "seed", 2026102401, "payload and tie seed; cryptographic key randomness remains independent")
	flag.Float64Var(&c.Amplitude, "amplitude", 0.2, "real/imag independent uniform [-amplitude,amplitude]")
	flag.BoolVar(&c.CheckSquare, "check-square", true, "")
	flag.BoolVar(&c.AllowSubunit, "allow-subunit", false, "")
	flag.BoolVar(&c.Diagnostics, "diagnostics", false, "extra deterministic rerun outside timed region, with ciphertext equality check")
	flag.StringVar(&output, "out", "direct.json", "")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments: %q; use --boolean=true syntax\n", flag.Args())
		os.Exit(2)
	}
	host, _ := os.Hostname()
	res := result{Config: c, Host: host, Started: time.Now().UTC().Format(time.RFC3339)}
	err := run(c, &res)
	res.Status = "executed"
	if err != nil {
		res.Status = "failed"
		res.Error = err.Error()
	}
	if e := os.MkdirAll(filepath.Dir(output), 0755); e != nil {
		panic(e)
	}
	f, e := os.Create(output)
	if e != nil {
		panic(e)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if e = enc.Encode(res); e != nil {
		panic(e)
	}
	if e = f.Close(); e != nil {
		panic(e)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
