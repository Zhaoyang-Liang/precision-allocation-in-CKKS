package main

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
	"sort"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
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
	SSEBase                                                                   int
	PairedTiming                                                              bool
	LaneWorkers                                                               int
	CalibrateApplicationScale                                                 bool
	OutputScaleOffset                                                         float64
	NoRS                                                                      bool
	Statistics, ApplicationBeforeReturn                                       bool
	InverseSqrtIterations                                                     int
	ActiveBranches                                                            int
	RefreshDummy                                                              bool
	ChainLength                                                               int
	ChainPhase                                                                float64
	ChainFactorShape                                                          bool
	LogN, Logn, KMessages, R, Power, Trials, Workers, OutputLevel             int
	Q0Bits, InputBits, OutputBits, EMBits, EvalQBits, CtSQBits, PBits, PCount int
	Degree, DA, InverseDegree, KMod1, RatioBits, SparseH, TargetBits          int
	Seed                                                                      int64
	Amplitude                                                                 float64
	UnitFile                                                                  string
	DryRun, CheckSquare, Diagnostics, ShapeEntry, AllowSubunit, ShapeCtS      bool
}
type state struct {
	Level          int
	LogQ, LogScale float64
	QPrimes        []uint64
}
type metric struct {
	MaxAbsError, MeanAbsError, RMSError, MaxErrorBits, MeanErrorBits, RMSBits, GuardMax, DataMax float64
	DataSlots                                                                                    int
}
type stage struct {
	Name              string
	Lane              int
	State             state
	DataMax, GuardMax float64
}
type branchResult struct {
	Skipped                                                                                           bool
	SkipReason                                                                                        string
	Index                                                                                             int
	Input, StC, SSE, Lift, CtSReal, Output                                                            state
	InputMetrics, OutputMetrics                                                                       metric
	Beta                                                                                              float64
	EntrySeconds, StCSeconds, SSESeconds, LiftTraceSeconds, CtSSeconds, EvalModSeconds, OnlineSeconds float64
	Arithmetic                                                                                        lb.ShapedStats
	Stages                                                                                            []stage
	ReadoutDiagnosticsAvailable, CarryDomainCovered                                                   bool
	MaxCarryAbs, ReadoutMessageError, PureApproximationError, OracleVsMessageError                    float64
}
type trialResult struct {
	SerialOnlineSeconds, ParallelOnlineSeconds, SerialApplicationSeconds, SerialPipelineSeconds, ParallelPipelineSeconds float64
	PairedCiphertextsEqual                                                                                               bool
	TimingOrder                                                                                                          string
	RefreshedBranches                                                                                                    int
	SkippedBranchIndices                                                                                                 []int
	ApplicationChain                                                                                                     ApplicationChainResult
	Frontend                                                                                                             StatisticsFrontendResult
	InverseSqrt                                                                                                          InverseSqrtApplicationResult
	OutputLocation                                                                                                       string
	Final                                                                                                                state
	FinalMetrics                                                                                                         metric
	FinalMeetsTarget                                                                                                     bool
	PipelineOnlineSeconds                                                                                                float64
	Index                                                                                                                int
	Error                                                                                                                string
	Initial, PreBootstrap, InternalMaximum, Output, AfterSquare                                                          state
	InputMetrics, OutputMetrics, SquareMetrics                                                                           metric
	InitialQGreaterThanOutputQ, PreBootstrapQGreaterThanOutputQ, MeetsTarget, SquareMeetsTarget                          bool
	OutputMinusInputQBits                                                                                                float64
	EntrySplitSeconds, LeafsSeconds, MergeReturnSeconds, OnlineSeconds, SquareSeconds                                    float64
	Branches                                                                                                             []branchResult
}
type result struct {
	ActiveBranches, LogicalMessages                                                                                          int
	FrontendKeyBytes, ReturnKeyLevel                                                                                         int
	CasesApplicationMeetingTarget                                                                                            int
	CasesChainComplete, CasesChainMeetingTarget                                                                              int
	Status, Error, Host, Started, Scope, PayloadDescription, SecretDescription                                               string
	Config                                                                                                                   config
	QPrimes, PPrimes                                                                                                         []uint64
	MainQBits, MainQPBits, EntryQPBits, InputQBits, OutputQBits, ReturnQPBits                                                float64
	MainReferenceCap, EntryReferenceCap                                                                                      int
	ReferenceTableFits                                                                                                       bool
	MainLevel, InputLevel, OutputLevel, EvalModLevel, EvalModDepth, InverseDepth, Branches, TotalMessages, TraceMultiplicity int
	UnitFocus, FocusSuppressionBits, CtSGain, MaxStCDiagonal, MaxCtSDiagonal                                                 float64
	StCDiagonals, CtSDiagonals, MainGaloisKeyCount                                                                           int
	MainKeyBytes, EntryKeyBytes, SSEKeyBytes, LiftKeyBytes, ReturnKeyBytes, ApplicationKeyBytes, MatrixBytes                 int
	KeygenSeconds, MatrixSeconds, TotalSeconds                                                                               float64
	GOMAXPROCS, CasesExecuted, CasesFailed, CasesMeetingTarget                                                               int
	Trials                                                                                                                   []trialResult
}

func ctState(p ckks.Parameters, ct *rlwe.Ciphertext) state {
	return state{Level: ct.Level(), LogQ: logProduct(p.Q()[:ct.Level()+1]), LogScale: scaleLog(ct.Scale), QPrimes: append([]uint64(nil), p.Q()[:ct.Level()+1]...)}
}
func metrics(v, w []complex128, R int) (metric, error) {
	m := metric{}
	if len(v) != len(w) {
		return m, fmt.Errorf("metric dimension mismatch")
	}
	for j, x := range v {
		if math.IsNaN(cmplx.Abs(x)) || math.IsInf(cmplx.Abs(x), 0) {
			return m, fmt.Errorf("nonfinite decoded value")
		}
		if j%R == 0 {
			e := cmplx.Abs(x - w[j])
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
	return m, nil
}
func measure(p ckks.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, w []complex128, R int) (metric, error) {
	v, e := decode(p, sk, ct)
	if e != nil {
		return metric{}, e
	}
	return metrics(v, w, R)
}
func identityUnit(R int) unitSpec {
	u := unitSpec{R: R, Focus: "1", Coeffs: make([]string, 2*R), Inverse: make([]string, 2*R)}
	for i := range u.Coeffs {
		u.Coeffs[i], u.Inverse[i] = "0", "0"
	}
	u.Coeffs[0], u.Inverse[0] = "1", "1"
	return u
}
func loadUnit(c config) (unitSpec, error) {
	if c.Power == 0 {
		return identityUnit(c.R), nil
	}
	b, e := os.ReadFile(c.UnitFile)
	if e != nil {
		return unitSpec{}, e
	}
	var units []unitSpec
	if e = json.Unmarshal(b, &units); e != nil {
		return unitSpec{}, e
	}
	for _, u := range units {
		if u.R == c.R {
			return unitPower(u, c.Power)
		}
	}
	return unitSpec{}, fmt.Errorf("R%d missing from unit file", c.R)
}
func parameters(c config) (top, main, entryLeaf, low ckks.Parameters, lit mod1.ParametersLiteral, err error) {
	if c.NoRS != (c.LogN == c.Logn) || (c.NoRS && c.ActiveBranches > 1) {
		err = fmt.Errorf("no-rs requires equal dimensions and one active branch; ring switching requires unequal dimensions")
		return
	}
	if c.ActiveBranches < 0 || (c.LogN > c.Logn && c.ActiveBranches > 1<<(c.LogN-c.Logn)) {
		err = fmt.Errorf("invalid active branch count")
		return
	}
	if c.Statistics && (c.ActiveBranches != 1 || !c.ShapeEntry || c.InputBits != 40) {
		err = fmt.Errorf("statistics requires one active branch, shaped entry, input bits40")
		return
	}
	if c.InverseSqrtIterations != 0 && (!c.Statistics || c.InverseSqrtIterations < 2 || c.OutputLevel < 2*c.InverseSqrtIterations-1 || c.CheckSquare || c.ChainLength != 0) {
		err = fmt.Errorf("inverse sqrt requires statistics, enough levels, and exclusive application mode")
		return
	}
	if c.ApplicationBeforeReturn && c.InverseSqrtIterations == 0 {
		err = fmt.Errorf("application-before-return requires inverse sqrt")
		return
	}
	if c.ChainLength < -1 || c.ChainLength > c.OutputLevel {
		err = fmt.Errorf("invalid application chain length")
		return
	}
	if c.LogN < c.Logn || c.Logn < 5 || c.KMessages < 1 || c.KMessages&(c.KMessages-1) != 0 || c.R < 1 || c.R&(c.R-1) != 0 || c.KMessages%c.R != 0 || c.KMessages*c.R > 1<<(c.Logn-1) || c.OutputLevel < 1 || c.Trials < 1 || c.Workers < 1 || c.PCount < 1 || c.SparseH > 1<<c.Logn || c.Power < 0 || c.Power > 6 {
		err = fmt.Errorf("invalid dimensions/classes/levels/counts")
		return
	}
	lit = mod1.ParametersLiteral{LogScale: c.EMBits, Mod1Type: mod1.CosContinuous, LogMessageRatio: c.RatioBits, K: c.KMod1, Mod1Degree: c.Degree, DoubleAngle: c.DA, Mod1InvDegree: c.InverseDegree}
	qs, ps := []uint64{}, []uint64{}
	used := map[uint64]bool{}
	generators := map[int]*ring.NTTFriendlyPrimesGenerator{}
	next := func(bits int) (uint64, error) {
		g, ok := generators[bits]
		if !ok {
			x := ring.NewNTTFriendlyPrimesGenerator(uint64(bits), uint64(2<<c.LogN))
			g = &x
			generators[bits] = g
		}
		for {
			q, e := g.NextUpstreamPrime()
			if e != nil {
				return 0, e
			}
			if !used[q] {
				used[q] = true
				return q, nil
			}
		}
	}
	q, e := next(c.Q0Bits)
	if e != nil {
		err = e
		return
	}
	qs = append(qs, q)
	for i := 0; i < c.OutputLevel; i++ {
		q, e = next(c.OutputBits)
		if e != nil {
			err = e
			return
		}
		qs = append(qs, q)
	}
	for i := 0; i < lit.Depth(); i++ {
		q, e = next(c.EvalQBits)
		if e != nil {
			err = e
			return
		}
		qs = append(qs, q)
	}
	q, e = next(c.CtSQBits)
	if e != nil {
		err = e
		return
	}
	qs = append(qs, q)
	for i := 0; i < c.PCount; i++ {
		q, e = next(c.PBits)
		if e != nil {
			err = e
			return
		}
		ps = append(ps, q)
	}
	dist := ring.Ternary{P: 2.0 / 3.0}
	main, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: qs, P: ps, LogDefaultScale: c.EMBits, Xs: dist})
	if err != nil {
		return
	}
	top, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.LogN, Q: qs[:c.OutputLevel+1], P: ps, LogDefaultScale: c.OutputBits, Xs: dist})
	if err != nil {
		return
	}
	entryLeaf, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: qs[:2], P: ps, LogDefaultScale: c.InputBits, Xs: dist})
	if err != nil {
		return
	}
	low, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: qs[:1], P: ps, LogDefaultScale: c.InputBits, Xs: ring.Ternary{H: c.SparseH}})
	lit.LevelQ = main.MaxLevel() - 1
	lit.Scaling = math.Exp2(math.Round(math.Log2(float64(qs[0])))) / float64(qs[0])
	return
}
func maxDiagonal(diags lintrans.Diagonals[complex128]) float64 {
	m := 0.0
	for _, d := range diags {
		for _, v := range d {
			m = math.Max(m, cmplx.Abs(v))
		}
	}
	return m
}
func plainCipher(p ckks.Parameters, v []complex128, level int, scale rlwe.Scale) (*rlwe.Ciphertext, error) {
	pt := ckks.NewPlaintext(p, level)
	pt.Scale = scale
	if e := ckks.NewEncoder(p, 128).Encode(v, pt); e != nil {
		return nil, e
	}
	ct := ckks.NewCiphertext(p, 0, level)
	ct.MetaData = pt.MetaData.CopyNew()
	ct.Value[0].Copy(pt.Value)
	return ct, nil
}
func decodePlain(p ckks.Parameters, ct *rlwe.Ciphertext) ([]complex128, error) {
	pt := ckks.NewPlaintext(p, ct.Level())
	pt.MetaData = ct.MetaData.CopyNew()
	pt.Value.Copy(ct.Value[0])
	v := make([]complex128, p.MaxSlots())
	e := ckks.NewEncoder(p, 128).Decode(pt, v)
	return v, e
}
func runIndexed(count, workers int, fn func(int) error) error {
	errs := make([]error, count)
	var wg sync.WaitGroup
	for w := 0; w < min(count, workers); w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < count; i += workers {
				errs[i] = fn(i)
			}
		}(w)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			return fmt.Errorf("branch %d: %w", i, e)
		}
	}
	return nil
}

type engine struct {
	c             config
	main, low     ckks.Parameters
	base          *ckks.Evaluator
	shape         *lb.ShapedEvaluator
	laneShapes    [2]*lb.ShapedEvaluator
	linear        *lintrans.Evaluator
	switcher      *rlwe.Evaluator
	stc, cts      lintrans.LinearTransformation
	plan          mod1.Parameters
	sse, lift     *rlwe.EvaluationKey
	plusI, minusI []*big.Int
}

func (e *engine) refresh(input *rlwe.Ciphertext, index int, hook func(string, int, *rlwe.Ciphertext) error) (out *rlwe.Ciphertext, br branchResult, err error) {
	begin := time.Now()
	defer func() { br.OnlineSeconds = time.Since(begin).Seconds() }()
	br.Index = index
	br.Input = ctState(e.main, input)
	e.shape.Stats = lb.ShapedStats{}
	mark := func(name string, lane int, ct *rlwe.Ciphertext) error {
		if hook != nil {
			return hook(name, lane, ct)
		}
		return nil
	}
	t := time.Now()
	stc, err := e.linear.EvaluateNew(input, e.stc)
	if err != nil {
		return nil, br, fmt.Errorf("StC: %w", err)
	}
	if err = e.base.Rescale(stc, stc); err != nil {
		return nil, br, err
	}
	br.StCSeconds = time.Since(t).Seconds()
	br.StC = ctState(e.main, stc)
	br.Beta = float64(e.main.Q()[0]) / stc.Scale.Float64()
	if err = mark("StC", -1, stc); err != nil {
		return
	}
	t = time.Now()
	lowCT := ckks.NewCiphertext(e.low, 1, 0)
	if err = e.switcher.ApplyEvaluationKey(stc, e.sse, lowCT); err != nil {
		return
	}
	br.SSESeconds = time.Since(t).Seconds()
	br.SSE = ctState(e.low, lowCT)
	if err = mark("SSE", -1, lowCT); err != nil {
		return
	}
	t = time.Now()
	coeffs, err := lb.CenteredCiphertextComponents(e.low, lowCT)
	if err != nil {
		return
	}
	lifted := ckks.NewCiphertext(e.main, 1, e.main.MaxLevel())
	lifted.MetaData = lowCT.MetaData.CopyNew()
	lifted.Scale = rlwe.NewScale(math.Exp2(float64(e.c.EMBits)))
	for component := range coeffs {
		lifted.Value[component], err = lb.PolynomialFromCoefficients(e.main, coeffs[component], e.main.MaxLevel(), true, false)
		if err != nil {
			return
		}
	}
	liftedOut := lifted.CopyNew()
	if err = e.switcher.ApplyEvaluationKey(lifted, e.lift, liftedOut); err != nil {
		return
	}
	lifted = liftedOut
	for rotation := e.c.KMessages; rotation < e.main.MaxSlots(); rotation *= 2 {
		rotated, er := e.base.RotateNew(lifted, rotation)
		if er != nil {
			err = er
			return
		}
		if err = e.base.Add(lifted, rotated, lifted); err != nil {
			return
		}
	}
	br.LiftTraceSeconds = time.Since(t).Seconds()
	br.Lift = ctState(e.main, lifted)
	if err = mark("lift_raw_trace", -1, lifted); err != nil {
		return
	}
	t = time.Now()
	ct, err := e.linear.EvaluateNew(lifted, e.cts)
	if err != nil {
		return nil, br, fmt.Errorf("CtS: %w", err)
	}
	if err = mark("CtS_complex_wide", -1, ct); err != nil {
		return
	}
	conj, err := e.base.ConjugateNew(ct)
	if err != nil {
		return
	}
	re, err := e.base.AddNew(ct, conj)
	if err != nil {
		return
	}
	diff, err := e.base.SubNew(ct, conj)
	if err != nil {
		return
	}
	im, err := lb.MulIntegerPolynomial(e.main, diff, e.minusI)
	if err != nil {
		return
	}
	if err = mark("CtS_real_wide", 0, re); err != nil {
		return
	}
	if err = e.shape.Rescale(re, re); err != nil {
		return
	}
	if err = e.shape.Rescale(im, im); err != nil {
		return
	}
	br.CtSSeconds = time.Since(t).Seconds()
	br.CtSReal = ctState(e.main, re)
	if err = mark("CtS_real", 0, re); err != nil {
		return
	}
	if err = mark("CtS_imag", 1, im); err != nil {
		return
	}
	t = time.Now()
	lanes := []*rlwe.Ciphertext{re, im}
	workers := e.c.LaneWorkers
	if hook != nil {
		workers = 1
	}
	for _, shape := range e.laneShapes {
		shape.Stats = lb.ShapedStats{}
	}
	err = lb.RunTwoLanes(workers, func(lane int) error {
		v := lanes[lane]
		shape := e.laneShapes[lane]
		var err error
		var stageHook lb.ShapedStageHook
		if hook != nil {
			stageHook = func(name string, x *rlwe.Ciphertext) error { return mark(name, lane, x) }
		}
		lanes[lane], err = lb.EvaluateShapedMod1(shape, v, e.plan, rlwe.NewScale(br.Beta*math.Exp2(float64(e.c.OutputBits)+e.c.OutputScaleOffset)), true, stageHook)
		if err != nil {
			return fmt.Errorf("EvalMod lane%d: %w", lane, err)
		}
		lanes[lane].Scale = lanes[lane].Scale.Div(rlwe.NewScale(br.Beta))
		if e.plan.DoubleAngle > 0 && e.plan.Mod1InvPoly == nil {
			if err = shape.Rescale(lanes[lane], lanes[lane]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, br, err
	}
	for _, shape := range e.laneShapes {
		lb.AddShapedStats(&e.shape.Stats, shape.Stats)
	}
	imagCT, err := lb.MulIntegerPolynomial(e.main, lanes[1], e.plusI)
	if err != nil {
		return
	}
	out, err = e.base.AddNew(lanes[0], imagCT)
	br.EvalModSeconds = time.Since(t).Seconds()
	if err != nil {
		return
	}
	br.Output = ctState(e.main, out)
	br.Arithmetic = e.shape.Stats
	if out.Level() != e.c.OutputLevel {
		return nil, br, fmt.Errorf("output level%d wanted%d", out.Level(), e.c.OutputLevel)
	}
	return
}

func run(c config, res *result) (err error) {
	start := time.Now()
	defer func() { res.TotalSeconds = time.Since(start).Seconds() }()
	top, main, entryLeaf, low, lit, err := parameters(c)
	if err != nil {
		return err
	}
	if c.ActiveBranches == 0 {
		c.ActiveBranches = top.N() / main.N()
	}
	if c.InverseSqrtIterations != 0 && c.CalibrateApplicationScale {
		c.OutputScaleOffset = inverseSqrtInitialLogScale(main.Q(), c.OutputLevel, c.InverseSqrtIterations, float64(c.OutputBits)) - float64(c.OutputBits)
	}
	res.Config = c
	res.Scope = "full split -> same-ring small-batch fiber StC/SSE/lift/CtS/PA EvalMod -> full merge/return KS"
	if c.NoRS {
		res.Scope = "direct same-ring PA fiber bootstrap; no entry/return key switch, no Split/Merge"
	}
	res.PayloadDescription = fmt.Sprintf("%d independent complex messages per active leaf; public active prefix of %d/%d coefficient branches; focus positions (slot/R) mod k; other branches ideal zero", c.KMessages, c.ActiveBranches, top.N()/main.N())
	res.SecretDescription = "main/top uniform ternary P(nonzero)=2/3; ephemeral same-ring SSE fixed H with independent random signs"
	res.QPrimes, res.PPrimes = main.Q(), main.P()
	res.MainQBits = logProduct(main.Q())
	res.MainQPBits = res.MainQBits + logProduct(main.P())
	res.EntryQPBits = math.Log2(float64(main.Q()[0])) + logProduct(main.P())
	res.InputQBits = logProduct(main.Q()[:2])
	res.OutputQBits = logProduct(top.Q())
	res.ReturnQPBits = res.OutputQBits + logProduct(top.P())
	res.MainLevel = main.MaxLevel()
	res.InputLevel = 1
	res.OutputLevel = c.OutputLevel
	res.EvalModLevel = lit.LevelQ
	res.EvalModDepth = lit.Depth()
	res.Branches = top.N() / main.N()
	res.TotalMessages = c.ActiveBranches * c.KMessages
	res.ActiveBranches, res.LogicalMessages = c.ActiveBranches, res.TotalMessages
	res.TraceMultiplicity = main.MaxSlots() / c.KMessages
	res.GOMAXPROCS = runtime.GOMAXPROCS(0)
	if c.Logn == 15 && c.SparseH == 32 {
		res.MainReferenceCap = 868
		res.EntryReferenceCap = 162
		res.ReferenceTableFits = res.MainQPBits <= 868 && res.EntryQPBits <= 162
	}
	res.CtSGain = math.Exp2(float64(c.EMBits)) / (2 * float64(main.Q()[0]) * float64(c.KMod1) * float64(res.TraceMultiplicity))
	res.InverseDepth = 0
	if c.InverseDegree > 0 {
		res.InverseDepth = int(math.Ceil(math.Log2(float64(c.InverseDegree + 1))))
	}
	if c.DryRun {
		res.Status = "dry_run"
		return nil
	}
	u, err := loadUnit(c)
	if err != nil {
		return err
	}
	gf := f64(u.Focus)
	res.UnitFocus = gf
	res.FocusSuppressionBits = -math.Log2(gf)
	ul, il := embed(u.Coeffs, main.N()), embed(u.Inverse, main.N())
	ut, it := embed(u.Coeffs, top.N()), embed(u.Inverse, top.N())
	matrixStart := time.Now()
	stcD, err := lb.FiberDiagonals(main.MaxSlots(), c.KMessages, c.R, false, 1)
	if err != nil {
		return err
	}
	ctsD, err := lb.FiberDiagonals(main.MaxSlots(), c.KMessages, c.R, true, res.CtSGain)
	if err != nil {
		return err
	}
	res.StCDiagonals, res.CtSDiagonals = len(stcD), len(ctsD)
	res.MaxStCDiagonal, res.MaxCtSDiagonal = maxDiagonal(stcD), maxDiagonal(ctsD)
	stc, err := lb.NewFiberMatrix(main, stcD, 1, rlwe.NewScale(main.Q()[1]))
	if err != nil {
		return err
	}
	var cts lintrans.LinearTransformation
	if c.ShapeCtS {
		focus, _, parseErr := big.ParseFloat(u.Focus, 10, 192, big.ToNearestEven)
		if parseErr != nil {
			return parseErr
		}
		cts, err = lb.NewShapedFiberMatrix(main, ctsD, main.MaxLevel(), rlwe.NewScale(main.Q()[main.MaxLevel()]), c.R, ul, focus)
	} else {
		cts, err = lb.NewFiberMatrix(main, ctsD, main.MaxLevel(), rlwe.NewScale(main.Q()[main.MaxLevel()]))
	}
	if err != nil {
		return err
	}
	for _, m := range []lintrans.LinearTransformation{stc, cts} {
		for _, poly := range m.Vec {
			res.MatrixBytes += poly.BinarySize()
		}
	}
	res.MatrixSeconds = time.Since(matrixStart).Seconds()
	keyStart := time.Now()
	kt, km := rlwe.NewKeyGenerator(top), rlwe.NewKeyGenerator(main)
	st := kt.GenSecretKeyNew()
	var sm *rlwe.SecretKey
	if c.NoRS {
		sm, err = lb.RebaseSecretKey(top, main, st)
		if err != nil {
			return err
		}
	} else {
		sm = km.GenSecretKeyNew()
	}
	sl := rlwe.NewKeyGenerator(low).GenSecretKeyWithHammingWeightNew(c.SparseH)
	se, err := lb.RebaseSecretKey(main, entryLeaf, sm)
	if err != nil {
		return err
	}
	var entry *lb.RingEntry
	if !c.NoRS {
		entry, err = lb.NewRingEntry(top, entryLeaf, st, se, 1, top.MaxLevelP(), 0)
		if err != nil {
			return err
		}
		res.EntryKeyBytes = entry.Key.BinarySize()
	}
	lq, lp, baseTwo := 0, low.MaxLevelP(), c.SSEBase
	if err = lb.ValidateBaseTwoDecompositionCoverage(low, lq, lp, baseTwo); err != nil {
		return err
	}
	sseKey := rlwe.NewKeyGenerator(low).GenEvaluationKeyNew(sm, sl, rlwe.EvaluationKeyParameters{LevelQ: &lq, LevelP: &lp, BaseTwoDecomposition: &baseTwo})
	res.SSEKeyBytes = sseKey.BinarySize()
	sparseHigh, err := lb.RebaseSecretKey(low, main, sl)
	if err != nil {
		return err
	}
	liftKey := km.GenEvaluationKeyNew(sparseHigh, sm)
	res.LiftKeyBytes = liftKey.BinarySize()
	galSet := map[uint64]bool{main.GaloisElementForComplexConjugation(): true}
	for _, x := range stc.GaloisElements(main) {
		galSet[x] = true
	}
	for _, x := range cts.GaloisElements(main) {
		galSet[x] = true
	}
	for stride := c.KMessages; stride < main.MaxSlots(); stride *= 2 {
		galSet[main.GaloisElementForRotation(stride)] = true
	}
	galEls := make([]uint64, 0, len(galSet))
	for g := range galSet {
		galEls = append(galEls, g)
	}
	sort.Slice(galEls, func(i, j int) bool { return galEls[i] < galEls[j] })
	gals := km.GenGaloisKeysNew(galEls, sm)
	relin := km.GenRelinearizationKeyNew(sm)
	keys := rlwe.NewMemEvaluationKeySet(relin, gals...)
	res.MainKeyBytes = relin.BinarySize()
	for _, g := range gals {
		res.MainKeyBytes += g.BinarySize()
	}
	res.MainGaloisKeyCount = len(gals)
	retLeaf, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: c.Logn, Q: top.Q(), P: top.P(), LogDefaultScale: c.OutputBits, Xs: ring.Ternary{P: 2.0 / 3.0}})
	if err != nil {
		return err
	}
	sr, err := lb.RebaseSecretKey(main, retLeaf, sm)
	if err != nil {
		return err
	}
	var returnKey *rlwe.EvaluationKey
	if !c.NoRS {
		res.ReturnKeyLevel = c.OutputLevel
		if c.ApplicationBeforeReturn {
			res.ReturnKeyLevel -= 2*c.InverseSqrtIterations - 1
		}
		res.ReturnQPBits = logProduct(top.Q()[:res.ReturnKeyLevel+1]) + logProduct(top.P())
		returnKey = kt.GenEvaluationKeyNew(sr, st, rlwe.EvaluationKeyParameters{LevelQ: &res.ReturnKeyLevel})
		res.ReturnKeyBytes = returnKey.BinarySize()
	}
	returnEval := rlwe.NewEvaluator(top, nil)
	var app *lb.ShapedEvaluator
	if c.CheckSquare || c.ChainLength != 0 || (c.InverseSqrtIterations != 0 && !c.ApplicationBeforeReturn) {
		rk := relin
		if !c.NoRS {
			rk = kt.GenRelinearizationKeyNew(st)
			res.ApplicationKeyBytes = rk.BinarySize()
		}
		app, err = lb.NewShapedEvaluator(top, ckks.NewEvaluator(top, rlwe.NewMemEvaluationKeySet(rk)), ut, it, c.R, complex(gf, 0))
		if err != nil {
			return err
		}
	}
	plusI, minusI := make([]*big.Int, main.N()), make([]*big.Int, main.N())
	for i := range plusI {
		plusI[i], minusI[i] = new(big.Int), new(big.Int)
	}
	plusI[main.N()/2].SetInt64(1)
	minusI[main.N()/2].SetInt64(-1)
	engines := make([]*engine, res.Branches)
	for b := range engines {
		base := ckks.NewEvaluator(main, keys)
		shape, e := lb.NewShapedEvaluator(main, base, ul, il, c.R, complex(gf, 0))
		if e != nil {
			return e
		}
		shape.AllowSubunitCoefficientScale = c.AllowSubunit
		plan, e := mod1.NewParametersFromLiteral(main, lit)
		if e != nil {
			return e
		}
		engines[b] = &engine{laneShapes: [2]*lb.ShapedEvaluator{lb.ForkShapedEvaluator(shape), lb.ForkShapedEvaluator(shape)}, c: c, main: main, low: low, base: base, shape: shape, linear: lintrans.NewEvaluator(base), switcher: rlwe.NewEvaluator(main, nil), stc: stc, cts: cts, plan: plan, sse: sseKey, lift: liftKey, plusI: plusI, minusI: minusI}
	}
	var frontend *StatisticsFrontend
	if c.Statistics {
		frontend, err = NewStatisticsFrontend(top, st, ut, it, c.R, c.KMessages, complex(gf, 0))
		if err != nil {
			return err
		}
		res.FrontendKeyBytes = frontend.setup.KeyBytes
		res.PayloadDescription = fmt.Sprintf("%d dense real samples -> %d mean squares x -> t=x/32 in a periodic PA focus layout; one ideal nonzero coefficient branch", top.MaxSlots(), c.KMessages)
	}
	res.KeygenSeconds = time.Since(keyStart).Seconds()
	fmt.Printf("fiber N=%d n=%d k=%d R=%d depth=%d outputL=%d mainQP=%.6f SSEQP=%.6f keys=%d\n", top.N(), main.N(), c.KMessages, c.R, res.EvalModDepth, c.OutputLevel, res.MainQPBits, res.EntryQPBits, res.MainKeyBytes)
	rng := rand.New(rand.NewSource(c.Seed))
	inputScale := rlwe.NewScale(math.Exp2(float64(c.InputBits)))
	for trial := 0; trial < c.Trials; trial++ {
		tr := trialResult{Index: trial + 1, Branches: make([]branchResult, res.Branches)}
		trialErr := func() error {
			wants := make([][]complex128, res.Branches)
			var ct *rlwe.Ciphertext
			var wantTop []complex128
			var e error
			if frontend != nil {
				targets := scenarioTargets(c.KMessages, c.InverseSqrtIterations)
				ct, wantTop, tr.Frontend, e = frontend.Run(c.Seed+int64(trial), targets)
				if e != nil {
					return e
				}
				for b := range wants {
					wants[b] = make([]complex128, main.MaxSlots())
					if b == 0 {
						for j := 0; j < len(wants[b]); j += c.R {
							wants[b][j] = complex(tr.Frontend.IndependentMeanSquares[(j/c.R)%c.KMessages]/32, 0)
						}
					}
				}
			} else {
				inversePlains, idealPlains := make([]*rlwe.Ciphertext, res.Branches), make([]*rlwe.Ciphertext, res.Branches)
				for b := range wants {
					messages := make([]complex128, c.KMessages)
					for j := range messages {
						if b < c.ActiveBranches {
							messages[j] = complex((rng.Float64()*2-1)*c.Amplitude, (rng.Float64()*2-1)*c.Amplitude)
						}
					}
					wants[b] = make([]complex128, main.MaxSlots())
					inv := make([]complex128, main.MaxSlots())
					for s := 0; s < main.MaxSlots(); s += c.R {
						wants[b][s] = messages[(s/c.R)%c.KMessages]
						inv[s] = wants[b][s] / complex(gf, 0)
					}
					var e error
					inversePlains[b], e = plainCipher(entryLeaf, inv, 1, inputScale)
					if e != nil {
						return e
					}
					idealPlains[b], e = plainCipher(entryLeaf, wants[b], 1, inputScale)
					if e != nil {
						return e
					}
				}
				mergedPlain, e := mergeOrIdentity(top, entryLeaf, inversePlains)
				if e != nil {
					return e
				}
				pt := ckks.NewPlaintext(top, 1)
				pt.MetaData = mergedPlain.MetaData.CopyNew()
				pt.Value.Copy(mergedPlain.Value[0])
				ct, e = rlwe.NewEncryptor(top, st).EncryptNew(pt)
				if e != nil {
					return e
				}
				ct, e = lb.MulIntegerPolynomial(top, ct, ut)
				if e != nil {
					return e
				}
				ideal, e := mergeOrIdentity(top, entryLeaf, idealPlains)
				if e != nil {
					return e
				}
				wantTop, e = decodePlain(top, ideal)
				if e != nil {
					return e
				}
			}
			tr.Initial = ctState(top, ct)
			tr.PreBootstrap = tr.Initial
			tr.InternalMaximum = state{Level: main.MaxLevel(), LogQ: res.MainQBits, LogScale: float64(c.EMBits), QPrimes: append([]uint64(nil), main.Q()...)}
			tr.InputMetrics, e = measure(top, st, ct, wantTop, c.R)
			if e != nil {
				return e
			}

			onlineRun := func(laneWorkers int) (*rlwe.Ciphertext, []*rlwe.Ciphertext, []*rlwe.Ciphertext, error) {
				for _, engine := range engines {
					engine.c.LaneWorkers = laneWorkers
				}
				tr.SkippedBranchIndices = nil
				tr.Branches = make([]branchResult, res.Branches)
				t := time.Now()
				entryInput := ct
				if c.ShapeEntry && !c.NoRS {
					entryInput, e = lb.MulIntegerPolynomial(top, ct, it)
					if e != nil {
						return nil, nil, nil, e
					}
				}
				var leaves []*rlwe.Ciphertext
				if c.NoRS {
					leaves = []*rlwe.Ciphertext{entryInput.CopyNew()}
				} else {
					leaves, e = entry.ApplyAll(entryInput)
					if e != nil {
						return nil, nil, nil, e
					}
				}
				if c.ShapeEntry && !c.NoRS {
					for b := range leaves {
						leaves[b], e = lb.MulIntegerPolynomial(main, leaves[b], ul)
						if e != nil {
							return nil, nil, nil, e
						}
					}
				}
				tr.EntrySplitSeconds = time.Since(t).Seconds()
				refreshed := make([]*rlwe.Ciphertext, res.Branches)
				refreshCount := c.ActiveBranches
				if c.RefreshDummy {
					refreshCount = res.Branches
				}
				tr.RefreshedBranches = refreshCount
				t = time.Now()
				e = runIndexed(refreshCount, c.Workers, func(b int) error {
					var e error
					refreshed[b], tr.Branches[b], e = engines[b].refresh(leaves[b], b, nil)
					return e
				})
				tr.LeafsSeconds = time.Since(t).Seconds()
				if e != nil {
					return nil, nil, nil, e
				}
				for b := refreshCount; b < res.Branches; b++ {
					refreshed[b] = zeroCiphertextLike(main, refreshed[0])
					tr.SkippedBranchIndices = append(tr.SkippedBranchIndices, b)
					tr.Branches[b] = branchResult{Index: b, Skipped: true, SkipReason: "public layout guarantees ideal branch message zero", Input: ctState(main, leaves[b]), Output: ctState(main, refreshed[b])}
				}
				returnInputs := refreshed
				if c.ApplicationBeforeReturn {
					returnInputs = make([]*rlwe.Ciphertext, res.Branches)
					leafApp, appErr := lb.NewShapedEvaluator(main, ckks.NewEvaluator(main, keys), ul, il, c.R, complex(gf, 0))
					if appErr != nil {
						return nil, nil, nil, appErr
					}
					returnInputs[0], tr.InverseSqrt, e = RunInverseSqrtApplication(main, sm, leafApp, refreshed[0], unscaleReference(wants[0], 32), InverseSqrtApplicationOptions{Iterations: c.InverseSqrtIterations, R: c.R, TargetBits: c.TargetBits})
					if e != nil {
						return nil, nil, nil, e
					}
					for b := 1; b < res.Branches; b++ {
						returnInputs[b] = zeroCiphertextLike(main, returnInputs[0])
					}
				}
				t = time.Now()
				var returned *rlwe.Ciphertext
				if c.NoRS {
					returned = returnInputs[0].CopyNew()
				} else {
					inverseOutputs := make([]*rlwe.Ciphertext, res.Branches)
					for b := range returnInputs {
						inverseOutputs[b], e = lb.MulIntegerPolynomial(main, returnInputs[b], il)
						if e != nil {
							return nil, nil, nil, e
						}
					}
					merged, e := lb.MergeCoefficientBranches(top, main, inverseOutputs)
					if e != nil {
						return nil, nil, nil, e
					}
					returned = ckks.NewCiphertext(top, 1, merged.Level())
					if e = returnEval.ApplyEvaluationKey(merged, returnKey, returned); e != nil {
						return nil, nil, nil, e
					}
					returned, e = lb.MulIntegerPolynomial(top, returned, ut)
					if e != nil {
						return nil, nil, nil, e
					}
				}
				tr.MergeReturnSeconds = time.Since(t).Seconds()
				tr.OnlineSeconds = tr.EntrySplitSeconds + tr.LeafsSeconds + tr.MergeReturnSeconds
				return returned, refreshed, leaves, nil
			}
			var returned *rlwe.Ciphertext
			var refreshed, leaves []*rlwe.Ciphertext
			if c.PairedTiming {
				savedProcs := runtime.GOMAXPROCS(0)
				if savedProcs < 2 {
					return fmt.Errorf("paired lane timing requires at least two CPU cores")
				}
				var serial, parallel *rlwe.Ciphertext
				var serialTime, serialApp float64
				var parallelTrial trialResult
				order := []int{1, 2}
				tr.TimingOrder = "serial,parallel"
				if trial%2 == 1 {
					order = []int{2, 1}
					tr.TimingOrder = "parallel,serial"
				}
				for _, mode := range order {
					runtime.GOMAXPROCS(mode)
					runtime.GC()
					returned, refreshed, leaves, e = onlineRun(mode)
					if e != nil {
						runtime.GOMAXPROCS(savedProcs)
						return e
					}
					if mode == 1 {
						serial = returned
						serialTime = tr.OnlineSeconds
						serialApp = tr.InverseSqrt.ArithmeticSeconds
					} else {
						parallel = returned
						parallelTrial = tr
					}
				}
				runtime.GOMAXPROCS(savedProcs)
				tr = parallelTrial
				tr.PairedCiphertextsEqual = serial.Equal(parallel)
				if !tr.PairedCiphertextsEqual {
					return fmt.Errorf("serial/parallel ciphertext mismatch")
				}
				returned = parallel
				tr.SerialOnlineSeconds, tr.ParallelOnlineSeconds = serialTime, tr.OnlineSeconds
				tr.SerialApplicationSeconds = serialApp
			} else {
				returned, refreshed, leaves, e = onlineRun(c.LaneWorkers)
				if e != nil {
					return e
				}
			}
			tr.OutputLocation = "top-ring bootstrap output before application"
			tr.Output = ctState(top, returned)
			if c.ApplicationBeforeReturn {
				tr.OutputLocation = "active leaf bootstrap output before application and return"
				tr.Output = ctState(main, refreshed[0])
				tr.OutputMetrics, e = measure(main, sm, refreshed[0], wants[0], c.R)
			} else {
				tr.OutputMetrics, e = measure(top, st, returned, wantTop, c.R)
			}
			if e != nil {
				return e
			}
			tr.MeetsTarget = tr.OutputMetrics.MaxErrorBits >= float64(c.TargetBits)
			tr.OutputMinusInputQBits = tr.Output.LogQ - tr.PreBootstrap.LogQ
			tr.InitialQGreaterThanOutputQ = tr.Initial.LogQ > tr.Output.LogQ+1e-9
			tr.PreBootstrapQGreaterThanOutputQ = tr.PreBootstrap.LogQ > tr.Output.LogQ+1e-9
			for b := range leaves {
				tr.Branches[b].InputMetrics, e = measure(main, sm, leaves[b], wants[b], c.R)
				if e != nil {
					return e
				}
				tr.Branches[b].OutputMetrics, e = measure(main, sm, refreshed[b], wants[b], c.R)
				if e != nil {
					return e
				}
				if c.Diagnostics && !tr.Branches[b].Skipped {
					tr.Branches[b].CarryDomainCovered = true
					diag, _, e := engines[b].refresh(leaves[b], b, func(name string, lane int, x *rlwe.Ciphertext) error {
						secret := sm
						if name == "SSE" {
							secret = sl
						}
						v, e := decode(main, secret, x)
						if e != nil {
							return e
						}
						if name == "CtS_real" || name == "CtS_imag" {
							br := &tr.Branches[b]
							br.ReadoutDiagnosticsAvailable = true
							for j := 0; j < len(v); j += c.R {
								want := real(wants[b][j])
								if lane == 1 {
									want = imag(wants[b][j])
								}
								lifted := float64(c.KMod1) * real(v[j])
								carry := math.Round(lifted - want/br.Beta)
								br.MaxCarryAbs = math.Max(br.MaxCarryAbs, math.Abs(carry))
								br.ReadoutMessageError = math.Max(br.ReadoutMessageError, cmplx.Abs(complex(br.Beta, 0)*(complex(float64(c.KMod1), 0)*v[j]-complex(carry, 0))-complex(want, 0)))
								br.CarryDomainCovered = br.CarryDomainCovered && math.Abs(lifted-0.25) <= float64(c.KMod1)
								idealT := (carry + want/br.Beta) / float64(c.KMod1)
								br.PureApproximationError = math.Max(br.PureApproximationError, math.Abs(br.Beta*lb.Mod1PlaintextOracle(engines[b].plan, idealT)-want))
								br.OracleVsMessageError = math.Max(br.OracleVsMessageError, cmplx.Abs(complex(br.Beta, 0)*lb.Mod1ComplexPlaintextOracle(engines[b].plan, v[j])-complex(want, 0)))
							}
						}
						m, e := metrics(v, make([]complex128, len(v)), c.R)
						if e != nil {
							return e
						}
						tr.Branches[b].Stages = append(tr.Branches[b].Stages, stage{Name: name, Lane: lane, State: ctState(main, x), DataMax: m.DataMax, GuardMax: m.GuardMax})
						return nil
					})
					if e != nil {
						return e
					}
					if !diag.Equal(refreshed[b]) {
						return fmt.Errorf("branch%d diagnostic ciphertext mismatch", b)
					}
				}
			}
			if c.InverseSqrtIterations != 0 {
				final := returned
				if !c.ApplicationBeforeReturn {
					final, tr.InverseSqrt, e = RunInverseSqrtApplication(top, st, app, returned, unscaleReference(wantTop, 32), InverseSqrtApplicationOptions{Iterations: c.InverseSqrtIterations, R: c.R, TargetBits: c.TargetBits})
					if e != nil {
						return e
					}
				}
				tr.Final = ctState(top, final)
				tr.FinalMetrics, e = measure(top, st, final, inverseSqrtReference(wantTop, 32, c.R), c.R)
				if e != nil {
					return e
				}
				tr.FinalMeetsTarget = tr.FinalMetrics.MaxErrorBits >= float64(c.TargetBits)
				if tr.FinalMeetsTarget {
					res.CasesApplicationMeetingTarget++
				}
			}
			tr.PipelineOnlineSeconds = tr.Frontend.OnlineSeconds + tr.OnlineSeconds + tr.InverseSqrt.ArithmeticSeconds
			if c.PairedTiming {
				if !c.ApplicationBeforeReturn {
					tr.SerialApplicationSeconds = tr.InverseSqrt.ArithmeticSeconds
				}
				tr.SerialPipelineSeconds = tr.Frontend.OnlineSeconds + tr.SerialOnlineSeconds + tr.SerialApplicationSeconds
				tr.ParallelPipelineSeconds = tr.PipelineOnlineSeconds
			}
			if c.CheckSquare {
				t := time.Now()
				sq, e := app.MulRelinNew(returned, returned)
				if e != nil {
					return e
				}
				if e = app.Rescale(sq, sq); e != nil {
					return e
				}
				tr.SquareSeconds = time.Since(t).Seconds()
				tr.AfterSquare = ctState(top, sq)
				wantSq := make([]complex128, len(wantTop))
				for j := range wantSq {
					wantSq[j] = wantTop[j] * wantTop[j]
				}
				tr.SquareMetrics, e = measure(top, st, sq, wantSq, c.R)
				if e != nil {
					return e
				}
				tr.SquareMeetsTarget = tr.SquareMetrics.MaxErrorBits >= float64(c.TargetBits)
			}
			if c.ChainLength != 0 {
				tr.ApplicationChain, e = RunBoundedApplicationChain(top, st, app, returned, wantTop, BoundedChainOptions{
					Steps: c.ChainLength, PhaseRadians: c.ChainPhase, ShapeFactor: c.ChainFactorShape,
					R: c.R, OutputBits: c.OutputBits, TargetBits: c.TargetBits,
				})
				if e != nil {
					return e
				}
				if tr.ApplicationChain.ExecutedSteps == tr.ApplicationChain.RequestedSteps {
					res.CasesChainComplete++
					if tr.ApplicationChain.InitialMeetsTarget && tr.ApplicationChain.EveryOutputMeetsTarget {
						res.CasesChainMeetingTarget++
					}
				}
			}
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
		fmt.Printf("trial%d outputL%d bits%.6f online%.6fs err=%s\n", tr.Index, tr.Output.Level, tr.OutputMetrics.MaxErrorBits, tr.OnlineSeconds, tr.Error)
	}
	if res.CasesFailed > 0 {
		return fmt.Errorf("%d trials failed execution", res.CasesFailed)
	}
	return nil
}
func main() {
	var c config
	flag.BoolVar(&c.PairedTiming, "paired-timing", false, "same-input one-core serial and two-core EvalMod-lane parallel timing")
	flag.IntVar(&c.LaneWorkers, "lane-workers", 1, "EvalMod lane workers")
	flag.IntVar(&c.SSEBase, "sse-base", 0, "low-q SSE key-switch gadget base bits")
	var out string
	flag.BoolVar(&c.CalibrateApplicationScale, "calibrate-application-scale", true, "select real EvalMod output scale from actual inverse-sqrt circuit primes")
	flag.BoolVar(&c.Statistics, "statistics", false, "real dense samples to per-channel mean squares frontend")
	flag.IntVar(&c.InverseSqrtIterations, "inverse-sqrt-iterations", 0, "true inverse RMS application; 7 wide-domain or 5 narrow-domain iterations")
	flag.BoolVar(&c.ApplicationBeforeReturn, "application-before-return", false, "evaluate inverse RMS in leaf ring, then merge and return with a final-level key")
	flag.BoolVar(&c.NoRS, "no-rs", false, "direct PA in the top ring; requires logN=logn and shares the input/output secret")
	flag.IntVar(&c.ActiveBranches, "active-branches", 0, "number of public active coefficient branches, prefix; 0 means all")
	flag.BoolVar(&c.RefreshDummy, "refresh-dummy", false, "refresh public ideal-zero branches instead of replacing by degree-one zero")
	flag.IntVar(&c.ChainLength, "chain-length", 0, "0 disables; -1 consumes every output level with actual bounded ciphertext multiplication")
	flag.Float64Var(&c.ChainPhase, "chain-phase", math.Pi/16, "phase of each independently encrypted unit-modulus multiplier")
	flag.BoolVar(&c.ChainFactorShape, "chain-factor-shape", true, "encrypt factors in inverse-unit coordinates, then multiply g")
	flag.IntVar(&c.LogN, "logN", 16, "")
	flag.IntVar(&c.Logn, "logn", 15, "")
	flag.IntVar(&c.KMessages, "messages", 64, "independent complex messages per leaf")
	flag.IntVar(&c.R, "r", 4, "PA classes")
	flag.IntVar(&c.Power, "power", 1, "0 is identity unit ablation with identical fiber layout")
	flag.IntVar(&c.Trials, "trials", 3, "")
	flag.IntVar(&c.Workers, "workers", 1, "")
	flag.IntVar(&c.OutputLevel, "output-level", 3, "")
	flag.IntVar(&c.Q0Bits, "q0-bits", 50, "")
	flag.IntVar(&c.InputBits, "input-bits", 40, "")
	flag.IntVar(&c.OutputBits, "output-bits", 35, "")
	flag.IntVar(&c.EMBits, "em-bits", 40, "")
	flag.IntVar(&c.EvalQBits, "eval-q-bits", 40, "")
	flag.IntVar(&c.CtSQBits, "cts-q-bits", 61, "")
	flag.IntVar(&c.PBits, "p-bits", 55, "")
	flag.IntVar(&c.PCount, "p-count", 2, "")
	flag.IntVar(&c.Degree, "degree", 31, "")
	flag.IntVar(&c.DA, "double-angle", 3, "")
	flag.IntVar(&c.InverseDegree, "inverse-degree", 0, "")
	flag.IntVar(&c.KMod1, "k-mod1", 17, "")
	flag.IntVar(&c.RatioBits, "ratio-bits", 4, "")
	flag.IntVar(&c.SparseH, "sparse-h", 32, "")
	flag.IntVar(&c.TargetBits, "target-bits", 20, "")
	flag.Int64Var(&c.Seed, "seed", 2026102411, "")
	flag.Float64Var(&c.Amplitude, "amplitude", 0.2, "")
	flag.StringVar(&c.UnitFile, "units", "units-classes.json", "")
	flag.BoolVar(&c.DryRun, "dry-run", false, "parameter and modulus ledger only; no keys")
	flag.BoolVar(&c.CheckSquare, "check-square", true, "")
	flag.BoolVar(&c.Diagnostics, "diagnostics", false, "extra same-input rerun outside online timing")
	flag.BoolVar(&c.ShapeCtS, "shape-cts", true, "PA encode CtS diagonals with BSGS-rotated units")
	flag.BoolVar(&c.ShapeEntry, "shape-entry", true, "PA conjugation around initial ring switch")
	flag.BoolVar(&c.AllowSubunit, "allow-subunit", false, "")
	flag.StringVar(&out, "out", "fiber-rs.json", "")
	flag.Parse()
	host, _ := os.Hostname()
	res := result{Config: c, Host: host, Started: time.Now().UTC().Format(time.RFC3339)}
	err := run(c, &res)
	if err != nil {
		res.Status = "failed"
		res.Error = err.Error()
	} else if !c.DryRun {
		res.Status = "executed"
	}
	if e := os.MkdirAll(filepath.Dir(out), 0755); e != nil {
		panic(e)
	}
	f, e := os.Create(out)
	if e != nil {
		panic(e)
	}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if e = encoder.Encode(res); e != nil {
		panic(e)
	}
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
