// This file is a modification of lattigo/examples/singleparty/ckks_bootstrapping/slim/main.go
//
// Remark: the scale management in CKKS bootstrapping is tailored for ModUp-then-CtS bootstrapping.
// It seems this scale management leads to a lower precision for slim bootstrapping,
// and I don't know how to fix this
package main

import (
	"flag"
	"fmt"
	"math"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/failure"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func sumSlice(s []int) (sum int) {
	for _, ele := range s {
		sum += ele
	}
	return
}

func makeSliceInit(length, val int) (s []int) {
	s = make([]int, length)
	for idx := range s {
		s[idx] = val
	}
	return
}

type MyBtpParamSet struct {
	LogDefaultScale                                   int
	q0, qiSlotsToCoeffs, qiCoeffsToSlots, piBootstrap []int
	qEvalMod                                          int
	StCLevels                                         []int
	LogMessageRatio                                   int

	K, mod1Degree, DoubleAngle int
	mod1Type                   mod1.Type

	StCSubringSecretExtDegree, bottomLevelSubringSecretExtDegree int
	// Xs is the regular secret distribution
	Xs     ring.Ternary
	isSlim bool

	EphemeralSecretWeight int
}

func (param MyBtpParamSet) getXs() (Xs *ring.Ternary) {
	Xs = new(ring.Ternary)
	Xs.ExtDegree = param.bottomLevelSubringSecretExtDegree
	if param.EphemeralSecretWeight > 0 {
		Xs.H = param.EphemeralSecretWeight
	} else {
		Xs.P = 2.0 / 3
	}
	return
}

func (param MyBtpParamSet) EvalModLevels() (levels int) {
	levels = int(math.Ceil(math.Log2(float64(param.mod1Degree)))) +
		param.DoubleAngle
	return
}

func (param MyBtpParamSet) MinimumK(logfailure float64) (K int) {
	logN := 16 - int(math.Round(math.Log2(
		float64(max(param.bottomLevelSubringSecretExtDegree, 1)))))
	return failure.FindSuitableK(param.getXs(), logN, 15, logfailure)
}

func (param MyBtpParamSet) FailureProbability() (prob float64) {
	logN := 16 - int(math.Round(math.Log2(
		float64(max(param.bottomLevelSubringSecretExtDegree, 1)))))
	return failure.Probability(param.getXs(), param.K, logN, 15)
}

func (param MyBtpParamSet) MinimumKSimple(logfailure float64) (K int) {
	logN := 16 - int(math.Round(math.Log2(
		float64(max(param.bottomLevelSubringSecretExtDegree, 1)))))
	return failure.FindSuitableKSimple(param.getXs(), logN, 15, logfailure, 13.1)
}

func (param MyBtpParamSet) FailureProbabilitySimple() (prob float64) {
	logN := 16 - int(math.Round(math.Log2(
		float64(max(param.bottomLevelSubringSecretExtDegree, 1)))))
	return failure.ProbabilitySimple(param.getXs(), param.K, logN, 15, 13.1)
}

/* parameter sets */

var BMTH21Params = MyBtpParamSet{
	LogDefaultScale: 40,
	q0:              []int{50},
	qiSlotsToCoeffs: []int{28, 56},
	qEvalMod:        60,
	qiCoeffsToSlots: makeSliceInit(4, 53),
	piBootstrap:     makeSliceInit(5, 61),
	StCLevels:       []int{2, 1}, // not sure if this works
	LogMessageRatio: 8,
	// Pfail = 2^-14.9, prec = 16.8
	K:           325,
	mod1Degree:  255,
	DoubleAngle: 4,
	mod1Type:    mod1.CosContinuous,

	StCSubringSecretExtDegree:         1,
	bottomLevelSubringSecretExtDegree: 1,
	Xs:                                ring.Ternary{P: 2.0 / 3}, // uniform ternary
	isSlim:                            false,
}

var GuidelineParamSet = MyBtpParamSet{
	LogDefaultScale: 35,
	q0:              []int{45},
	qiSlotsToCoeffs: []int{30, 30, 30},
	qEvalMod:        60,
	qiCoeffsToSlots: makeSliceInit(4, 56),
	piBootstrap:     makeSliceInit(5, 61),
	StCLevels:       []int{1, 1, 1},
	LogMessageRatio: 8,
	// Pfail = 2^-37.65, prec = 15.9
	K:           512,
	mod1Degree:  255,
	DoubleAngle: 4,
	mod1Type:    mod1.CosContinuous,

	StCSubringSecretExtDegree:         1,
	bottomLevelSubringSecretExtDegree: 1,
	Xs:                                ring.Ternary{P: 2.0 / 3.0},
	isSlim:                            false,
}

var SparseSecretParamSet = MyBtpParamSet{
	LogDefaultScale: 40,
	q0:              []int{50},
	qiSlotsToCoeffs: []int{39, 39, 39},
	qEvalMod:        60,
	qiCoeffsToSlots: makeSliceInit(4, 56),
	piBootstrap:     makeSliceInit(5, 61),
	StCLevels:       []int{1, 1, 1},
	LogMessageRatio: 8,
	K:               16,
	mod1Degree:      30,
	DoubleAngle:     3,
	mod1Type:        mod1.CosDiscrete,

	StCSubringSecretExtDegree:         1,
	bottomLevelSubringSecretExtDegree: 1,
	Xs:                                ring.Ternary{P: 2.0 / 3.0},
	isSlim:                            false,
	EphemeralSecretWeight:             16,
}

var MyParamSets = []MyBtpParamSet{
	{
		LogDefaultScale: 35,
		q0:              []int{45},
		qiSlotsToCoeffs: []int{35, 35, 35},
		qEvalMod:        60,
		qiCoeffsToSlots: makeSliceInit(4, 60),
		piBootstrap:     makeSliceInit(5, 61),
		StCLevels:       []int{1, 1, 1},
		LogMessageRatio: 8,
		// Pfail = 2^-37.65, prec = 15.9
		K:           512,
		mod1Degree:  255,
		DoubleAngle: 4,
		mod1Type:    mod1.CosContinuous,

		StCSubringSecretExtDegree:         1 << 3,
		bottomLevelSubringSecretExtDegree: 1 << 4,
		Xs:                                ring.Ternary{P: 2.0 / 3.0},
		isSlim:                            false,
	},
}

// k for 2^-16, 2^-32, 2^-64, 2^-128 based on Gaussian heuristic
// k =   6.4,   7.9,   10.3,  14.0  for 2^16 slots
// k =   4.4,   7.9,   9.2,   13.2  for one slot

var (
	flagLogScale    = flag.Int("scale", 35, "Log2(default scale)")
	flagStCLogQi    = flag.Int("scalestc", 35, "Log2(qi for StC)")
	flagCtSLogQi    = flag.Int("scalects", 60, "Log2(qi for CtS)")
	flagLogPfail    = flag.Float64("eps", -16, "log2(failure probability)")
	flagDegree      = flag.Int("degree", 255, "Degree for Mod 1 polynomial")
	flagDoubleAngle = flag.Int("r", 4, "Number of double angle formula")
	flagSlim        = flag.Bool("slim", false, "Set flag to use slim bootstrapping. NOTE: Slim bootstrapping in Lattigo seems to have a lower precision than ordinary ones.")
	flagMaxLevels   = flag.Int("lvls", 100, "Max number of levels")
	// flagMod1Type    = flag.Int("modtype", int(mod1.CosDiscrete), "Type of Mod 1 polynomial")
	flagRepeat     = flag.Int("repeat", 1, "Number of repeated tests")
	flagChange     = flag.Bool("change", true, "Set flag to use cmdline flags")
	flagInfo       = flag.Bool("info", false, "Set flag to print parameters without running")
	flagBMTH       = flag.Bool("BMTH", false, "Set flag to use BMTH21 parameters")
	flagGuidelines = flag.Bool("guide", false, "Set flag to use Guideline parameters")
	flagSparseSec  = flag.Bool("sparse", false, "Set flag to use sparse secret parameters")
	flagSparseHwt  = flag.Int("spsk", 0, "Hwt of the sparse secret")
)

func main() {

	flag.Parse()

	// Default LogN, which with the following defined parameters
	// provides a security of 128-bit.
	LogN := 16
	nRepeat := *flagRepeat // repeat over multiple secrets

	//============================
	//=== 1) SCHEME PARAMETERS ===
	//============================

	curParam := MyParamSets[0]
	if *flagBMTH {
		curParam = BMTH21Params
		curParam.isSlim = *flagSlim
		if *flagChange {
			curParam.K = curParam.MinimumKSimple(*flagLogPfail)
			fmt.Printf("Setting K to %d\n", curParam.K)
		}
	} else if *flagGuidelines {
		curParam = GuidelineParamSet
		curParam.isSlim = *flagSlim
		if *flagChange {
			curParam.K = curParam.MinimumKSimple(*flagLogPfail)
			fmt.Printf("Setting K to %d\n", curParam.K)
		}
	} else if *flagSparseSec {
		curParam = SparseSecretParamSet
		curParam.isSlim = *flagSlim
		if *flagChange {
			curParam.K = curParam.MinimumKSimple(*flagLogPfail)
			fmt.Printf("Setting K to %d\n", curParam.K)
		}
	} else if *flagChange {
		curParam.LogDefaultScale = *flagLogScale
		curParam.q0 = []int{curParam.LogDefaultScale + 10}
		curParam.qiSlotsToCoeffs = makeSliceInit(3, *flagStCLogQi)
		curParam.qiCoeffsToSlots = makeSliceInit(4, *flagCtSLogQi)

		curParam.EphemeralSecretWeight = *flagSparseHwt
		if curParam.EphemeralSecretWeight != 0 {
			curParam.bottomLevelSubringSecretExtDegree = 1
		}
		curParam.K = curParam.MinimumKSimple(*flagLogPfail)
		curParam.mod1Degree = *flagDegree
		curParam.DoubleAngle = *flagDoubleAngle
		curParam.isSlim = *flagSlim
		if curParam.mod1Degree >= 2*(curParam.K-1) {
			curParam.mod1Type = mod1.CosDiscrete
		} else {
			curParam.mod1Type = mod1.CosContinuous
		}
	}
	fmt.Printf("old K is %d\n", curParam.MinimumK(*flagLogPfail))
	fmt.Printf("Failure prob is 2^%f for K = %d\n",
		curParam.FailureProbabilitySimple(), curParam.K)
	fmt.Println(curParam)
	// for _, logPfail := range []float64{-16, -32, -64, -128} {
	// 	fmt.Printf("Minimum K for 2^%f fail probability is %d\n", logPfail,
	// 		curParam.MinimumK(logPfail))
	// }

	// subring secret parameters
	StCSubringSecretExtDegree := curParam.StCSubringSecretExtDegree
	bottomLevelSubringSecretExtDegree := curParam.bottomLevelSubringSecretExtDegree
	isSlim := curParam.isSlim
	if !isSlim {
		StCSubringSecretExtDegree = 1
	}

	LogDefaultScale := curParam.LogDefaultScale

	maxLogQP := 1747
	q0 := curParam.q0                                                       // 3) ScaleDown & 4) ModUp
	qiSlotsToCoeffs := curParam.qiSlotsToCoeffs                             // 1) SlotsToCoeffs
	qiEvalMod := makeSliceInit(curParam.EvalModLevels(), curParam.qEvalMod) // 6) EvalMod
	qiCoeffsToSlots := curParam.qiCoeffsToSlots                             // 5) CoeffsToSlots
	piBootstrap := curParam.piBootstrap                                     // P primes for bootstrapping

	// pop the last prime from qiCoeffsToSlots for subring CtS
	extraCtSLevel := 0
	if bottomLevelSubringSecretExtDegree > 1 {
		qiCoeffsToSlots = qiCoeffsToSlots[:len(qiCoeffsToSlots)-1]
		extraCtSLevel = 1
	}
	nCircuitLevels := (maxLogQP - sumSlice(q0) - sumSlice(qiSlotsToCoeffs) - sumSlice(qiEvalMod) -
		sumSlice(qiCoeffsToSlots) - sumSlice(piBootstrap)) / LogDefaultScale
	qiCircuitSlots := makeSliceInit(min(nCircuitLevels, *flagMaxLevels), LogDefaultScale) // 0) Circuit in the slot domain
	fmt.Printf("Number of circuit primes = %d\n", len(qiCircuitSlots))

	if *flagInfo {
		return
	}

	LogQ := q0
	if isSlim {
		LogQ = append(LogQ, qiSlotsToCoeffs...)
		LogQ = append(LogQ, qiCircuitSlots...)
	} else {
		LogQ = append(LogQ, qiCircuitSlots...)
		LogQ = append(LogQ, qiSlotsToCoeffs...)
	}
	LogQ = append(LogQ, qiEvalMod...)
	LogQ = append(LogQ, qiCoeffsToSlots...)

	fmt.Println("Primes length:", LogQ)

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            LogN,            // Log2 of the ring degree
		LogQ:            LogQ,            // Log2 of the ciphertext modulus
		LogP:            piBootstrap,     // Log2 of the key-switch auxiliary prime moduli
		LogDefaultScale: LogDefaultScale, // Log2 of the scale
		Xs:              curParam.Xs,
	})

	if err != nil {
		panic(err)
	}

	//====================================
	//=== 2) BOOTSTRAPPING PARAMETERS ===
	//====================================

	// CoeffsToSlots parameters (homomorphic encoding)
	CoeffsToSlotsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicEncode,
		Format:       dft.RepackImagAsReal, // Returns the real and imaginary part into separate ciphertexts
		LogSlots:     params.LogMaxSlots(),
		LevelQ:       params.MaxLevelQ(),
		LevelP:       params.MaxLevelP(),
		LogBSGSRatio: 1,
		Levels:       []int{1, 1, 1, 1}, //qiCoeffsToSlots
		// subring CtS stuff
		SubringExtDegree:      bottomLevelSubringSecretExtDegree,
		LevelsInSubringSecret: 1,
		// Base2Decomp: 0
		// ManualDepthSplit: []int{}
	}

	// Parameters of the homomorphic modular reduction x mod 1
	Mod1ParametersLiteral := mod1.ParametersLiteral{
		LevelQ:      params.MaxLevel() - CoeffsToSlotsParameters.Depth(true) + extraCtSLevel,
		LogScale:    curParam.qEvalMod,    // Matches qiEvalMod
		Mod1Type:    curParam.mod1Type,    // Multi-interval Chebyshev interpolation
		Mod1Degree:  curParam.mod1Degree,  // Depth 8
		DoubleAngle: curParam.DoubleAngle, // Depth 4
		// N'=2^12: set to 211 for 2^-128 failure prob; set to 96 for 2^-16 failure prob
		// N'=2^13: set to 298 for 2^-128 failure prob; set to 136 for 2^-16 failure prob
		K:               curParam.K,               // With EphemeralSecretWeight = 32 and 2^{15} slots, ensures < 2^{-138.7} failure probability
		LogMessageRatio: curParam.LogMessageRatio, // q/|m| = 2^8
		Mod1InvDegree:   0,                        // Depth 0
	}
	// Mod1ParametersLiteral := mod1.ParametersLiteral{
	// 	LevelQ:      params.MaxLevel() - CoeffsToSlotsParameters.Depth(true),
	// 	LogScale:    60,                 // Matches qiEvalMod
	// 	Mod1Type:    mod1.CosContinuous, // Multi-interval Chebyshev interpolation
	// 	Mod1Degree:  30,                 // Depth 5
	// 	DoubleAngle: 3,                  // Depth 3
	// 	K:               16, // With EphemeralSecretWeight = 32 and 2^{15} slots, ensures < 2^{-138.7} failure probability
	// 	LogMessageRatio: 10, // q/|m| = 2^10
	// 	Mod1InvDegree:   0,  // Depth 0
	// }

	// SlotsToCoeffs parameters (homomorphic decoding)
	SlotsToCoeffsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicDecode,
		LogSlots:     params.LogMaxSlots(),
		LogBSGSRatio: 1,
		LevelP:       params.MaxLevelP(),
		Levels:       curParam.StCLevels,
		// subring secret stuff
		LevelsInSubringSecret: 1,
		SubringExtDegree:      StCSubringSecretExtDegree,
		Base2Decomp:           0,
		ManualDepthSplit:      []int{}, // use this for two level StC
	}

	if isSlim {
		SlotsToCoeffsParameters.LevelQ = len(SlotsToCoeffsParameters.Levels)
	} else {
		SlotsToCoeffsParameters.LevelQ = Mod1ParametersLiteral.LevelQ - len(qiEvalMod)
	}

	// Custom bootstrapping.Parameters.
	// All fields are public and can be manually instantiated.
	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: SlotsToCoeffsParameters,
		Mod1ParametersLiteral:   Mod1ParametersLiteral,
		CoeffsToSlotsParameters: CoeffsToSlotsParameters,
		EphemeralSecretWeight:   curParam.EphemeralSecretWeight, // > 128bit secure for LogN=16 and LogQP = 115.
		SubringSecretExtDegree:  bottomLevelSubringSecretExtDegree,
		CircuitOrder:            bootstrapping.DecodeThenModUp, // XXX: only affects levels
	}
	if !isSlim {
		btpParams.CircuitOrder = bootstrapping.ModUpThenEncode
	}

	// We pring some information about the bootstrapping parameters (which are identical to the residual parameters in this example).
	// We can notably check that the LogQP of the bootstrapping parameters is smaller than 1550, which ensures
	// 128-bit of security as explained above.
	fmt.Printf("Bootstrapping parameters: logN=%d, logSlots=%d, H(%d; %d), ExtDegree=%d, sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.BootstrappingParameters.LogN(),
		btpParams.BootstrappingParameters.LogMaxSlots(),
		btpParams.BootstrappingParameters.XsHammingWeight(),
		btpParams.EphemeralSecretWeight,
		btpParams.SubringSecretExtDegree,
		btpParams.BootstrappingParameters.Xe(),
		btpParams.BootstrappingParameters.LogQP(),
		btpParams.BootstrappingParameters.QCount(),
		btpParams.BootstrappingParameters.LogDefaultScale())

	//===========================
	//=== 3) KEYGEN & ENCRYPT ===
	//===========================

	// Now that both the residual and bootstrapping parameters are instantiated, we can
	// instantiate the usual necessary object to encode, encrypt and decrypt.

	var avgL1err float64
	var avgStC, avgEvalMod, avgCtS, avgModUp, avgTotal time.Duration
	for repeat := 0; repeat < nRepeat; repeat++ {
		// Scheme context and keys
		kgen := rlwe.NewKeyGenerator(params)

		sk, pk := kgen.GenKeyPairNew()

		encoder := ckks.NewEncoder(params)
		decryptor := rlwe.NewDecryptor(params, sk)
		encryptor := rlwe.NewEncryptor(params, pk)

		fmt.Println()
		fmt.Println("Generating bootstrapping evaluation keys...")
		// CtS/StC keys are generated here and stored in evk
		evk, _, err := btpParams.GenEvaluationKeys(sk)
		if err != nil {
			panic(err)
		}
		fmt.Println("Done")

		//========================
		//=== 4) BOOTSTRAPPING ===
		//========================

		// Instantiates the bootstrapper
		var eval *bootstrapping.Evaluator
		// CtS/StC constants are calculated here and stored in eval
		if eval, err = bootstrapping.NewEvaluator(btpParams, evk); err != nil {
			panic(err)
		}

		// Generate a random plaintext with values uniformly distributed in [-1, 1] for the real and imaginary part.
		valuesWant := make([]complex128, params.MaxSlots())
		for i := range valuesWant {
			valuesWant[i] = sampling.RandComplex128(-1, 1)
		}

		// We encrypt at level 0
		startLevel := 0
		if isSlim {
			startLevel = SlotsToCoeffsParameters.LevelQ
		}
		plaintext := ckks.NewPlaintext(params, startLevel)
		if err := encoder.Encode(valuesWant, plaintext); err != nil {
			panic(err)
		}

		// Encrypt
		ciphertext, err := encryptor.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}

		// Decrypt, print and compare with the plaintext values
		fmt.Println()
		fmt.Println("Precision of values vs. ciphertext")
		valuesTest, _ := printDebug(params, ciphertext, valuesWant, decryptor, encoder)

		fmt.Println("Bootstrapping...")

		var afterStCTime, afterModUpTime, afterCtSTime, afterEvalTime time.Time
		startTime := time.Now()

		if isSlim {
			// Step 1 : SlotsToCoeffs (Homomorphic decoding)
			if ciphertext, err = eval.SlotsToCoeffs(ciphertext, nil); err != nil {
				panic(err)
			}
			afterStCTime = time.Now()
		}

		// Step 3: scale to q/|m|
		if ciphertext, _, err = eval.ScaleDown(ciphertext); err != nil {
			panic(err)
		}

		// Step 4 : Extend the basis from q to Q
		if ciphertext, err = eval.ModUp(ciphertext); err != nil {
			panic(err)
		}

		afterModUpTime = time.Now()

		// Step 5 : CoeffsToSlots (Homomorphic encoding)
		// Note: expects the result to be given in bit-reversed order
		// Also, we need the homomorphic encoding to split the real and
		// imaginary parts into two pure real ciphertexts, because the
		// homomorphic modular reduction is only defined on the reals.
		// The `imag` ciphertext can be ignored if the original input
		// is purely real.
		var real, imag *rlwe.Ciphertext
		if real, imag, err = eval.CoeffsToSlots(ciphertext); err != nil {
			panic(err)
		}

		afterCtSTime = time.Now()

		// if isSlim {
		// 	break // XXX: early stopping
		// }

		// Step 6 : EvalMod (Homomorphic modular reduction)
		if real, err = eval.EvalMod(real); err != nil {
			panic(err)
		}

		if imag, err = eval.EvalMod(imag); err != nil {
			panic(err)
		}

		if isSlim {
			// Recombines the real and imaginary part
			if err = eval.Evaluator.Mul(imag, 1i, imag); err != nil {
				panic(err)
			}

			if err = eval.Evaluator.Add(real, imag, ciphertext); err != nil {
				panic(err)
			}
		}
		afterEvalTime = time.Now()

		if !isSlim {
			if ciphertext, err = eval.SlotsToCoeffs(real, imag); err != nil {
				panic(err)
			}
			afterStCTime = time.Now()
		}

		var TotalTime, StCTime, ModUpTime, CtSTime, EvalModTime time.Duration
		if isSlim {
			TotalTime, StCTime, ModUpTime, CtSTime, EvalModTime =
				afterEvalTime.Sub(startTime), afterStCTime.Sub(startTime), afterModUpTime.Sub(afterStCTime), afterCtSTime.Sub(afterModUpTime), afterEvalTime.Sub(afterCtSTime)
		} else {
			TotalTime, StCTime, ModUpTime, CtSTime, EvalModTime =
				afterStCTime.Sub(startTime), afterStCTime.Sub(afterEvalTime), afterModUpTime.Sub(startTime), afterCtSTime.Sub(afterModUpTime), afterEvalTime.Sub(afterCtSTime)
		}
		avgCtS += CtSTime
		avgStC += StCTime
		avgModUp += ModUpTime
		avgEvalMod += EvalModTime
		avgTotal += TotalTime
		fmt.Printf("Bootstrapping finished in %s\nStC: %s, ModUp: %s, CtS: %s, EvalMod: %s\n", TotalTime, StCTime, ModUpTime, CtSTime, EvalModTime)
		fmt.Println("Done")

		fmt.Printf("Output ciphertext level = %d, circuit moduli = ", ciphertext.LevelQ())
		if isSlim {
			fmt.Println(btpParams.BootstrappingParameters.LogQi()[SlotsToCoeffsParameters.LevelQ+1 : ciphertext.LevelQ()+1])
		} else {
			fmt.Println(btpParams.BootstrappingParameters.LogQi()[1 : ciphertext.LevelQ()+1])
		}
		//==================
		//=== 5) DECRYPT ===
		//==================

		// Decrypt, print and compare with the plaintext values
		fmt.Println()
		fmt.Println("Precision of ciphertext vs. Bootstrap(ciphertext)")
		_, LogL1err := printDebug(params, ciphertext, valuesTest, decryptor, encoder)
		avgL1err += math.Pow(2, -LogL1err)
	}
	avgL1err = -math.Log2(avgL1err / float64(nRepeat))
	avgCtS /= time.Duration(nRepeat)
	avgStC /= time.Duration(nRepeat)
	avgModUp /= time.Duration(nRepeat)
	avgEvalMod /= time.Duration(nRepeat)
	avgTotal /= time.Duration(nRepeat)

	fmt.Printf("Avg L1 error is %f\n", avgL1err)
	fmt.Printf("Avg time... ModUp: %s, CtS: %s, EvalMod: %s, StC: %s, Total: %s\n",
		avgModUp, avgCtS, avgEvalMod, avgStC, avgTotal)
}

func printDebug(params ckks.Parameters, ciphertext *rlwe.Ciphertext, valuesWant []complex128, decryptor *rlwe.Decryptor, encoder *ckks.Encoder) (valuesTest []complex128, LogL1Err float64) {

	slots := ciphertext.Slots()

	if !ciphertext.IsBatched {
		slots *= 2
	}

	valuesTest = make([]complex128, slots)

	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), valuesTest); err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))

	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale.Float64()))
	fmt.Printf("ValuesTest: %10.14f %10.14f %10.14f %10.14f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %10.14f %10.14f %10.14f %10.14f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := ckks.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, 0, false)

	LogL1Err = precStats.Log2L1Err
	fmt.Printf("L1 Err = %f\n", LogL1Err)

	fmt.Println(precStats.String())
	fmt.Println()

	return
}
