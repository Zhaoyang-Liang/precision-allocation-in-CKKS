package bootstrapping

import (
	"bufio"
	"fmt"
	"io"
	"math"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils"
	"github.com/tuneinsight/lattigo/v6/utils/buffer"
)

// EvaluationKeys is a struct storing the different
// evaluation keys required by the bootstrapper.
type EvaluationKeys struct {

	// EvkN1ToN2 is the evaluation key to switch from the residual parameters'
	// ring degree (N1) to the bootstrapping parameters' ring degree (N2)
	EvkN1ToN2 *rlwe.EvaluationKey

	// EvkN2ToN1 is the evaluation key to switch from the bootstrapping parameters'
	// ring degree (N2) to the residual parameters' ring degree (N1)
	EvkN2ToN1 *rlwe.EvaluationKey

	// EvkRealToCmplx is the evaluation key to switch from the standard ring to the
	// conjugate invariant ring.
	EvkRealToCmplx *rlwe.EvaluationKey

	// EvkCmplxToReal is the evaluation key to switch from the conjugate invariant
	// ring to the standard ring.
	EvkCmplxToReal *rlwe.EvaluationKey

	// Key switching key to a subring secret during StC
	EvkInStC *rlwe.EvaluationKey

	// EvkBeforeModUp is the evaluation key to switch
	// from the dense secret to the sparse secret.
	// https://eprint.iacr.org/2022/024
	EvkBeforeModUp *rlwe.EvaluationKey

	// EvkAfterModUp is the evaluation key to switch
	// from the sparse secret to the dense secret.
	// https://eprint.iacr.org/2022/024
	EvkAfterModUp *rlwe.EvaluationKey

	// MemEvaluationKeySet is the evaluation key set storing the relinearization
	// key and the Galois keys necessary for the bootstrapping circuit.
	*rlwe.MemEvaluationKeySet

	// RotationKeysSubringStC stores the rotation keys for the last KSLevel of StC with subring secret
	RotationKeysSubringStC *rlwe.MemEvaluationKeySet

	// RotationKeysSubringCtS stores the rotation keys for the first KSLevel of CtS with subring secret
	RotationKeysSubringCtS *rlwe.MemEvaluationKeySet

	// parameters for switching to subring secret with custom P
	SubringParamsStc, SubringParamsModUp, SubringParamsCtS *rlwe.Parameters
}

// GenEvaluationKeys generates the bootstrapping evaluation keys, which include:
//
// If the bootstrapping parameters' ring degree > residual parameters' ring degree:
//   - An evaluation key to switch from the residual parameters' ring to the bootstrapping parameters' ring
//   - An evaluation key to switch from the bootstrapping parameters' ring to the residual parameters' ring
//
// If the residual parameters use the Conjugate Invariant ring:
//   - An evaluation key to switch from the conjugate invariant ring to the standard ring
//   - An evaluation key to switch from the standard ring to the conjugate invariant ring
//
// The core bootstrapping circuit evaluation keys:
//   - Relinearization key
//   - Galois keys
//   - The encapsulation evaluation keys (https://eprint.iacr.org/2022/024)
//
// Note:
//   - These evaluation keys are generated under an ephemeral secret key skN2 using the distribution
//     specified in the bootstrapping parameters.
//   - The ephemeral key used to generate the bootstrapping keys is returned by this method for debugging purposes.
//   - !WARNING! The bootstrapping parameters use their own and independent cryptographic parameters (i.e. float.Parameters)
//     and it is the user's responsibility to ensure that these parameters meet the target security and tweak them if necessary.
func (p Parameters) GenEvaluationKeys(skN1 *rlwe.SecretKey) (btpkeys *EvaluationKeys, skN2 *rlwe.SecretKey, err error) {

	var EvkN1ToN2, EvkN2ToN1 *rlwe.EvaluationKey
	var EvkRealToCmplx *rlwe.EvaluationKey
	var EvkCmplxToReal *rlwe.EvaluationKey
	paramsN2 := p.BootstrappingParameters

	kgen := rlwe.NewKeyGenerator(paramsN2)

	if p.ResidualParameters.N() != paramsN2.N() { // XXX: we don't need this case for our example, so we ignore this branch...
		// If the ring degree do not match
		// (if the residual parameters are Conjugate Invariant, N1 = N2/2)
		skN2 = kgen.GenSecretKeyNew()

		if p.ResidualParameters.RingType() == ring.ConjugateInvariant {
			EvkCmplxToReal, EvkRealToCmplx = kgen.GenEvaluationKeysForRingSwapNew(skN2, skN1)
		} else {
			EvkN1ToN2 = kgen.GenEvaluationKeyNew(skN1, skN2)
			EvkN2ToN1 = kgen.GenEvaluationKeyNew(skN2, skN1)
		}

	} else {

		ringQ := paramsN2.RingQ()
		ringP := paramsN2.RingP()

		// Else, keeps the same secret, but extends to the full modulus of the bootstrapping parameters.
		skN2 = rlwe.NewSecretKey(paramsN2)
		buff := ringQ.NewPoly()

		// Extends basis Q0 -> QL
		rlwe.ExtendBasisSmallNormAndCenterNTTMontgomery(ringQ, ringQ, skN1.Value.Q, buff, skN2.Value.Q)

		// Extends basis Q0 -> P
		rlwe.ExtendBasisSmallNormAndCenterNTTMontgomery(ringQ, ringP, skN1.Value.Q, buff, skN2.Value.P)
	}

	EvkInStC, EvkBeforeModup, EvkAfterModup,
		SubringParamsStC, SubringParamsModup, SubringParamsCtS,
		subringSkStC, skForModUp := p.genEncapsulationEvaluationKeysNew(skN2)

	var _ = skForModUp // TODO: needed if first matrix in CtS has depth >= N/N'
	var gksSubringSkStC []*rlwe.GaloisKey
	if subringSkStC != nil {
		kgenSubringSkStC := rlwe.NewKeyGenerator(SubringParamsStC)
		ckksParam := ckks.Parameters{Parameters: *SubringParamsStC}
		StCRotationKeysParams := rlwe.EvaluationKeyParameters{BaseTwoDecomposition: nil}
		if p.SlotsToCoeffsParameters.Base2Decomp > 0 {
			StCRotationKeysParams.BaseTwoDecomposition = utils.Pointy(p.SlotsToCoeffsParameters.Base2Decomp)
		}

		gksSubringSkStC = kgenSubringSkStC.GenGaloisKeysNew(append(p.GaloisElements(ckksParam), ckksParam.GaloisElementForComplexConjugation()),
			subringSkStC, StCRotationKeysParams)
	}

	var gksSubringSkCtS []*rlwe.GaloisKey
	if SubringParamsCtS != nil && skForModUp != nil {
		ckksParamCtS := ckks.Parameters{Parameters: *SubringParamsCtS}
		encoder := ckks.NewEncoder(paramsN2)
		subringEncoder := ckks.NewEncoder(ckksParamCtS)
		c2sMatrix, err := dft.NewMatrixFromLiteral(paramsN2, p.CoeffsToSlotsParameters, encoder, subringEncoder)
		if err != nil {
			return nil, nil, err
		}

		galElsMap := map[uint64]bool{}
		depth := min(p.CoeffsToSlotsParameters.LevelsInSubringSecret, len(c2sMatrix.Matrices))
		for _, mat := range c2sMatrix.Matrices[:depth] {
			if mat.N1 == 0 {
				slots := 1 << mat.LogDimensions.Cols
				subringSlots := min(slots, ckksParamCtS.N()/(2*ckksParamCtS.SubringSecretExtDegree()))
				for _, key := range utils.GetSortedKeys(mat.Vec) {
					subringKey := key & (subringSlots - 1)
					if subringKey != 0 {
						galElsMap[ckksParamCtS.GaloisElement(subringKey)] = true
					}
				}
			}
		}
		galElsCtS := utils.GetSortedKeys(galElsMap)
		if len(galElsCtS) > 0 {
			skForCtS := rlwe.NewSecretKey(SubringParamsCtS)
			ringQ0 := SubringParamsModup.RingQ()
			ringQCtS := SubringParamsCtS.RingQ()
			buff := ringQ0.NewPoly()
			rlwe.ExtendBasisSmallNormAndCenterNTTMontgomery(ringQ0, ringQCtS, skForModUp.Value.Q, buff, skForCtS.Value.Q)

			kgenSubringSkCtS := rlwe.NewKeyGenerator(SubringParamsCtS)
			gksSubringSkCtS = kgenSubringSkCtS.GenGaloisKeysNew(galElsCtS, skForCtS)
		}
	}

	rlk := kgen.GenRelinearizationKeyNew(skN2)
	gks := kgen.GenGaloisKeysNew(append(p.GaloisElements(paramsN2), paramsN2.GaloisElementForComplexConjugation()), skN2)

	return &EvaluationKeys{
		EvkN1ToN2:              EvkN1ToN2,
		EvkN2ToN1:              EvkN2ToN1,
		EvkRealToCmplx:         EvkRealToCmplx,
		EvkCmplxToReal:         EvkCmplxToReal,
		MemEvaluationKeySet:    rlwe.NewMemEvaluationKeySet(rlk, gks...),
		RotationKeysSubringStC: rlwe.NewMemEvaluationKeySet(nil, gksSubringSkStC...),
		RotationKeysSubringCtS: rlwe.NewMemEvaluationKeySet(nil, gksSubringSkCtS...),
		EvkInStC:               EvkInStC,
		EvkBeforeModUp:         EvkBeforeModup,
		EvkAfterModUp:          EvkAfterModup,
		SubringParamsStc:       SubringParamsStC,
		SubringParamsModUp:     SubringParamsModup,
		SubringParamsCtS:       SubringParamsCtS,
	}, skN2, nil
}

// GenEncapsulationEvaluationKeysNew generates the low level encapsulation EvaluationKeys for the bootstrapping.
// NOTE: three stages of key switching:
//   - during StC
//   - before ModUp  // OK
//   - after Modup
//
// NOTE: SubringParamsStC and SubringParamsModup are non-nil if corresponding Evks are non-nil
// FIXED: rlwe.Parameters with provided Q's and logP's may generate Pi=Qj
// DONE: larger sampling noise with a larger P in StC subring KS
func (p Parameters) genEncapsulationEvaluationKeysNew(skDense *rlwe.SecretKey) (EvkInStC, EvkBeforeModup, EvkAfterModup *rlwe.EvaluationKey,
	SubringParamsStC, SubringParamsModup, SubringParamsCtS *rlwe.Parameters, subringSkStC, skForModup *rlwe.SecretKey) {

	params := p.BootstrappingParameters
	StCparams := &p.SlotsToCoeffsParameters
	StCparams.SubringExtDegree = max(StCparams.SubringExtDegree, 1)

	FlagKSinStC := StCparams.SubringExtDegree > 1
	FlagKSinModup := p.EphemeralSecretWeight > 0 || p.SubringSecretExtDegree > 1

	if !FlagKSinStC && !FlagKSinModup {
		return
	}

	if FlagKSinStC && p.CircuitOrder != DecodeThenModUp {
		panic("switching to subring secret during StC is only supported for slim bootstrapping")
	}
	var prevSk = skDense
	prevSkExtDegree := 1

	if FlagKSinStC {
		// switch to subring in StC
		StCmoduliLength := params.LogQLvl(StCparams.LevelsInSubringSecret)

		log2p := []int{0}
		StCKeySwitchEvkParams := rlwe.EvaluationKeyParameters{}
		subringDeg := params.N() / StCparams.SubringExtDegree
		if subringDeg == 1<<12 {
			// see Security Guidelines for Implementing Homomorphic Encryption, Table 5.2
			// 106 bits for uniform ternary secret
			log2p[0] = 106 - StCmoduliLength
			if log2p[0] <= 0 { // use pure base2 decomposition
				log2p = nil
			} else {
				// for correct prime generation
				log2p[0] = max(log2p[0], params.LogNthRoot())
			}
			// follow the decomp base in StCparams
			if StCparams.Base2Decomp < 1 {
				panic("Base2Decomp should be positive")
			}
			StCKeySwitchEvkParams.BaseTwoDecomposition = utils.Pointy(StCparams.Base2Decomp)
		} else if subringDeg == 1<<13 {
			if StCmoduliLength > 106 {
				panic("expecting StC modulus for subring secret <= 106 bits")
			}
			// two primes in Pi
			log2p[0] = min((212-StCmoduliLength)/2, 61)
			log2p = append(log2p, log2p[0])
			StCKeySwitchEvkParams.BaseTwoDecomposition = nil
		} else {
			panic("Only subring degrees = 2^12 or 2^13 are supported for now")
		}

		SubringParamsStCTmp, _ := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: params.LogN(),
			Q:    params.Q()[:StCparams.LevelsInSubringSecret+1], // q0 & StC moduli
			LogP: log2p,
			Xs:   ring.Ternary{P: 2.0 / 3, ExtDegree: StCparams.SubringExtDegree},
		})
		SubringParamsStC = &SubringParamsStCTmp
		// NOTE: the required log2p[0] may be too small to be satisfied
		//  in case a larger P0 is chosen, we need to increase the Gaussian stddev to keep the security level
		if subringDeg == 1<<12 {
			errStddevRatio := math.Exp2(SubringParamsStC.LogQP() - 106)
			*SubringParamsStC.XeMut() = rlwe.NewDistribution(ring.DiscreteGaussian{
				Sigma: DefaultXe.Sigma * errStddevRatio,
				Bound: DefaultXe.Bound * errStddevRatio,
				// useful for Galois keygen
				ExtDegree: StCparams.SubringExtDegree,
			}, params.LogN())
		}
		// NOTE: rlwe.Evaluator is configured with the large ring moduli chain, so the BasisExtender produces wrong results for custom P
		//  already fixed by using a separate Evaluator when custom P is needed
		// P.S. this rlwe.Parameters is also needed for rotation keygen, so we choose to pass it regardless of customP
		// var customP = (log2p[0] != params.LogPi()[0])
		// if !customP {
		// 	SubringParamsStc = nil
		// }
		kgenSubring := rlwe.NewKeyGenerator(SubringParamsStC)
		kgenSubring.ResetSubringExtDegree(1) // to mask skDense
		subringSkStC = kgenSubring.GenSecretKeyNew()
		EvkInStC = kgenSubring.GenEvaluationKeyNew(skDense, subringSkStC, StCKeySwitchEvkParams)

		// ModUp uses the regular key
		if !FlagKSinModup {
			kgenDense := rlwe.NewKeyGenerator(params)
			EvkBeforeModup = kgenDense.GenEvaluationKeyNew(subringSkStC, skDense)
			return
		}
		prevSk = subringSkStC
		prevSkExtDegree = StCparams.SubringExtDegree
	}

	// now FlagKSinStC = 0/1; FlagKSinModup = 1
	var ModupKeySwitchParams rlwe.Parameters
	var ModupKeySwitchEvkParams rlwe.EvaluationKeyParameters

	if p.EphemeralSecretWeight == 0 {
		if FlagKSinStC && StCparams.SubringExtDegree == p.SubringSecretExtDegree {
			// ModUp still uses the subring secret from StC
			kgenDense := rlwe.NewKeyGenerator(params)
			EvkAfterModup = kgenDense.GenEvaluationKeyNew(prevSk, skDense)
			return
		}
		if p.SubringSecretExtDegree != p.CoeffsToSlotsParameters.SubringExtDegree {
			panic("subring extension degrees in CtS & Modup should be the same")
		}
		// otherwise, a secret in a different subring is used
		subringDeg := params.N() / p.SubringSecretExtDegree
		// use custom pi
		log2p := []int{0}
		// we believe log2p[0] is large enough in most cases
		//  so we do not check for negative log2p[0] or fix the stddev, and determine the decomposition base automatically
		if subringDeg == 1<<12 {
			log2q0 := int(params.LogQi()[0])
			log2p[0] = min(106-log2q0, 61)
			nlimbs := (log2q0 + log2p[0] - 4) / (log2p[0] - 3)
			if nlimbs > 1 {
				ModupKeySwitchEvkParams.BaseTwoDecomposition = utils.Pointy((log2q0 + nlimbs - 1) / nlimbs)
			}
		} else if subringDeg == 1<<13 {
			log2p[0] = 61
		} else {
			panic("Only subring degrees = 2^12 or 2^13 are supported for now")
		}

		ModupKeySwitchParams, _ = rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: params.LogN(),
			Q:    params.Q()[:1],
			LogP: log2p,
			Xs:   ring.Ternary{P: 2.0 / 3, ExtDegree: p.SubringSecretExtDegree},
			// to mask prevSk
			Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 3.2 * 6,
				ExtDegree: max(p.SubringSecretExtDegree, prevSkExtDegree)},
		})
		SubringParamsModup = &ModupKeySwitchParams

		// append an extra 60-bit Qi for CtS
		extraQ, _, _ := rlwe.GenModuli(params.LogNthRoot(), []int{60}, nil, params.Q())
		SubringParamsCtSTmp, _ := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: params.LogN(),
			Q:    append(params.Q(), extraQ[0]), // no P here
			Xs:   ring.Ternary{P: 2.0 / 3, ExtDegree: p.SubringSecretExtDegree},
			Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 3.2 * 6,
				ExtDegree: p.SubringSecretExtDegree},
		})
		SubringParamsCtS = &SubringParamsCtSTmp
	} else { // sparse secret encapsulation
		ModupKeySwitchParams, _ = rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: params.LogN(),
			Q:    params.Q()[:1],
			P:    params.P()[:1],
		})
	}

	kgenSparse := rlwe.NewKeyGenerator(ModupKeySwitchParams)
	kgenDense := rlwe.NewKeyGenerator(params)
	if p.EphemeralSecretWeight == 0 { // subring secret
		skForModup = kgenSparse.GenSecretKeyNew()
	} else { // sparse secret
		skForModup = kgenSparse.GenSecretKeyWithHammingWeightNew(p.EphemeralSecretWeight)
	}

	EvkBeforeModup = kgenSparse.GenEvaluationKeyNew(prevSk, skForModup, ModupKeySwitchEvkParams)
	EvkAfterModup = kgenDense.GenEvaluationKeyNew(skForModup, skDense)
	return
}

// BinarySize returns the total binary size of the bootstrapper's keys.
func (b EvaluationKeys) BinarySize() (dLen int) {
	if b.EvkN1ToN2 != nil {
		dLen += b.EvkN1ToN2.BinarySize()
	}
	dLen++

	if b.EvkN2ToN1 != nil {
		dLen += b.EvkN2ToN1.BinarySize()
	}
	dLen++

	if b.EvkRealToCmplx != nil {
		dLen += b.EvkRealToCmplx.BinarySize()
	}
	dLen++

	if b.EvkCmplxToReal != nil {
		dLen += b.EvkCmplxToReal.BinarySize()
	}
	dLen++

	if b.EvkBeforeModUp != nil {
		dLen += b.EvkBeforeModUp.BinarySize()
	}
	dLen++

	if b.EvkAfterModUp != nil {
		dLen += b.EvkAfterModUp.BinarySize()
	}
	dLen++

	if b.MemEvaluationKeySet != nil {
		dLen += b.MemEvaluationKeySet.BinarySize()
	}
	dLen++

	return
}

// MarshalBinary encodes the object into a binary form on a newly allocated slices of bytes.
func (b EvaluationKeys) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(b.BinarySize())
	_, err = b.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary encodes a slices of bytes generated by MarshalBinary or WriteTo on the object.
func (b *EvaluationKeys) UnmarshalBinary(p []byte) (err error) {
	_, err = b.ReadFrom(buffer.NewBuffer(p))
	return
}

// WriteTo writes the object on an io.Writer. It implements the io.WriterTo
// interface, and will write exactly object.BinarySize() bytes on w.
//
// Unless w implements the buffer.Writer interface (see lattigo/utils/buffer/writer.go),
// it will be wrapped into a bufio.Writer. Since this requires allocations, it
// is preferable to pass a buffer.Writer directly:
//
//   - When writing multiple times to a io.Writer, it is preferable to first wrap the
//     io.Writer in a pre-allocated bufio.Writer.
//   - When writing to a pre-allocated var b []byte, it is preferable to pass
//     buffer.NewBuffer(b) as w (see lattigo/utils/buffer/buffer.go).
func (b EvaluationKeys) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		inc, err = writeEvkKey(b.EvkN1ToN2, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkN1ToN2 evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkN2ToN1, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkN2ToN1 evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkRealToCmplx, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkRealToCmplx evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkCmplxToReal, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkCmplxToReal evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkBeforeModUp, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkDenseToSparse evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkAfterModUp, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkSparseToDense evaluation key: %w", err)
		}
		n += inc

		if b.MemEvaluationKeySet != nil {
			if inc, err = buffer.WriteUint8(w, 1); err != nil {
				return inc, err
			}
			n += inc

			if inc, err = b.MemEvaluationKeySet.WriteTo(w); err != nil {
				return n + inc, err
			}
			n += inc

		} else {
			if inc, err = buffer.WriteUint8(w, 0); err != nil {
				return inc, err
			}
			n += inc
		}

		return n, w.Flush()
	default:
		return b.WriteTo(bufio.NewWriter(w))
	}
}

// ReadFrom reads on the object from an io.Writer. It implements the
// io.ReaderFrom interface.
//
// Unless r implements the buffer.Reader interface (see see lattigo/utils/buffer/reader.go),
// it will be wrapped into a bufio.Reader. Since this requires allocation, it
// is preferable to pass a buffer.Reader directly:
//
//   - When reading multiple values from a io.Reader, it is preferable to first
//     first wrap io.Reader in a pre-allocated bufio.Reader.
//   - When reading from a var b []byte, it is preferable to pass a buffer.NewBuffer(b)
//     as w (see lattigo/utils/buffer/buffer.go).
func (b *EvaluationKeys) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		b.EvkN1ToN2, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkN1ToN2 evaluation key: %w", err)
		}
		n += inc

		b.EvkN2ToN1, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkN2ToN1 evaluation key: %w", err)
		}
		n += inc

		b.EvkRealToCmplx, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkRealToCmplx evaluation key: %w", err)
		}
		n += inc

		b.EvkCmplxToReal, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkCmplxToReal evaluation key: %w", err)
		}
		n += inc

		b.EvkBeforeModUp, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkDenseToSparse evaluation key: %w", err)
		}
		n += inc

		b.EvkAfterModUp, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkSparseToDense evaluation key: %w", err)
		}
		n += inc

		var hasKey uint8

		if inc, err = buffer.ReadUint8(r, &hasKey); err != nil {
			return inc, err
		}
		n += inc

		if hasKey == 1 {

			b.MemEvaluationKeySet = new(rlwe.MemEvaluationKeySet)

			if inc, err = b.MemEvaluationKeySet.ReadFrom(r); err != nil {
				return inc, err
			}

			n += inc
		}

		return n, nil

	default:
		return b.ReadFrom(bufio.NewReader(r))
	}
}

// writeEvkKey is a helper function for marshalling a bootstrapping evaluation key.
func writeEvkKey(key *rlwe.EvaluationKey, w buffer.Writer) (n int64, err error) {
	var inc int64

	if key != nil {
		if inc, err = buffer.WriteUint8(w, 1); err != nil {
			return inc, err
		}
		n += inc

		if inc, err = key.WriteTo(w); err != nil {
			return inc, err
		}
		n += inc
	} else {
		if inc, err = buffer.WriteUint8(w, 0); err != nil {
			return inc, err
		}
		n += inc
	}
	return
}

// readEvkKey is a helper function for unmarshalling a bootstrapping evaluation key.
func readEvkKey(r buffer.Reader) (key *rlwe.EvaluationKey, n int64, err error) {
	var (
		inc    int64
		hasKey uint8
	)

	if inc, err = buffer.ReadUint8(r, &hasKey); err != nil {
		return nil, inc, err
	}
	n += inc

	if hasKey == 1 {

		key = new(rlwe.EvaluationKey)

		if inc, err = key.ReadFrom(r); err != nil {
			return nil, n + inc, err
		}

		n += inc
	}
	return
}
