package lowbootstrap

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// FusedRecovery performs the public single-message masked-lift/trace map.
// Secrets are used only by the constructor to generate genuine evaluation keys.
// No decryption or ideal key-switch oracle appears in Apply.
type FusedRecovery struct {
	Params      ckks.Parameters
	R           int
	Alpha       *big.Float
	OutputScale rlwe.Scale
	Unit        []*big.Int
	BranchKeys  []*rlwe.EvaluationKey
	Eval        *ckks.Evaluator
	switches    *rlwe.Evaluator
	tieRNG      *rand.Rand
}

// ShallowCopy shares immutable parameters and evaluation keys, while allocating
// independent evaluator scratch buffers and a separate rounding RNG. Neither
// secret keys nor key generation are needed to create a concurrent worker.
func (f *FusedRecovery) ShallowCopy(tieSeed int64) *FusedRecovery {
	return &FusedRecovery{Params: f.Params, R: f.R,
		Alpha:       new(big.Float).SetPrec(f.Alpha.Prec()).Set(f.Alpha),
		OutputScale: f.OutputScale, Unit: f.Unit, BranchKeys: f.BranchKeys,
		Eval: f.Eval.ShallowCopy(), switches: f.switches.ShallowCopy(),
		tieRNG: rand.New(rand.NewSource(tieSeed))}
}

// SetRoundingSeed is for reproducible serial/parallel comparisons. Call only
// while this worker is idle. A branch's seed never depends on scheduling.
func (f *FusedRecovery) SetRoundingSeed(seed int64) {
	f.tieRNG.Seed(seed)
}

func NewFusedRecovery(params ckks.Parameters, R int, alpha *big.Float, scale rlwe.Scale,
	unit []*big.Int, sparse, dense *rlwe.SecretKey, evk rlwe.EvaluationKeySet, tieSeed int64, keyParams ...rlwe.EvaluationKeyParameters) (*FusedRecovery, error) {
	if R < 1 || R&(R-1) != 0 || params.N()%(2*R) != 0 {
		return nil, fmt.Errorf("invalid guard ratio")
	}
	levelQ, levelP, baseTwo, _ := rlwe.ResolveEvaluationKeyParameters(*params.GetRLWEParameters(), keyParams)
	if err := ValidateBaseTwoDecompositionCoverage(params, levelQ, levelP, baseTwo); err != nil {
		return nil, fmt.Errorf("fused branch keys: %w", err)
	}
	f := &FusedRecovery{Params: params, R: R, Alpha: new(big.Float).SetPrec(192).Set(alpha),
		OutputScale: scale, Unit: unit, Eval: ckks.NewEvaluator(params, evk),
		switches: rlwe.NewEvaluator(params, nil), tieRNG: rand.New(rand.NewSource(tieSeed))}
	f.BranchKeys = make([]*rlwe.EvaluationKey, R)
	kgen := rlwe.NewKeyGenerator(params)
	for r := 0; r < R; r++ {
		source := sparse
		if r != 0 {
			source = rlwe.NewSecretKey(params)
			params.RingQP().AutomorphismNTT(sparse.Value, params.GaloisElementForRotation(r), source.Value)
		}
		f.BranchKeys[r] = kgen.GenEvaluationKeyNew(source, dense, keyParams...)
	}
	return f, nil
}

func FusedGaloisElements(params ckks.Parameters, R int) []uint64 {
	els := []uint64{params.GaloisElementForComplexConjugation()}
	for stride := R; stride < params.N()/2; stride *= 2 {
		els = append(els, params.GaloisElementForRotation(stride))
	}
	return els
}

func powerMod(a uint64, k int, m uint64) uint64 {
	z := uint64(1)
	for ; k > 0; k >>= 1 {
		if k&1 != 0 {
			z = z * a % m
		}
		a = a * a % m
	}
	return z
}

// The mask is represented in degree 2R; at full dimension it is sparsely embedded.
// P_j=cos(pi*j/(2R))/R. tau^(-r)(P) is an exact signed permutation of these values.
func rotatedMask(R, r int) []*big.Float {
	d := 2 * R
	prec := uint(192)
	p := make([]*big.Float, d)
	exponent := powerMod(5, (R-r)%R, uint64(2*d))
	for j := 0; j < d; j++ {
		x := new(big.Float).SetPrec(prec).Mul(bignum.Pi(prec), new(big.Float).SetInt64(int64(j)))
		x.Quo(x, new(big.Float).SetInt64(int64(d)))
		v := bignum.Cos(x)
		if j == R {
			v.SetInt64(0)
		}
		v.Quo(v, new(big.Float).SetInt64(int64(R)))
		idx := int(uint64(j) * exponent % uint64(2*d))
		if idx >= d {
			v.Neg(v)
		}
		p[idx%d] = v
	}
	return p
}

func nearestInteger(x *big.Float) *big.Int {
	z := new(big.Float).SetPrec(x.Prec()).Set(x)
	half := new(big.Float).SetPrec(x.Prec()).SetFloat64(0.5)
	if z.Sign() < 0 {
		z.Sub(z, half)
	} else {
		z.Add(z, half)
	}
	out, _ := z.Int(nil)
	return out
}

func maskRound(coeffs []*big.Int, mask []*big.Float, alpha *big.Float) []*big.Int {
	n, d := len(coeffs), len(mask)
	stride := n / d
	out := make([]*big.Int, n)
	factors := make([]*big.Float, d)
	for j := range mask {
		factors[j] = new(big.Float).SetPrec(192).Mul(mask[j], alpha)
	}
	sum := new(big.Float).SetPrec(192)
	term := new(big.Float).SetPrec(192)
	for k := 0; k < n; k++ {
		sum.SetInt64(0)
		for j, factor := range factors {
			src := k - stride*j
			neg := src < 0
			if neg {
				src += n
			}
			term.SetInt(coeffs[src])
			term.Mul(term, factor)
			if neg {
				sum.Sub(sum, term)
			} else {
				sum.Add(sum, term)
			}
		}
		out[k] = nearestInteger(sum)
	}
	return out
}

// normalizedHalf uses full centered CRT components. Fresh pseudorandom tie
// choices are reproducible diagnostics, not an asserted failure-probability proof.
func (f *FusedRecovery) normalizedHalf(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	components, err := CenteredCiphertextComponents(f.Params, ct)
	if err != nil {
		return nil, err
	}
	out := ct.CopyNew()
	two := big.NewInt(2)
	rem := new(big.Int)
	for k, c := range components {
		for i, v := range c {
			sign := v.Sign()
			c[i] = new(big.Int)
			c[i].QuoRem(v, two, rem)
			if rem.Sign() != 0 && f.tieRNG.Intn(2) == 1 {
				c[i].Add(c[i], big.NewInt(int64(sign)))
			}
		}
		out.Value[k], err = PolynomialFromCoefficients(f.Params, c, ct.Level(), true, false)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Apply takes the ORIGINAL low-q leaf ciphertext. It returns two real focused
// ciphertexts with ideal values (I_Re+z_Re/beta)/K and (I_Im+z_Im/beta)/K
// when Alpha=OutputScale/(2*R*gF*q*K).
func (f *FusedRecovery) Apply(lowParams ckks.Parameters, low *rlwe.Ciphertext) (*rlwe.Ciphertext, *rlwe.Ciphertext, error) {
	if low == nil || lowParams.N() != f.Params.N() || low.Level() != 0 || low.Degree() != 1 || !low.IsNTT || low.IsMontgomery || lowParams.Q()[0] != f.Params.Q()[0] || f.Alpha.Sign() <= 0 {
		return nil, nil, fmt.Errorf("expected level-zero leaf ciphertext")
	}
	original, err := CenteredCiphertextComponents(lowParams, low)
	if err != nil {
		return nil, nil, err
	}
	level := f.Params.MaxLevel()
	var sum *rlwe.Ciphertext
	for r := 0; r < f.R; r++ {
		c := ckks.NewCiphertext(f.Params, 1, level)
		*c.MetaData = *low.MetaData
		c.Scale = f.OutputScale
		for k, coeffs := range original {
			rounded := maskRound(coeffs, rotatedMask(f.R, r), f.Alpha)
			c.Value[k], err = PolynomialFromCoefficients(f.Params, rounded, level, true, false)
			if err != nil {
				return nil, nil, err
			}
		}
		if r != 0 {
			rotated := c.CopyNew()
			for k := range c.Value {
				f.Params.RingQ().AutomorphismNTT(c.Value[k], f.Params.GaloisElementForRotation(r), rotated.Value[k])
			}
			c = rotated
		}
		switched := c.CopyNew()
		if err = f.switches.ApplyEvaluationKey(c, f.BranchKeys[r], switched); err != nil {
			return nil, nil, err
		}
		if sum == nil {
			sum = switched
		} else if err = f.Eval.Add(sum, switched, sum); err != nil {
			return nil, nil, err
		}
	}
	for stride := f.R; stride < f.Params.N()/2; stride *= 2 {
		half, e := f.normalizedHalf(sum)
		if e != nil {
			return nil, nil, e
		}
		rotated := half.CopyNew()
		if err = f.Eval.Automorphism(half, f.Params.GaloisElementForRotation(stride), rotated); err != nil {
			return nil, nil, err
		}
		if err = f.Eval.Add(half, rotated, sum); err != nil {
			return nil, nil, err
		}
	}
	conjugate := sum.CopyNew()
	if err = f.Eval.Automorphism(sum, f.Params.GaloisElementForComplexConjugation(), conjugate); err != nil {
		return nil, nil, err
	}
	realPart, err := f.Eval.AddNew(sum, conjugate)
	if err != nil {
		return nil, nil, err
	}
	imagPart, err := f.Eval.SubNew(sum, conjugate)
	if err != nil {
		return nil, nil, err
	}
	minusI := make([]*big.Int, f.Params.N())
	for i := range minusI {
		minusI[i] = new(big.Int)
	}
	minusI[f.Params.N()/2].SetInt64(-1)
	imagPart, err = MulIntegerPolynomial(f.Params, imagPart, minusI)
	if err != nil {
		return nil, nil, err
	}
	realPart, err = MulIntegerPolynomial(f.Params, realPart, f.Unit)
	if err != nil {
		return nil, nil, err
	}
	imagPart, err = MulIntegerPolynomial(f.Params, imagPart, f.Unit)
	if err != nil {
		return nil, nil, err
	}
	realPart.Scale = f.OutputScale
	imagPart.Scale = f.OutputScale
	return realPart, imagPart, nil
}
