package lowbootstrap

// An experimental auxiliary-P ring entry. P need not admit an NTT. Its public
// polynomial products are computed EXACTLY using a wider temporary NTT basis.
// No encryption or secret-key sample is published at the temporary moduli.
// The Q and P key components together are ordinary CRT RLWE samples modulo qP.
// This is a correctness prototype, not a new security reduction.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type SmallPEntry struct {
	Top, Leaf              ckks.Parameters
	P                      uint64
	KeyQ                   *rlwe.EvaluationKey
	KeyP                   [][2]ring.Poly // NTT+Montgomery, deterministic public cache
	Work                   *ring.Ring
	eval                   *rlwe.Evaluator
	crtProduct, crtInverse uint64
}

func uniformSmallMod(n int, p uint64) ([]uint64, error) {
	if p < 2 || p >= 1<<16 {
		return nil, fmt.Errorf("P outside supported uint16 range")
	}
	out := make([]uint64, n)
	buf := make([]byte, 2*n+128)
	limit := uint64(1<<16) / p * p
	for at := 0; at < n; {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		for j := 0; j+1 < len(buf) && at < n; j += 2 {
			v := uint64(binary.LittleEndian.Uint16(buf[j:]))
			if v >= limit {
				continue
			}
			out[at] = v % p
			at++
		}
	}
	return out, nil
}

// NewSmallPEntry retains only public evaluation keys. Secret-key access is
// confined to this generation routine, including extraction of the key error
// needed to generate its correlated CRT P component.
func NewSmallPEntry(top, leaf ckks.Parameters, skTop, skLeaf *rlwe.SecretKey, p, workPrime uint64) (*SmallPEntry, error) {
	// Equal dimensions implement ordinary same-ring SSE entry. In this case
	// ApplyTop performs no coefficient projection, split or ring change.
	if top.LogN() < leaf.LogN() || leaf.MaxLevel() != 0 || top.Q()[0] != leaf.Q()[0] ||
		top.RingType() != ring.Standard || leaf.RingType() != ring.Standard {
		return nil, fmt.Errorf("small-P entry requires compatible standard rings and one leaf Q prime")
	}
	q := top.Q()[0]
	if !ring.IsPrime(p) || p >= 1<<16 || p >= q || workPrime >= 1<<31 || p == workPrime || q == workPrime {
		return nil, fmt.Errorf("invalid auxiliary primes")
	}
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: top.LogN(), Q: []uint64{q}, LogDefaultScale: top.LogDefaultScale()})
	if err != nil {
		return nil, err
	}
	if err = ValidateBaseTwoDecompositionCoverage(params, 0, -1, 1); err != nil {
		return nil, err
	}
	if skTop == nil || skLeaf == nil || skTop.Value.Q.N() != top.N() || skLeaf.Value.Q.N() != leaf.N() {
		return nil, fmt.Errorf("invalid secrets")
	}
	rq := params.RingQ()
	scaled := rlwe.NewSecretKey(params)
	copy(scaled.Value.Q.Coeffs[0], skTop.Value.Q.Coeffs[0])
	rq.MulScalar(scaled.Value.Q, p, scaled.Value.Q)
	lq, lp, base := 0, -1, 1
	key := rlwe.NewKeyGenerator(params).GenEvaluationKeyNew(scaled, skLeaf, rlwe.EvaluationKeyParameters{LevelQ: &lq, LevelP: &lp, BaseTwoDecomposition: &base})
	digits := len(key.Value[0])
	bound := new(big.Int).SetUint64(uint64(digits) * uint64(top.N()) * (p - 1))
	product := new(big.Int).Mul(new(big.Int).SetUint64(q), new(big.Int).SetUint64(workPrime))
	if product.BitLen() > 62 || new(big.Int).Lsh(bound, 1).Cmp(product) >= 0 {
		return nil, fmt.Errorf("temporary CRT product must exceed twice exact convolution bound and fit 62 bits")
	}
	work, err := ring.NewRing(top.N(), []uint64{q, workPrime})
	if err != nil {
		return nil, err
	}
	inv := new(big.Int).ModInverse(new(big.Int).SetUint64(q), new(big.Int).SetUint64(workPrime))
	if inv == nil {
		return nil, fmt.Errorf("noncoprime work primes")
	}
	e := &SmallPEntry{Top: params, Leaf: leaf, P: p, KeyQ: key, KeyP: make([][2]ring.Poly, digits), Work: work, eval: rlwe.NewEvaluator(params, nil), crtProduct: product.Uint64(), crtInverse: inv.Uint64()}
	target := rq.NewPoly()
	ring.MapSmallDimensionToLargerDimensionNTT(skLeaf.Value.Q, target)
	targetCoeff, err := CenteredCoefficients(params, target, true, true)
	if err != nil {
		return nil, err
	}
	type term struct {
		index int
		sign  int64
	}
	support := []term{}
	for i, x := range targetCoeff {
		if !x.IsInt64() || x.Int64() < -1 || x.Int64() > 1 {
			return nil, fmt.Errorf("target is not ternary")
		}
		if x.Sign() != 0 {
			support = append(support, term{i, x.Int64()})
		}
	}
	source := rq.NewPoly()
	rq.IMForm(scaled.Value.Q, source)
	for j := 0; j < digits; j++ {
		aq, bq, phase, msg := rq.NewPoly(), rq.NewPoly(), rq.NewPoly(), rq.NewPoly()
		rq.IMForm(key.Value[0][j][0].Q, bq)
		rq.IMForm(key.Value[0][j][1].Q, aq)
		rq.MulCoeffsMontgomery(aq, target, phase)
		rq.Add(phase, bq, phase)
		rq.MulScalar(source, uint64(1)<<j, msg)
		rq.Sub(phase, msg, phase)
		rq.INTT(phase, phase)
		a, err := uniformSmallMod(top.N(), p)
		if err != nil {
			return nil, err
		}
		conv := make([]int64, top.N())
		for _, s := range support {
			cut := top.N() - s.index
			for i := 0; i < cut; i++ {
				conv[i+s.index] += s.sign * int64(a[i])
			}
			for i := cut; i < top.N(); i++ {
				conv[i-cut] -= s.sign * int64(a[i])
			}
		}
		b := make([]uint64, top.N())
		for i, x := range phase.Coeffs[0] {
			v := int64(x)
			if x > q/2 {
				v -= int64(q)
			}
			if v < -64 || v > 64 {
				return nil, fmt.Errorf("Q key error extraction failed: digit %d coefficient %d error %d", j, i, v)
			}
			u := (v - conv[i]) % int64(p)
			if u < 0 {
				u += int64(p)
			}
			b[i] = uint64(u)
		}
		for component, coeff := range [][]uint64{b, a} {
			poly := work.NewPoly()
			for limb := 0; limb < 2; limb++ {
				copy(poly.Coeffs[limb], coeff)
			}
			work.NTT(poly, poly)
			work.MForm(poly, poly)
			e.KeyP[j][component] = poly
		}
	}
	return e, nil
}

// CachedKeyBytes counts Q key plus both redundant public NTT limbs of P keys.
// This is an upper bound on public key storage, not a compressed serialization.
func (e *SmallPEntry) CachedKeyBytes() int { return e.KeyQ.BinarySize() + len(e.KeyP)*2*2*e.Top.N()*8 }

func (e *SmallPEntry) pProduct(c1 ring.Poly) ([2][]int64, error) {
	var out [2][]int64
	rq := e.Top.RingQ()
	coeff := rq.NewPoly()
	rq.INTT(c1, coeff)
	if len(e.KeyP) < bits.Len64(e.Top.Q()[0]-1) {
		return out, fmt.Errorf("digit coverage failure")
	}
	acc := [2]ring.Poly{e.Work.NewPoly(), e.Work.NewPoly()}
	digit := e.Work.NewPoly()
	tmp := e.Work.NewPoly()
	for j := range e.KeyP {
		for limb := 0; limb < 2; limb++ {
			for i, x := range coeff.Coeffs[0] {
				digit.Coeffs[limb][i] = (x >> j) & 1
			}
		}
		e.Work.NTT(digit, digit)
		for c := 0; c < 2; c++ {
			e.Work.MulCoeffsMontgomery(digit, e.KeyP[j][c], tmp)
			e.Work.Add(acc[c], tmp, acc[c])
		}
	}
	q0, q1 := e.Work.ModuliChain()[0], e.Work.ModuliChain()[1]
	for c := 0; c < 2; c++ {
		e.Work.INTT(acc[c], acc[c])
		out[c] = make([]int64, e.Top.N())
		for i, a := range acc[c].Coeffs[0] {
			b := acc[c].Coeffs[1][i]
			t := ((b + q1 - a%q1) % q1 * e.crtInverse) % q1
			x := a + q0*t
			v := int64(x)
			if x > e.crtProduct/2 {
				v -= int64(e.crtProduct)
			}
			v %= int64(e.P)
			if v < 0 {
				v += int64(e.P)
			}
			if v > int64(e.P/2) {
				v -= int64(e.P)
			}
			out[c][i] = v
		}
	}
	return out, nil
}

func (e *SmallPEntry) ApplyTop(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if ct == nil || ct.MetaData == nil || ct.LogN() != e.Top.LogN() || ct.Degree() != 1 || ct.Level() != 0 || !ct.IsNTT || ct.IsMontgomery {
		return nil, fmt.Errorf("small-P entry expects ordinary NTT degree-one top ciphertext at level0")
	}
	vp, err := e.pProduct(ct.Value[1])
	if err != nil {
		return nil, err
	}
	out := ckks.NewCiphertext(e.Top, 1, 0)
	out.MetaData = ct.MetaData.CopyNew()
	e.eval.GadgetProduct(0, ct.Value[1], &e.KeyQ.GadgetCiphertext, out)
	rq := e.Top.RingQ()
	lift := rq.NewPoly()
	q := e.Top.Q()[0]
	inv := new(big.Int).ModInverse(new(big.Int).SetUint64(e.P), new(big.Int).SetUint64(q)).Uint64()
	for c := 0; c < 2; c++ {
		for i, v := range vp[c] {
			if v < 0 {
				lift.Coeffs[0][i] = q - uint64(-v)
			} else {
				lift.Coeffs[0][i] = uint64(v)
			}
		}
		rq.NTT(lift, lift)
		rq.Sub(out.Value[c], lift, out.Value[c])
		rq.MulScalar(out.Value[c], inv, out.Value[c])
	}
	rq.Add(out.Value[0], ct.Value[0], out.Value[0])
	return out, nil
}

func (e *SmallPEntry) ApplyAll(ct *rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	switched, err := e.ApplyTop(ct)
	if err != nil {
		return nil, err
	}
	return SplitCoefficientBranches(e.Top, e.Leaf, switched)
}
