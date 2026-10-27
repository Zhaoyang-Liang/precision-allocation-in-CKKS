package bench

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/big"
	"sort"
	"time"

	cp "github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type ParamReport struct {
	N         int `json:"n"`
	Slots     int `json:"slots"`
	Q, P      []string
	LogQP     float64 `json:"log2_qp_display"`
	ProductQP string  `json:"qp_exact"`
	Secret    string  `json:"secret_distribution"`
	Error     string  `json:"error_distribution"`
}

func paramReport(p ckks.Parameters) ParamReport {
	qp := new(big.Int).Mul(prod(p.Q()), prod(p.P()))
	return ParamReport{p.N(), p.MaxSlots(), primeStrings(p.Q()), primeStrings(p.P()), log2Rat(new(big.Rat).SetInt(qp)), qp.String(), "ternary P=2/3, H=0", "discrete Gaussian sigma=3.2, bound=19.2"}
}

type KeyReport struct {
	ID                      string `json:"id"`
	Kind                    string `json:"kind"`
	SHA256                  string `json:"sha256"`
	SerializedBytes         Count  `json:"serialized_bytes"`
	CoefficientPayloadBytes Count  `json:"coefficient_payload_bytes"`
	LevelQ                  int    `json:"level_q"`
	LevelP                  int    `json:"level_p"`
	GaloisElement           string `json:"galois_element,omitempty"`
	RNSBlocks               int    `json:"rns_blocks,omitempty"`
	DigitCounts             []int  `json:"digits_per_rns_block,omitempty"`
	Compressed              bool   `json:"compressed"`
}

// Stream serialization rather than allocating a several-hundred-MB key copy.
// Actual written length is cross-checked against both WriteTo and BinarySize.
type binaryWriter interface {
	WriteTo(io.Writer) (int64, error)
	BinarySize() int
}
type hashCount struct {
	h hash.Hash
	n uint64
}

func (w *hashCount) Write(p []byte) (int, error) { n, e := w.h.Write(p); w.n += uint64(n); return n, e }
func measureSerialized(x binaryWriter) (Count, string, error) {
	w := &hashCount{h: sha256.New()}
	b := bufio.NewWriterSize(w, 64*1024)
	n, e := x.WriteTo(b)
	if e != nil {
		return 0, "", e
	}
	if e = b.Flush(); e != nil {
		return 0, "", e
	}
	if n < 0 || uint64(n) != w.n || uint64(x.BinarySize()) != w.n {
		return 0, "", fmt.Errorf("serialized size mismatch: actual=%d write=%d reported=%d", w.n, n, x.BinarySize())
	}
	return Count(w.n), fmt.Sprintf("%x", w.h.Sum(nil)), nil
}

func publicKeyReport(pk *rlwe.PublicKey) (KeyReport, error) {
	n, h, e := measureSerialized(pk)
	if e != nil {
		return KeyReport{}, e
	}
	var payload uint64
	for _, p := range pk.Value {
		for _, limb := range p.Q.Coeffs {
			payload += 8 * uint64(len(limb))
		}
		for _, limb := range p.P.Coeffs {
			payload += 8 * uint64(len(limb))
		}
	}
	return KeyReport{ID: h, Kind: "public", SHA256: h, SerializedBytes: n, CoefficientPayloadBytes: Count(payload), LevelQ: pk.LevelQ(), LevelP: pk.Value.LevelP()}, nil
}
func gadgetReport(kind string, x binaryWriter, g *rlwe.GadgetCiphertext, gal uint64) (KeyReport, error) {
	n, h, e := measureSerialized(x)
	if e != nil {
		return KeyReport{}, e
	}
	var payload uint64
	for _, row := range g.Value {
		for _, vec := range row {
			for _, p := range vec {
				for _, a := range p.Q.Coeffs {
					payload += 8 * uint64(len(a))
				}
				for _, a := range p.P.Coeffs {
					payload += 8 * uint64(len(a))
				}
			}
		}
	}
	r := KeyReport{ID: h, Kind: kind, SHA256: h, SerializedBytes: n, CoefficientPayloadBytes: Count(payload), LevelQ: g.LevelQ(), LevelP: g.LevelP(), RNSBlocks: len(g.Value), DigitCounts: g.BaseTwoDecompositionVectorSize(), Compressed: false}
	if gal != 0 {
		r.GaloisElement = fmt.Sprint(gal)
	}
	return r, nil
}

type keyFamily struct {
	P            ckks.Parameters
	SK           *rlwe.SecretKey
	PK           *rlwe.PublicKey
	KG           *rlwe.KeyGenerator
	Keys         *rlwe.MemEvaluationKeySet
	Rows         []KeyReport
	KeygenNS     Count
	AccountingNS Count
}

func newKeyFamily(p ckks.Parameters) (*keyFamily, error) {
	f := &keyFamily{P: p}
	t := time.Now()
	f.KG = rlwe.NewKeyGenerator(p)
	f.SK = f.KG.GenSecretKeyNew()
	f.PK = f.KG.GenPublicKeyNew(f.SK)
	f.KeygenNS = Count(time.Since(t).Nanoseconds())
	t = time.Now()
	row, e := publicKeyReport(f.PK)
	if e != nil {
		return nil, e
	}
	f.Rows = []KeyReport{row}
	f.AccountingNS = Count(time.Since(t).Nanoseconds())
	return f, nil
}

func compatiblePrefix(a, b ckks.Parameters) bool {
	if a.N() != b.N() || len(a.P()) != len(b.P()) || len(a.Q()) < len(b.Q()) {
		return false
	}
	for i, q := range b.Q() {
		if a.Q()[i] != q {
			return false
		}
	}
	for i, p := range a.P() {
		if p != b.P()[i] {
			return false
		}
	}
	return true
}

func (f *keyFamily) prepareKeys(rotLevels map[int]int, relinLevel, conjugateLevel int) (Count, Count, error) {
	var gks []*rlwe.GaloisKey
	var rk *rlwe.RelinearizationKey
	rots := make([]int, 0, len(rotLevels))
	for r := range rotLevels {
		rots = append(rots, r)
	}
	sort.Ints(rots)
	t := time.Now()
	for _, rot := range rots {
		l := rotLevels[rot]
		gks = append(gks, f.KG.GenGaloisKeyNew(f.P.GaloisElementForRotation(rot), f.SK, rlwe.EvaluationKeyParameters{LevelQ: &l}))
	}
	if conjugateLevel >= 0 {
		gks = append(gks, f.KG.GenGaloisKeyNew(f.P.GaloisElementForComplexConjugation(), f.SK, rlwe.EvaluationKeyParameters{LevelQ: &conjugateLevel}))
	}
	if relinLevel >= 0 {
		rk = f.KG.GenRelinearizationKeyNew(f.SK, rlwe.EvaluationKeyParameters{LevelQ: &relinLevel})
	}
	f.Keys = rlwe.NewMemEvaluationKeySet(rk, gks...)
	gen := Count(time.Since(t).Nanoseconds())
	t = time.Now()
	for _, k := range gks {
		kind := "rotation"
		if k.GaloisElement == f.P.GaloisElementForComplexConjugation() {
			kind = "conjugation"
		}
		r, e := gadgetReport(kind, k, &k.GadgetCiphertext, k.GaloisElement)
		if e != nil {
			return gen, 0, e
		}
		f.Rows = append(f.Rows, r)
	}
	if rk != nil {
		r, e := gadgetReport("relinearization", rk, &rk.GadgetCiphertext, 0)
		if e != nil {
			return gen, 0, e
		}
		f.Rows = append(f.Rows, r)
	}
	return gen, Count(time.Since(t).Nanoseconds()), nil
}

func rotations(b BranchSpec) []int {
	stride := 2
	if b.Layout == "compact" || b.Layout == "real_imag" || b.Layout == "paired_compact" {
		stride = 1
	}
	if b.Paired() {
		return []int{stride, 2 * stride, 4 * stride}
	}
	return []int{stride, 2 * stride, 4 * stride, 8 * stride}
}

type branchRuntime struct {
	NativeOutput     *rlwe.Ciphertext
	NativePhaseSum   Count
	ExpectedGraph    PolynomialGraph
	ActualGraph      *PolynomialGraph
	ApproxPolynomial *bignum.Polynomial
	PolyEvaluator    *cp.Evaluator
	Spec             BranchSpec
	P                ckks.Parameters
	Family           *keyFamily
	Encoder          *ckks.Encoder
	Evaluator        *ckks.Evaluator
	Representation   *Representation
	Map              SlotMapping
	Input            *rlwe.Ciphertext
	InputWire        []byte
	InputReport      CipherReport
	Constants        []ConstantReport
	Scratch          ring.Poly
	EntryScratch     ring.Poly
	EntryMultipliers []*PublicMultiplier
	EntryRawScale    rlwe.Scale
	Center           *rlwe.Plaintext
	Imaginary        *PublicMultiplier
}

// Public client transform, separated from encryption for non-HE tests.
func inputValues(s *Suite, d *Dataset, b *branchRuntime) []*bignum.Complex {
	v := make([]*bignum.Complex, b.P.MaxSlots())
	for i := range v {
		v[i] = bignum.ToComplex(0, s.Precision)
	}
	for k, slot := range b.Map.Slots {
		i := b.Map.Business[k]
		x := d.Values[i]
		if s.Task == "mean16" {
			x = sub(x, big.NewRat(13, 16))
		}
		f := bf(x, s.Precision)
		f.Quo(f, b.Representation.Weights[i%2])
		component := 0
		if len(b.Map.Components) != 0 {
			component = b.Map.Components[k]
		}
		v[slot][component].Set(f)
	}
	return v
}

func encodeInput(s *Suite, d *Dataset, b *branchRuntime) (*rlwe.Ciphertext, error) {
	v := inputValues(s, d, b)
	pt := ckks.NewPlaintext(b.P, b.P.MaxLevel())
	pt.Scale = scale(pow2(b.Spec.ScaleBits))
	if e := b.Encoder.Encode(v, pt); e != nil {
		return nil, e
	}
	return rlwe.NewEncryptor(b.P, b.Family.PK).EncryptNew(pt)
}

type existingSource struct {
	Family   *keyFamily
	Inputs   [2]*rlwe.Ciphertext
	Reports  [2]CipherReport
	Wire     [2][]byte
	ClientNS Count
}

func prepareSource(s *Suite, d *Dataset) (*existingSource, error) {
	p, e := s.Source.Parameters.Build()
	if e != nil {
		return nil, e
	}
	f, e := newKeyFamily(p)
	if e != nil {
		return nil, e
	}
	src := &existingSource{Family: f}
	enc := ckks.NewEncoder(p, s.Precision)
	encrypt := rlwe.NewEncryptor(p, f.PK)
	for j := 0; j < 2; j++ {
		t := time.Now()
		v := make([]*bignum.Complex, p.MaxSlots())
		for i := range v {
			if i%2 == j {
				v[i] = bignum.ToComplex(bf(d.Values[i], s.Precision), s.Precision)
			} else {
				v[i] = bignum.ToComplex(0, s.Precision)
			}
		}
		pt := ckks.NewPlaintext(p, p.MaxLevel())
		pt.Scale = scale(pow2(s.Source.ScaleBitsLowHigh[j]))
		if e = enc.Encode(v, pt); e != nil {
			return nil, e
		}
		ct, err := encrypt.EncryptNew(pt)
		if err != nil {
			return nil, err
		}
		src.ClientNS += Count(time.Since(t).Nanoseconds())
		wire, round, rep, err := wireCipher(p, ct)
		if err != nil {
			return nil, err
		}
		src.Inputs[j], src.Wire[j], src.Reports[j] = round, wire, rep
	}
	return src, nil
}
