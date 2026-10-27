package lowbootstrap

import (
	"math"
	"math/big"
	"math/cmplx"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	commonlintrans "github.com/tuneinsight/lattigo/v6/circuits/common/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func shapedFiberTestParams(t *testing.T) ckks.Parameters {
	t.Helper()
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 8, LogQ: []int{55, 50}, LogP: []int{60}, LogDefaultScale: 40,
		Xs: ring.Ternary{H: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func shapedFiberTestUnit(p ckks.Parameters) ([]*big.Int, *big.Float) {
	// R4-s8 calibrated unit from the exact public-unit construction. Its
	// inverse identity is also checked below, independently of JSON loading.
	coefficients := []int64{1, 0, 2, -5, 0, 5, -2, 0}
	inverse := []int64{157, 145, 111, 60, 0, -60, -111, -145}
	product := make([]int64, len(coefficients))
	for i, a := range coefficients {
		for j, b := range inverse {
			if i+j < len(product) {
				product[i+j] += a * b
			} else {
				product[i+j-len(product)] -= a * b
			}
		}
	}
	for i, c := range product {
		if (i == 0 && c != 1) || (i != 0 && c != 0) {
			panic("test unit exact inverse check failed")
		}
	}
	full := make([]*big.Int, p.N())
	for i, c := range coefficients {
		full[i*p.N()/8] = big.NewInt(c)
	}
	focus, _, err := big.ParseFloat("0.001592801095292380318777608115407489525898125897625732015353119706004617323317155330637215232447673986", 10, 192, big.ToNearestEven)
	if err != nil {
		panic(err)
	}
	return full, focus
}

func decodeShapedFiberDiagonal(t *testing.T, p ckks.Parameters, matrix lintrans.LinearTransformation, offset int) []complex128 {
	t.Helper()
	pt := ckks.NewPlaintext(p, matrix.LevelQ)
	pt.MetaData = matrix.MetaData.CopyNew()
	pt.IsMontgomery = false
	p.RingQ().AtLevel(matrix.LevelQ).IMForm(matrix.Vec[offset].Q, pt.Value)
	values := make([]complex128, p.MaxSlots())
	if err := ckks.NewEncoder(p, 128).Decode(pt, values); err != nil {
		t.Fatal(err)
	}
	return values
}

func TestShapedFiberMatrixBSGSDiagonalQuantization(t *testing.T) {
	p := shapedFiberTestParams(t)
	const k, R = 4, 4
	diags, err := FiberDiagonals(p.MaxSlots(), k, R, true, math.Exp2(-10))
	if err != nil {
		t.Fatal(err)
	}
	unit, focus := shapedFiberTestUnit(p)
	scale := rlwe.NewScale(math.Exp2(14))
	shaped, err := NewShapedFiberMatrix(p, diags, 1, scale, R, unit, focus)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := NewFiberMatrix(p, diags, 1, scale)
	if err != nil {
		t.Fatal(err)
	}
	index, _, _ := commonlintrans.LinearTransformation(shaped).BSGSIndex()
	nontrivial := false
	maxShaped, maxOrdinary, maxGuard := 0.0, 0.0, 0.0
	for giant, babies := range index {
		if giant%R != 0 {
			nontrivial = true
		}
		for _, baby := range babies {
			offset := giant + baby
			sv := decodeShapedFiberDiagonal(t, p, shaped, offset)
			ov := decodeShapedFiberDiagonal(t, p, ordinary, offset)
			for s, target := range diags[offset] {
				// The evaluator applies the outer giant rotation to the stored
				// diagonal. This also tests the sign in tau_{-giant}(g).
				pos := (s + giant) % p.MaxSlots()
				if s%R == 0 {
					maxShaped = math.Max(maxShaped, cmplx.Abs(sv[pos]-target))
					maxOrdinary = math.Max(maxOrdinary, cmplx.Abs(ov[pos]-target))
				} else {
					maxGuard = math.Max(maxGuard, cmplx.Abs(sv[pos]))
				}
			}
		}
	}
	if !nontrivial {
		t.Fatal("test did not exercise a giant step that changes the unit")
	}
	if maxShaped >= maxOrdinary/20 || maxShaped > 1e-6 {
		t.Fatalf("encoding errors shaped=%g ordinary=%g guard=%g", maxShaped, maxOrdinary, maxGuard)
	}
	if shaped.Scale.Value.Cmp(&scale.Value) != 0 || shaped.LevelQ != ordinary.LevelQ || shaped.LevelP != ordinary.LevelP {
		t.Fatal("shaping changed matrix scale or modulus levels")
	}
	t.Logf("N1=%d nontrivial giant; diagonal data error ordinary %.3g shaped %.3g; shaped guard %.3g", shaped.N1, maxOrdinary, maxShaped, maxGuard)
}

func TestShapedFiberMatrixUnitOneExactAblation(t *testing.T) {
	p := shapedFiberTestParams(t)
	diags, err := FiberDiagonals(p.MaxSlots(), 4, 4, true, .013)
	if err != nil {
		t.Fatal(err)
	}
	unit := make([]*big.Int, p.N())
	unit[0] = big.NewInt(1)
	scale := rlwe.NewScale(math.Exp2(30))
	shaped, err := NewShapedFiberMatrix(p, diags, 1, scale, 4, unit, new(big.Float).SetPrec(192).SetInt64(1))
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := NewFiberMatrix(p, diags, 1, scale)
	if err != nil {
		t.Fatal(err)
	}
	if shaped.N1 != ordinary.N1 || !shaped.MetaData.Equal(ordinary.MetaData) {
		t.Fatal("unit-one matrix metadata differs from ordinary encoding")
	}
	for offset, sv := range shaped.Vec {
		ov := ordinary.Vec[offset]
		if !sv.Equal(&ov) {
			t.Fatalf("unit-one matrix differs in Q or P at diagonal %d", offset)
		}
	}
}

func TestShapedFiberMatrixEncrypted(t *testing.T) {
	p := shapedFiberTestParams(t)
	const k, R = 4, 4
	diags, err := FiberDiagonals(p.MaxSlots(), k, R, true, math.Exp2(-10))
	if err != nil {
		t.Fatal(err)
	}
	unit, focus := shapedFiberTestUnit(p)
	scale := rlwe.NewScale(math.Exp2(14))
	shaped, err := NewShapedFiberMatrix(p, diags, 1, scale, R, unit, focus)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := NewFiberMatrix(p, diags, 1, scale)
	if err != nil {
		t.Fatal(err)
	}
	kg := rlwe.NewKeyGenerator(p)
	sk := kg.GenSecretKeyNew()
	keys := rlwe.NewMemEvaluationKeySet(nil, kg.GenGaloisKeysNew(shaped.GaloisElements(p), sk)...)
	ev := ckks.NewEvaluator(p, keys)
	lt := lintrans.NewEvaluator(ev)
	encoder := ckks.NewEncoder(p, 128)
	values := make([]complex128, p.MaxSlots())
	for s := range values {
		j := s % k
		values[s] = complex(.11*float64(j+1), -.07*float64(j*j+1))
	}
	want := applyFiberPlain(diags, values)
	pt := ckks.NewPlaintext(p, 1)
	if err = encoder.Encode(values, pt); err != nil {
		t.Fatal(err)
	}
	ct, err := rlwe.NewEncryptor(p, sk).EncryptNew(pt)
	if err != nil {
		t.Fatal(err)
	}
	measure := func(matrix lintrans.LinearTransformation) (float64, float64) {
		result, e := lt.EvaluateNew(ct, matrix)
		if e != nil {
			t.Fatal(e)
		}
		expectedScale := ct.Scale.Mul(scale)
		if result.Level() != ct.Level() || result.Scale.Value.Cmp(&expectedScale.Value) != 0 {
			t.Fatal("matrix evaluation changed level or misreported its real scale")
		}
		decoded := make([]complex128, p.MaxSlots())
		if e = encoder.Decode(rlwe.NewDecryptor(p, sk).DecryptNew(result), decoded); e != nil {
			t.Fatal(e)
		}
		dataError, guard := 0.0, 0.0
		for s, v := range decoded {
			if s%R == 0 {
				dataError = math.Max(dataError, cmplx.Abs(v-want[s]))
			} else {
				guard = math.Max(guard, cmplx.Abs(v))
			}
		}
		return dataError, guard
	}
	ordinaryError, ordinaryGuard := measure(ordinary)
	shapedError, shapedGuard := measure(shaped)
	if shapedError >= ordinaryError/20 || shapedError > 2e-6 || shapedGuard > .01 {
		t.Fatalf("encrypted data ordinary=%g shaped=%g, guards ordinary=%g shaped=%g", ordinaryError, shapedError, ordinaryGuard, shapedGuard)
	}
	t.Logf("real ciphertext, same input and keys: data ordinary %.3g shaped %.3g; guards ordinary %.3g shaped %.3g", ordinaryError, shapedError, ordinaryGuard, shapedGuard)
}

func TestShapedFiberMatrixRejectsIncompatibleInputs(t *testing.T) {
	p := shapedFiberTestParams(t)
	diags, _ := FiberDiagonals(p.MaxSlots(), 4, 4, true, 1)
	unit, focus := shapedFiberTestUnit(p)
	scale := rlwe.NewScale(math.Exp2(30))
	wrongFocus := new(big.Float).SetPrec(192).Mul(focus, new(big.Float).SetInt64(2))
	if _, err := NewShapedFiberMatrix(p, diags, 1, scale, 4, unit, wrongFocus); err == nil {
		t.Fatal("accepted a focus inconsistent with integer unit")
	}
	diags[0][1] = 1
	if _, err := NewShapedFiberMatrix(p, diags, 1, scale, 4, unit, focus); err == nil {
		t.Fatal("accepted a nonzero ideal guard")
	}
	diags[0][1] = 0
	unit[1] = big.NewInt(1)
	if _, err := NewShapedFiberMatrix(p, diags, 1, scale, 4, unit, focus); err == nil {
		t.Fatal("accepted a unit outside the declared class subring")
	}
}
