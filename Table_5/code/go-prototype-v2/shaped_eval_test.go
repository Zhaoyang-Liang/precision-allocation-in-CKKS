package lowbootstrap

import (
	"fmt"
	"math"
	"math/big"
	"math/cmplx"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func shapedTestParams(t *testing.T) ckks.Parameters {
	t.Helper()
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 10, LogQ: []int{50, 28, 28, 28, 28, 28, 28, 28, 28, 28}, LogP: []int{53}, LogDefaultScale: 28, Xs: ring.Ternary{H: 32}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func shapedTestPlan(t *testing.T, p ckks.Parameters) mod1.Parameters {
	t.Helper()
	qd := float64(p.Q()[0]) / math.Exp2(math.Round(math.Log2(float64(p.Q()[0]))))
	m, err := mod1.NewParametersFromLiteral(p, mod1.ParametersLiteral{LevelQ: p.MaxLevel(), LogScale: 28, Mod1Type: mod1.CosDiscrete, Scaling: 1 / qd, LogMessageRatio: 13, K: 16, Mod1Degree: 47, DoubleAngle: 3})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMod1PlaintextOracleGrid(t *testing.T) {
	p := shapedTestParams(t)
	plan := shapedTestPlan(t, p)
	maxerr := 0.0
	maxk, maxz := 0, 0.0
	for k := -16; k <= 16; k++ {
		for _, z := range []float64{-0.9, -0.5, -0.1, 0, 0.1, 0.5, 0.9} {
			y := 8192 * Mod1PlaintextOracle(plan, (float64(k)+z/8192)/16)
			if math.Abs(y-z) > maxerr {
				maxerr = math.Abs(y - z)
				maxk = k
				maxz = z
			}
		}
	}
	t.Logf("compiled CosDiscrete degree %d, beta=8192, max oracle error %.4g (%.2f bits), I=%d z=%g; I3,z.25 error=%g", plan.Mod1Poly.Degree(), maxerr, -math.Log2(maxerr), maxk, maxz, 8192*Mod1PlaintextOracle(plan, (3+.25/8192)/16)-.25)
	if maxerr > math.Exp2(-23) {
		t.Fatalf("polynomial oracle exceeds 23-bit target: %g", maxerr)
	}
	qd := float64(p.Q()[0]) / math.Exp2(math.Round(math.Log2(float64(p.Q()[0]))))
	bad, err := mod1.NewParametersFromLiteral(p, mod1.ParametersLiteral{LevelQ: p.MaxLevel(), LogScale: 28, Mod1Type: mod1.CosDiscrete, Scaling: 1 / qd, LogMessageRatio: 13, K: 16, Mod1Degree: 31, DoubleAngle: 3})
	if err != nil {
		t.Fatal(err)
	}
	badErr := math.Abs(8192*Mod1PlaintextOracle(bad, (-15-.9/8192)/16) + .9)
	if badErr < .04 {
		t.Fatalf("expected degree31 DA3 edge failure disappeared: %g", badErr)
	}
	t.Logf("preserved degree31 DA3 regression: I=-15,z=-.9 error=%g", badErr)
}

// This is a deliberately insecure tiny-ring arithmetic test. It exercises actual
// encryption, relinearization, shaped plaintexts and all eight nonlinear levels;
// it is not a low-dimension security claim or an end-to-end bootstrap test.
func TestShapedEvalModEncryptedSmoke(t *testing.T) {
	runShapedEvalModEncryptedCase(t, 28, 32, 47, 3)
}

// Local diagnostic of the effect of working precision, using an intentionally
// insecure N=1024 even when H=1024. This is solely an arithmetic contract test.
func TestShapedEvalModEncryptedParameterProbe(t *testing.T) {
	for _, embits := range []int{28, 32} {
		for _, shape := range []struct{ degree, da int }{{47, 3}, {31, 4}} {
			t.Run(fmt.Sprintf("EM%d_H1024_degree%d_DA%d", embits, shape.degree, shape.da), func(t *testing.T) {
				runShapedEvalModEncryptedCase(t, embits, 1024, shape.degree, shape.da)
			})
		}
	}
}

func runShapedEvalModEncryptedCase(t *testing.T, embits, weight, degree, da int) {
	logq := []int{50}
	for j := 0; j < 9; j++ {
		logq = append(logq, embits)
	}
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 10, LogQ: logq, LogP: []int{53}, LogDefaultScale: embits, Xs: ring.Ternary{H: weight}})
	if err != nil {
		t.Fatal(err)
	}
	qd := float64(p.Q()[0]) / math.Exp2(math.Round(math.Log2(float64(p.Q()[0]))))
	plan, err := mod1.NewParametersFromLiteral(p, mod1.ParametersLiteral{LevelQ: p.MaxLevel(), LogScale: embits, Mod1Type: mod1.CosDiscrete, Scaling: 1 / qd, LogMessageRatio: 13, K: 16, Mod1Degree: degree, DoubleAngle: da})
	if err != nil {
		t.Fatal(err)
	}
	kg := rlwe.NewKeyGenerator(p)
	sk := kg.GenSecretKeyNew()
	base := ckks.NewEvaluator(p, rlwe.NewMemEvaluationKeySet(kg.GenRelinearizationKeyNew(sk)))
	u := []int64{59, -20, -21, 10, 0, -10, 21, 20}
	ui := []int64{98541, 91040, 69679, 37710, 0, -37710, -69679, -91040}
	embed := func(v []int64) []*big.Int {
		a := make([]*big.Int, p.N())
		for j := range a {
			a[j] = new(big.Int)
		}
		for j, x := range v {
			a[j*p.N()/len(v)].SetInt64(x)
		}
		return a
	}
	ev, err := NewShapedEvaluator(p, base, embed(u), embed(ui), 4, complex(0.00000253701532916460640889633278621236711683225093184736, 0))
	if err != nil {
		t.Fatal(err)
	}
	const z = 0.25
	const beta = 8192.0
	tin := (3 + z/beta) / 16
	pt, err := ev.ShapedPlaintext(tin, p.MaxLevel(), rlwe.NewScale(math.Exp2(float64(embits))))
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary encryption in inverse-unit coordinates, followed by exact g,
	// makes the encryption noise shaped as well as the plaintext rounding.
	p.RingQ().MulCoeffsMontgomery(pt.Value, ev.InverseNTT, pt.Value)
	ct, err := rlwe.NewEncryptor(p, sk).EncryptNew(pt)
	if err != nil {
		t.Fatal(err)
	}
	ct, err = ev.rawUnit(ct, false)
	if err != nil {
		t.Fatal(err)
	}
	ct.LogDimensions = p.LogMaxDimensions()
	dec := rlwe.NewDecryptor(p, sk)
	enc := ckks.NewEncoder(p)
	inputValues := make([]complex128, p.MaxSlots())
	if err = enc.Decode(dec.DecryptNew(ct), inputValues); err != nil {
		t.Fatal(err)
	}
	inputErr := 0.0
	for j, v := range inputValues {
		if j%4 == 0 {
			inputErr = math.Max(inputErr, cmplx.Abs(v-complex(tin, 0)))
		}
	}
	t.Logf("input focus error %g; linear output propagation bound %g", inputErr, inputErr*16*beta)
	measure := func(c *rlwe.Ciphertext) (float64, float64) {
		plain := dec.DecryptNew(c)
		plain.LogDimensions = p.LogMaxDimensions()
		values := make([]complex128, p.MaxSlots())
		if err := enc.Decode(plain, values); err != nil {
			t.Fatal(err)
		}
		data, guard := 0.0, 0.0
		for j, v := range values {
			if j%4 == 0 {
				data = math.Max(data, cmplx.Abs(v))
			} else {
				guard = math.Max(guard, cmplx.Abs(v))
			}
		}
		return data, guard
	}
	hook := func(name string, c *rlwe.Ciphertext) error {
		d, g := measure(c)
		t.Logf("%s level=%d scale=%.3f data=%.4g guard=%.4g", name, c.Level(), math.Log2(c.Scale.Float64()), d, g)
		if math.IsNaN(g) || math.IsInf(g, 0) {
			t.Fatalf("nonfinite guard at %s", name)
		}
		return nil
	}
	out, err := EvaluateShapedMod1(ev, ct, plan, rlwe.NewScale(beta*math.Exp2(20)), true, hook)
	if err != nil {
		t.Fatal(err)
	}
	out.Scale = out.Scale.Div(rlwe.NewScale(beta))
	if err = ev.Rescale(out, out); err != nil {
		t.Fatal(err)
	}
	plain := dec.DecryptNew(out)
	plain.LogDimensions = p.LogMaxDimensions()
	values := make([]complex128, p.MaxSlots())
	if err = enc.Decode(plain, values); err != nil {
		t.Fatal(err)
	}
	maxerr, guard, circuitErr := 0.0, 0.0, 0.0
	for j, v := range values {
		if j%4 == 0 {
			maxerr = math.Max(maxerr, cmplx.Abs(v-complex(z, 0)))
			circuitErr = math.Max(circuitErr, cmplx.Abs(v-complex(beta, 0)*Mod1ComplexPlaintextOracle(plan, inputValues[j])))
		} else {
			guard = math.Max(guard, cmplx.Abs(v))
		}
	}
	t.Logf("output level=%d scale=%.3f data error %.4g (%.2f bits), guard %.4g, shaped stats %+v", out.Level(), math.Log2(out.Scale.Float64()), maxerr, -math.Log2(maxerr), guard, ev.Stats)
	t.Logf("output vs oracle on decoded noisy input: %g (%.2f bits)", circuitErr, -math.Log2(circuitErr))
	if out.Level() != 0 || math.Abs(math.Log2(out.Scale.Float64())-20) > 0.01 {
		t.Fatal("final scale/level contract failed")
	}
	if ev.Stats.Rescales == 0 || ev.Stats.Relinearizations == 0 || ev.Stats.CoefficientProducts == 0 {
		t.Fatal("wrapper not used by polynomial evaluator")
	}
	if maxerr > math.Exp2(-16) || guard > 0.5 {
		t.Fatalf("nonlinear smoke failed: data=%g guard=%g", maxerr, guard)
	}
	if embits >= 32 && maxerr > math.Exp2(-20) {
		t.Fatalf("32-bit working scale did not reach 20-bit target: %g", maxerr)
	}
}
