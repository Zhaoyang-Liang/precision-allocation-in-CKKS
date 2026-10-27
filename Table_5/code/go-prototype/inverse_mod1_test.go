package lowbootstrap

import (
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// A plaintext reference independent of the encrypted evaluator checks that the
// inverse polynomial is actually composed, with the library's real coefficients.
func TestInverseMod1OracleReducesSineBias(t *testing.T) {
	p, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 7, LogQ: []int{40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40}, LogP: []int{40}, LogDefaultScale: 40})
	if e != nil {
		t.Fatal(e)
	}
	lit := mod1.ParametersLiteral{LevelQ: p.MaxLevel(), LogScale: 40, Mod1Type: mod1.CosContinuous, LogMessageRatio: 4, K: 17, Mod1Degree: 63, DoubleAngle: 3, Mod1InvDegree: 0, Scaling: math.Exp2(math.Round(math.Log2(float64(p.Q()[0])))) / float64(p.Q()[0])}
	sine, e := mod1.NewParametersFromLiteral(p, lit)
	if e != nil {
		t.Fatal(e)
	}
	lit.Mod1InvDegree = 7
	inverse, e := mod1.NewParametersFromLiteral(p, lit)
	if e != nil {
		t.Fatal(e)
	}
	maxSine, maxInverse := 0.0, 0.0
	for carry := -16; carry <= 16; carry++ {
		for _, fraction := range []float64{-.04, -.02, .02, .04} {
			normalized := (float64(carry) + fraction) / 17
			maxSine = math.Max(maxSine, math.Abs(Mod1PlaintextOracle(sine, normalized)-fraction))
			maxInverse = math.Max(maxInverse, math.Abs(Mod1PlaintextOracle(inverse, normalized)-fraction))
		}
	}
	if maxInverse >= maxSine/1000 || maxInverse > 5e-8 {
		t.Fatalf("arcsine oracle composition incorrect: sine %.12g inverse %.12g", maxSine, maxInverse)
	}
	t.Logf("max sine-only bias %.12g, inverse7 %.12g", maxSine, maxInverse)
}
