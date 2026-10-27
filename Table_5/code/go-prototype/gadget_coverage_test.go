package lowbootstrap

import (
	"math/bits"
	"strings"
	"testing"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestGadgetCoverageRejectsMissingHighestBit(t *testing.T) {
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 9, LogQ: []int{52, 20, 34}, LogP: []int{32}, LogDefaultScale: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The generated qout is a real NTT prime above 2^20, although LogQi
	// reports 20. Exhibit a canonical residue that the actual fork mask loses.
	q := p.Q()[1]
	if q <= 1<<20 || bits.Len64(q) != 21 {
		t.Fatalf("regression fixture must lie above 2^20; got qout=%d", q)
	}
	digits := p.BaseTwoDecompositionVectorSize(p.MaxLevelQ(), p.MaxLevelP(), 20)
	if digits[1] != 1 {
		t.Fatalf("fork allocation changed: qout uses %d digits; reassess this workaround", digits[1])
	}
	input, masked := make([]uint64, 8), make([]uint64, 8)
	for i := range input {
		input[i] = 1 << 20
	}
	ring.MaskVec(input, 0, (1<<20)-1, masked)
	if masked[0] != 0 || input[0] >= q {
		t.Fatal("expected the fork's one-digit mask to lose a valid residue")
	}
	if err = ValidateBaseTwoDecompositionCoverage(p, p.MaxLevelQ(), p.MaxLevelP(), 20); err == nil || !strings.Contains(err.Error(), "Q[1]") {
		t.Fatalf("expected explicit qout coverage rejection, got %v", err)
	}
	for _, base := range []int{0, 14, 19} {
		if err = ValidateBaseTwoDecompositionCoverage(p, p.MaxLevelQ(), p.MaxLevelP(), base); err != nil {
			t.Errorf("safe base %d rejected: %v", base, err)
		}
	}
	// Base13 covers qout, but is not a universal safe choice: when q0 is
	// just above 2^52, four digits cover 52 bits while 53 are required.
	if p.Q()[0] > 1<<52 {
		if err = ValidateBaseTwoDecompositionCoverage(p, p.MaxLevelQ(), p.MaxLevelP(), 13); err == nil || !strings.Contains(err.Error(), "Q[0]") {
			t.Fatalf("expected q52/base13 rejection, got %v", err)
		}
	}
}

func TestGadgetCoverageRejectsQ52Boundary(t *testing.T) {
	// This is the actual q0 generated for the N32768/R8 run. Use it in a
	// small ring so the regression needs neither large keys nor evaluation.
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 9, Q: []uint64{4503599627763713}, LogP: []int{24}, LogDefaultScale: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateBaseTwoDecompositionCoverage(p, 0, 0, 13); err == nil || !strings.Contains(err.Error(), "requires 53 bits") {
		t.Fatalf("expected actual q52/base13 rejection, got %v", err)
	}
	for _, base := range []int{14, 19} {
		if err = ValidateBaseTwoDecompositionCoverage(p, 0, 0, base); err != nil {
			t.Errorf("safe base %d rejected: %v", base, err)
		}
	}
}
