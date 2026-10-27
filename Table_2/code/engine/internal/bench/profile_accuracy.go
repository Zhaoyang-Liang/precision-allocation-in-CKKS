package bench

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type ProfileGroupError struct {
	Group         int      `json:"group"`
	TargetBits    int      `json:"target_bits"`
	Checked       int      `json:"checked_effective_results"`
	Passing       int      `json:"passing_effective_results"`
	WorstBusiness int      `json:"worst_business_index"`
	MaxSquared    string   `json:"max_complex_error_squared_exact_for_decoded_values"`
	PrecisionBits *float64 `json:"precision_bits_display"`
	Pass          bool     `json:"all_results_pass"`
}
type profileErrors struct {
	cfg          *ProfileConfig
	rows         []ProfileGroupError
	maxima       []*big.Rat
	seen         map[[2]int]bool
	dummyMaximum *big.Rat
	dummyChecked int
}

func newProfileErrors(c *ProfileConfig) *profileErrors {
	a := &profileErrors{cfg: c, rows: make([]ProfileGroupError, len(c.Targets)), maxima: make([]*big.Rat, len(c.Targets)), seen: map[[2]int]bool{}, dummyMaximum: ri(0)}
	for g, b := range c.Targets {
		a.rows[g] = ProfileGroupError{Group: g, TargetBits: b, WorstBusiness: -1}
		a.maxima[g] = ri(0)
	}
	return a
}
func (a *profileErrors) add(got []*bignum.Complex, m ProfileBatchMap, truth [][]*big.Rat) error {
	if len(got) != m.PhysicalSlots {
		return fmt.Errorf("decoder slot count mismatch")
	}
	assigned := map[int]bool{}
	for _, v := range m.Values {
		if v.Group < 0 || v.Group >= len(truth) || v.Index < 0 || v.Index >= len(truth[v.Group]) || v.Slot < 0 || v.Slot >= len(got) {
			return fmt.Errorf("invalid accuracy mapping")
		}
		if assigned[v.Slot] || a.seen[[2]int{v.Group, v.Index}] {
			return fmt.Errorf("duplicate measured business result")
		}
		assigned[v.Slot] = true
		a.seen[[2]int{v.Group, v.Index}] = true
		z := got[v.Slot]
		if z == nil || z[0].IsInf() || z[1].IsInf() {
			return fmt.Errorf("invalid decoded value")
		}
		x, _ := z[0].Rat(nil)
		y, _ := z[1].Rat(nil)
		dx := sub(x, truth[v.Group][v.Index])
		sq := add(mul(dx, dx), mul(y, y))
		row := &a.rows[v.Group]
		row.Checked++
		if sq.Cmp(pow2(-2*row.TargetBits)) <= 0 {
			row.Passing++
		}
		if row.WorstBusiness < 0 || sq.Cmp(a.maxima[v.Group]) > 0 {
			a.maxima[v.Group] = sq
			row.WorstBusiness = v.Index
		}
	}
	// Unassigned slots include both structural dummy and last-batch padding.
	// They are measured for range diagnostics, never credited as business.
	for slot, z := range got {
		if assigned[slot] {
			continue
		}
		if z == nil || z[0].IsInf() || z[1].IsInf() {
			return fmt.Errorf("invalid dummy decode")
		}
		x, _ := z[0].Rat(nil)
		y, _ := z[1].Rat(nil)
		sq := add(mul(x, x), mul(y, y))
		a.dummyChecked++
		if sq.Cmp(a.dummyMaximum) > 0 {
			a.dummyMaximum = sq
		}
	}
	return nil
}
func (a *profileErrors) finish() ([]ProfileGroupError, error) {
	for g := range a.rows {
		row := &a.rows[g]
		if row.Checked != a.cfg.GroupSizes[g] {
			return nil, fmt.Errorf("missing effective results in group %d", g)
		}
		row.Pass = row.Checked == row.Passing
		row.MaxSquared = a.maxima[g].RatString()
		if a.maxima[g].Sign() > 0 {
			b := -log2Rat(a.maxima[g]) / 2
			row.PrecisionBits = &b
		}
	}
	return a.rows, nil
}
