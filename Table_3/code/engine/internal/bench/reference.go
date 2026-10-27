package bench

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
)

type Dataset struct {
	Values     []*big.Rat
	SHA256     string
	References map[string][]*big.Rat
}

// 120-bit dyadic values. Every business slot receives its own sample; neither
// group is repeated to fill SIMD slots. The seed is PUBLIC data randomness.
func NewDataset(s *Suite) *Dataset {
	seed, _ := strconv.ParseUint(s.Seed, 10, 64)
	d := &Dataset{Values: make([]*big.Rat, 2*s.GroupSize), References: map[string][]*big.Rat{}}
	h := sha256.New()
	var input [16]byte
	binary.BigEndian.PutUint64(input[:8], seed)
	for i := range d.Values {
		binary.BigEndian.PutUint64(input[8:], uint64(i))
		b := sha256.Sum256(input[:])
		n := new(big.Int).SetBytes(b[:15])
		d.Values[i] = add(big.NewRat(255, 256), div(new(big.Rat).SetInt(n), pow2(128)))
		fmt.Fprintln(h, d.Values[i].RatString())
	}
	d.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
	return d
}

// All returned reference values are exact rationals, including x^16. A real
// reference does not discard an observed imaginary error during validation.
func (d *Dataset) Reference(task string, exponent int) []*big.Rat {
	key := fmt.Sprintf("%s/%d", task, exponent)
	if r := d.References[key]; r != nil {
		return r
	}
	r := make([]*big.Rat, len(d.Values))
	for i, x := range d.Values {
		if task == "centered_input" {
			r[i] = sub(x, big.NewRat(13, 16))
		} else if task == "mean16" {
			s := ri(0)
			for k := 0; k < 16; k++ {
				s = add(s, d.Values[(i+2*k)%len(r)])
			}
			r[i] = sub(div(s, ri(16)), big.NewRat(13, 16))
		} else {
			r[i] = new(big.Rat).SetFrac(new(big.Int).Exp(x.Num(), big.NewInt(int64(exponent)), nil), new(big.Int).Exp(x.Denom(), big.NewInt(int64(exponent)), nil))
		}
	}
	d.References[key] = r
	return r
}

type SlotMapping struct {
	Slots, Business []int
	// Empty means one real business per slot, checked with the full complex
	// error as before. Otherwise 0/1 explicitly selects a real/imag business.
	Components []int
}

func mapping(s *Suite, b BranchSpec) SlotMapping {
	m := SlotMapping{}
	for i := 0; i < 2*s.GroupSize; i++ {
		if b.Group == "low" && i%2 != 0 || b.Group == "high" && i%2 != 1 {
			continue
		}
		j := i
		if b.Layout == "compact" || b.Layout == "real_imag" {
			j = i / 2
		}
		if b.Layout == "real_imag" {
			m.Components = append(m.Components, i%2)
		}
		if b.Paired() {
			j = i / 4
			if b.Layout == "paired_interleaved" {
				j = 2*j + i%2
			}
			m.Components = append(m.Components, (i/2)%2)
		}
		m.Slots = append(m.Slots, j)
		m.Business = append(m.Business, i)
	}
	return m
}

func validateMappings(s *Suite, ms []SlotMapping) error {
	seen := make([]bool, 2*s.GroupSize)
	for _, m := range ms {
		if len(m.Slots) != len(m.Business) {
			return fmt.Errorf("mapping length mismatch")
		}
		if len(m.Components) != 0 && len(m.Components) != len(m.Slots) {
			return fmt.Errorf("component mapping length mismatch")
		}
		occupied := map[[2]int]bool{}
		for k, slot := range m.Slots {
			component := 0
			if len(m.Components) != 0 {
				component = m.Components[k]
			}
			key := [2]int{slot, component}
			if slot < 0 || component < 0 || component > 1 || occupied[key] {
				return fmt.Errorf("invalid/duplicate slot-component mapping")
			}
			occupied[key] = true
		}
		for _, i := range m.Business {
			if i < 0 || i >= len(seen) || seen[i] {
				return fmt.Errorf("missing/duplicate business result mapping")
			}
			seen[i] = true
		}
	}
	for _, v := range seen {
		if !v {
			return fmt.Errorf("incomplete business result mapping")
		}
	}
	return nil
}
