package bench

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func testProfileEncoder(t *testing.T, logn int, onlyFirst bool) {
	raw, e := os.ReadFile("../../testdata/new_profiles.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Profiles []struct {
			ProfileMultiplier
			Targets []int `json:"target_bits"`
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	p, e := (ParamSpec{LogN: logn, LogQ: []int{60, 60, 60, 60}, LogP: []int{60}, DefaultScaleBits: 60}).Build()
	if e != nil {
		t.Fatal(e)
	}
	enc := ckks.NewEncoder(p, 1024)
	for index, row := range fixture.Profiles {
		if onlyFirst && index > 0 {
			break
		}
		forward, weights, e := profileMultiplier(p, &row.ProfileMultiplier, 1024)
		if e != nil {
			t.Fatal(e)
		}
		c := &ProfileConfig{Precision: 1024, Targets: make([]int, row.Period), GroupSizes: make([]int, row.Period)}
		b := ProfileBranch{ID: "public_encoder", ScaleBits: 180, Multiplier: &row.ProfileMultiplier, Pattern: make([]int, row.Period)}
		inputs := make([][]*big.Rat, row.Period)
		for g := range inputs {
			b.Groups = append(b.Groups, g)
			b.Pattern[g] = g
			c.Targets[g] = max(16, row.Targets[g])
			c.GroupSizes[g] = p.MaxSlots() / row.Period
			inputs[g] = make([]*big.Rat, c.GroupSizes[g])
			for j := range inputs[g] {
				inputs[g][j] = profileInput(2026100201, g, j)
			}
		}
		maps, e := makeProfileMaps(c, b, p.MaxSlots())
		if e != nil {
			t.Fatal(e)
		}
		if len(maps) != 1 {
			t.Fatal("public test expected one full plaintext")
		}
		pt, e := encodeProfilePlain(c, b, p, enc, maps[0], weights, inputs)
		if e != nil {
			t.Fatal(e)
		}
		// Plaintext multiplication only. No ciphertext or key generation.
		p.RingQ().MulCoeffsMontgomery(pt.Value, forward.Poly, pt.Value)
		got := make([]*bignum.Complex, p.MaxSlots())
		if e = enc.Decode(pt, got); e != nil {
			t.Fatal(e)
		}
		acc := newProfileErrors(c)
		if e = acc.add(got, maps[0], inputs); e != nil {
			t.Fatal(e)
		}
		rows, e := acc.finish()
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range rows {
			if !r.Pass {
				t.Fatalf("profile %d logN %d group %d: bits=%v", index, logn, r.Group, r.PrecisionBits)
			}
		}
	}
}

func TestProfilePublicEncoderSmallRing(t *testing.T) { testProfileEncoder(t, 6, false) }
func TestProfilePublicEncoderFullRing(t *testing.T)  { testProfileEncoder(t, 15, true) }
