package main

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

func TestUnitPowersPreserveInverseAndProfile(t *testing.T) {
	raw, err := os.ReadFile("../../units-weak.json")
	if err != nil {
		t.Fatal(err)
	}
	var units []unitSpec
	if err = json.Unmarshal(raw, &units); err != nil {
		t.Fatal(err)
	}
	u := units[0]
	for _, k := range []int{0, 1, 2, 3} {
		p, e := unitPower(u, k)
		if e != nil {
			t.Fatal(e)
		}
		if math.Abs(math.Log2(f64(p.Focus))-float64(k)*math.Log2(f64(u.Focus))) > 1e-12 {
			t.Fatal("incorrect focus power")
		}
		if k == 0 {
			for j, v := range p.Coeffs {
				want := "0"
				if j == 0 {
					want = "1"
				}
				if v != want {
					t.Fatal("power zero is not identity")
				}
			}
		}
		if k == 1 {
			for j, v := range p.Coeffs {
				if v != u.Coeffs[j] || p.Inverse[j] != u.Inverse[j] {
					t.Fatal("power one changed unit")
				}
			}
		}
	}
	bad := u
	bad.Inverse = append([]string(nil), u.Inverse...)
	bad.Inverse[0] = "0"
	if _, e := unitPower(bad, 1); e == nil {
		t.Fatal("corrupt inverse accepted")
	}
	for _, s := range []string{"-1", "1,1", "7", "x"} {
		if _, e := parsePowers(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
