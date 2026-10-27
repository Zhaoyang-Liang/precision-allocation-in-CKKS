package bench

import (
	"math/big"
	"testing"
)

func TestProfileDummyCapacity(t *testing.T) {
	for _, messages := range []int{8, 1024, 8192} {
		for _, r := range []int{1, 2, 4, 8} {
			for _, slots := range []int{16, 2048, 4096, 16384} {
				c := &ProfileConfig{GroupSizes: []int{messages}}
				b := ProfileBranch{ID: "direct", Groups: []int{0}}
				if r > 1 {
					b.Pattern = make([]int, r)
					for k := 1; k < r; k++ {
						b.Pattern[k] = -1
					}
				}
				maps, e := makeProfileMaps(c, b, slots)
				if e != nil {
					t.Fatal(e)
				}
				if e = validateProfileMaps(c, maps); e != nil {
					t.Fatal(e)
				}
				capacity := slots / r
				want := (messages + capacity - 1) / capacity
				if len(maps) != want {
					t.Fatalf("capacity mismatch m=%d r=%d slots=%d", messages, r, slots)
				}
				count := 0
				for _, m := range maps {
					count += len(m.Values)
				}
				if count != messages {
					t.Fatal("dummy counted as business")
				}
			}
		}
	}
}

func TestProfileGroupsAndSplit(t *testing.T) {
	c := &ProfileConfig{GroupSizes: []int{7, 13, 7, 13}}
	var all []ProfileBatchMap
	for _, b := range []ProfileBranch{{ID: "ac", Groups: []int{0, 2}}, {ID: "bd", Groups: []int{1, 3}}} {
		maps, e := makeProfileMaps(c, b, 8)
		if e != nil {
			t.Fatal(e)
		}
		all = append(all, maps...)
	}
	if e := validateProfileMaps(c, all); e != nil {
		t.Fatal(e)
	}
	all[0].Values[1] = all[0].Values[0]
	if validateProfileMaps(c, all) == nil {
		t.Fatal("duplicate business was accepted")
	}
}

func TestProfilePeriodicUnequalCounts(t *testing.T) {
	c := &ProfileConfig{GroupSizes: []int{5, 12, 7, 20}}
	b := ProfileBranch{ID: "four", Groups: []int{0, 1, 2, 3}, Pattern: []int{0, 1, 2, 3}}
	maps, e := makeProfileMaps(c, b, 16)
	if e != nil {
		t.Fatal(e)
	}
	if len(maps) != 5 {
		t.Fatal("wrong repeated-slot capacity")
	}
	if e = validateProfileMaps(c, maps); e != nil {
		t.Fatal(e)
	}
}

func TestProfileExactInputReference(t *testing.T) {
	seen := map[string]bool{}
	for g := 0; g < 4; g++ {
		for i := 0; i < 100; i++ {
			x := profileInput(2026100201, g, i)
			if x.Cmp(big.NewRat(3, 4)) < 0 || x.Cmp(big.NewRat(7, 8)) > 0 {
				t.Fatal("range")
			}
			if i > 2 {
				if seen[x.RatString()] {
					t.Fatal("unintended repeated interior messages")
				}
				seen[x.RatString()] = true
			}
			want := new(big.Rat).Set(x)
			for d := 1; d <= 4; d++ {
				want.Mul(want, want)
				if profileReference(x, d).Cmp(want) != 0 {
					t.Fatal("reference")
				}
			}
		}
	}
	if profileInput(2026100201, 0, 3).Cmp(profileInput(2026100202, 0, 3)) == 0 {
		t.Fatal("repeat dataset did not change")
	}
}
