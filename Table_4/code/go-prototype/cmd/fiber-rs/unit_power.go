package main

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

func parsePowers(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, v := range strings.Split(s, ",") {
		k, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || k < 0 || k > 6 || seen[k] {
			return nil, fmt.Errorf("invalid/duplicate unit power %q", v)
		}
		seen[k] = true
		out = append(out, k)
	}
	return out, nil
}

func compactMultiply(a, b []*big.Int) []*big.Int {
	d := len(a)
	c := make([]*big.Int, d)
	for i := range c {
		c[i] = new(big.Int)
	}
	for i, x := range a {
		for j, y := range b {
			v := new(big.Int).Mul(x, y)
			if i+j >= d {
				v.Neg(v)
			}
			c[(i+j)%d].Add(c[(i+j)%d], v)
		}
	}
	return c
}

// Exact integer powers modulo Y^(2R)+1. Verify the inverse after powering;
// the focus value is public high-precision metadata, not a modified ciphertext.
func unitPower(u unitSpec, k int) (unitSpec, error) {
	d := len(u.Coeffs)
	if d != 2*u.R || len(u.Inverse) != d {
		return unitSpec{}, fmt.Errorf("invalid compact unit")
	}
	g, gi := embed(u.Coeffs, d), embed(u.Inverse, d)
	h, hi := make([]*big.Int, d), make([]*big.Int, d)
	for i := range h {
		h[i], hi[i] = new(big.Int), new(big.Int)
	}
	h[0].SetInt64(1)
	hi[0].SetInt64(1)
	focus, _, err := big.ParseFloat(u.Focus, 10, 256, big.ToNearestEven)
	if err != nil || focus.Sign() <= 0 {
		return unitSpec{}, fmt.Errorf("positive focus required")
	}
	f := new(big.Float).SetPrec(256).SetInt64(1)
	for i := 0; i < k; i++ {
		h = compactMultiply(h, g)
		hi = compactMultiply(hi, gi)
		f.Mul(f, focus)
	}
	identity := compactMultiply(h, hi)
	for i, v := range identity {
		want := int64(0)
		if i == 0 {
			want = 1
		}
		if v.Cmp(big.NewInt(want)) != 0 {
			return unitSpec{}, fmt.Errorf("unit inverse check failed")
		}
	}
	out := unitSpec{R: u.R, Coeffs: make([]string, d), Inverse: make([]string, d), Focus: f.Text('g', 75)}
	for i := range h {
		out.Coeffs[i], out.Inverse[i] = h[i].String(), hi[i].String()
	}
	return out, nil
}
