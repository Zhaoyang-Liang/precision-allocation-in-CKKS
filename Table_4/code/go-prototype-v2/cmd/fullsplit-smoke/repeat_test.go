package main

import "testing"

func TestRepeatSupportContract(t *testing.T) {
	z := make([]complex128, 8)
	z[0] = .2 + .1i
	z[1] = -.1 + .3i
	v, s, e := squareLogicalSupport(z, 2)
	if e != nil || s != 3 || v[0] != z[0]*z[0] || v[1] != 2*z[0]*z[1] || v[2] != z[1]*z[1] {
		t.Fatal("incorrect coefficient convolution")
	}
	_, s, e = squareLogicalSupport(v, 3)
	if e != nil || s != 5 {
		t.Fatal("second support expansion")
	}
	if _, _, e = squareLogicalSupport(v, 5); e == nil {
		t.Fatal("wrapped interface must be rejected")
	}
}
