package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

// The direct mode keeps the same plaintext and secret throughout. It does not
// implement a simulated ring switch when dimensions agree.
func mergeOrIdentity(top, leaf ckks.Parameters, cts []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if top.LogN() != leaf.LogN() {
		return lb.MergeCoefficientBranches(top, leaf, cts)
	}
	if len(cts) != 1 || cts[0] == nil || cts[0].LogN() != top.LogN() {
		return nil, fmt.Errorf("direct mode requires exactly one same-ring ciphertext")
	}
	return cts[0].CopyNew(), nil
}
