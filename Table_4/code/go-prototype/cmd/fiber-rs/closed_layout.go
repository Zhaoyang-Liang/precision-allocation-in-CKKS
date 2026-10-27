package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Public trivial RLWE zero with two zero components. This is degree one and
// carries the active ciphertext's actual level/scale/dimensions/NTT metadata.
// It is not a fresh randomized encryption; the branch is publicly known zero.
func zeroCiphertextLike(p ckks.Parameters, reference *rlwe.Ciphertext) *rlwe.Ciphertext {
	zero := ckks.NewCiphertext(p, 1, reference.Level())
	zero.MetaData = reference.MetaData.CopyNew()
	return zero
}
