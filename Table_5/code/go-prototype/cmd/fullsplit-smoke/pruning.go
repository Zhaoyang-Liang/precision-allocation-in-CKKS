package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"time"
)

// The caller guarantees that branches outside the public support have ideal
// plaintext zero. No ciphertext inspection decides the support. This primitive
// must not be applied to arbitrary inputs with merely zero canonical slots.
func refreshKnownSupport(leaves []*rlwe.Ciphertext, engines []*leafEngine, workers, messages int, prune bool) ([]*rlwe.Ciphertext, []float64, error) {
	if !prune {
		return refreshLeaves(leaves, engines, workers)
	}
	if messages < 1 || messages > len(leaves) {
		return nil, nil, fmt.Errorf("invalid public support")
	}
	outputs := make([]*rlwe.Ciphertext, len(leaves))
	durations := make([]float64, len(leaves))
	err := runIndexed(messages, workers, func(b int) error {
		start := time.Now()
		var e error
		outputs[b], e = engines[b].refresh(leaves[b])
		durations[b] = time.Since(start).Seconds()
		return e
	})
	if err != nil {
		return outputs, durations, err
	}
	for b := messages; b < len(outputs); b++ {
		outputs[b] = ckks.NewCiphertext(engines[b].main, outputs[0].Degree(), outputs[0].Level())
		outputs[b].MetaData = outputs[0].MetaData.CopyNew()
	}
	return outputs, durations, nil
}
