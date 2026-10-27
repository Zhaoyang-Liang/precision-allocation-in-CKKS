package main

import (
	"errors"
	"sync/atomic"
	"testing"
)

func TestRunIndexed(t *testing.T) {
	for _, workers := range []int{1, 3, 8, 16, 32} {
		counts := make([]atomic.Int32, 16)
		sentinel := errors.New("expected failure")
		err := runIndexed(16, workers, func(b int) error {
			counts[b].Add(1)
			if b == 7 {
				return sentinel
			}
			return nil
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("workers %d: failure was swallowed: %v", workers, err)
		}
		for b := range counts {
			if counts[b].Load() != 1 {
				t.Fatalf("workers %d: branch %d ran %d times", workers, b, counts[b].Load())
			}
		}
	}
}
