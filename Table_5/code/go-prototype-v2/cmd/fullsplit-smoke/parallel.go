package main

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

// Every branch owns mutable evaluators, encoder, plan and rounding RNG.
// The large evaluation keys are shared read-only across all branches.
type leafEngine struct {
	laneWorkers                    int
	laneShapes                     [2]*lb.ShapedEvaluator
	readoutSeconds, evalModSeconds float64
	low, main                      ckks.Parameters
	fused                          *lb.FusedRecovery
	shaped                         *lb.ShapedEvaluator
	plan                           mod1.Parameters
	plusI                          []*big.Int
	beta                           float64
	scaleBits                      int
}

type onlineResult struct {
	readoutTimes, evalModTimes                             []float64
	leaves, refreshed                                      []*rlwe.Ciphertext
	returned                                               *rlwe.Ciphertext
	durations                                              []float64
	entrySeconds, leafSeconds, mergeSeconds, onlineSeconds float64
}

func (e *leafEngine) refresh(leaf *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	return e.refreshWithHook(leaf, nil)
}

func (e *leafEngine) refreshWithHook(leaf *rlwe.Ciphertext, hook func(int, string, *rlwe.Ciphertext) error) (*rlwe.Ciphertext, error) {
	t := time.Now()
	re, im, err := e.fused.Apply(e.low, leaf)
	e.readoutSeconds = time.Since(t).Seconds()
	t = time.Now()
	if err != nil {
		return nil, err
	}
	lanes := []*rlwe.Ciphertext{re, im}
	workers := e.laneWorkers
	if hook != nil {
		workers = 1
	}
	e.shaped.Stats = lb.ShapedStats{}
	if e.laneShapes[0] == nil {
		e.laneShapes = [2]*lb.ShapedEvaluator{lb.ForkShapedEvaluator(e.shaped), lb.ForkShapedEvaluator(e.shaped)}
	}
	for _, shape := range e.laneShapes {
		shape.Stats = lb.ShapedStats{}
	}
	err = lb.RunTwoLanes(workers, func(lane int) error {
		v := lanes[lane]
		shape := e.laneShapes[lane]
		var err error
		var stageHook lb.ShapedStageHook
		if hook != nil {
			if err := hook(lane, "fused", v); err != nil {
				return err
			}
			stageHook = func(name string, ct *rlwe.Ciphertext) error { return hook(lane, name, ct) }
		}
		lanes[lane], err = lb.EvaluateShapedMod1(shape, v, e.plan,
			rlwe.NewScale(e.beta*math.Exp2(float64(e.scaleBits))), true, stageHook)
		if err != nil {
			return fmt.Errorf("lane %d: %w", lane, err)
		}
		lanes[lane].Scale = lanes[lane].Scale.Div(rlwe.NewScale(e.beta))
		// With zero double angles the polynomial already returns at the final
		// fractional scale. There is no deferred square/rescale to consume.
		if e.plan.DoubleAngle > 0 {
			if err = shape.Rescale(lanes[lane], lanes[lane]); err != nil {
				return err
			}
		}
		if hook != nil {
			name := "final_rescale"
			if e.plan.DoubleAngle == 0 {
				name = "final_scale_return"
			}
			if err = hook(lane, name, lanes[lane]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, shape := range e.laneShapes {
		lb.AddShapedStats(&e.shaped.Stats, shape.Stats)
	}
	e.evalModSeconds = time.Since(t).Seconds()
	imagCT, err := lb.MulIntegerPolynomial(e.main, lanes[1], e.plusI)
	if err != nil {
		return nil, err
	}
	return e.shaped.Evaluator.AddNew(lanes[0], imagCT)
}

// runIndexed limits actual concurrent branch work, joins all workers before
// returning, and reports the first error in branch order. Each index is owned
// by exactly one worker; no shared accumulator is written concurrently.
func runIndexed(count, workers int, fn func(int) error) error {
	if count < 1 || workers < 1 {
		return fmt.Errorf("positive count and workers required")
	}
	errs := make([]error, count)
	var wg sync.WaitGroup
	for w := 0; w < min(count, workers); w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for b := w; b < count; b += workers {
				errs[b] = fn(b)
			}
		}(w)
	}
	wg.Wait()
	for b, err := range errs {
		if err != nil {
			return fmt.Errorf("branch %d: %w", b, err)
		}
	}
	return nil
}

func refreshLeaves(leaves []*rlwe.Ciphertext, engines []*leafEngine, workers int) ([]*rlwe.Ciphertext, []float64, error) {
	outputs := make([]*rlwe.Ciphertext, len(leaves))
	durations := make([]float64, len(leaves))
	err := runIndexed(len(leaves), workers, func(b int) error {
		start := time.Now()
		var err error
		outputs[b], err = engines[b].refresh(leaves[b])
		durations[b] = time.Since(start).Seconds()
		return err
	})
	return outputs, durations, err
}
