package lowbootstrap

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"sync"
)

// ForkShapedEvaluator shares immutable keys and unit polynomials only.
// Each lane owns its evaluator scratch, encoder and arithmetic counters.
func ForkShapedEvaluator(ev *ShapedEvaluator) *ShapedEvaluator {
	out := *ev
	out.Evaluator = ev.Evaluator.ShallowCopy()
	out.Encoder128 = ckks.NewEncoder(ev.Params, 128)
	out.Stats = ShapedStats{}
	return &out
}

func RunTwoLanes(workers int, fn func(int) error) error {
	var errs [2]error
	if workers < 2 {
		for i := range errs {
			errs[i] = fn(i)
		}
	} else {
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func(i int) { defer wg.Done(); errs[i] = fn(i) }(i)
		}
		wg.Wait()
	}
	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("lane %d: %w", i, err)
		}
	}
	return nil
}

func AddShapedStats(dst *ShapedStats, src ShapedStats) {
	dst.SubunitCoefficientProducts += src.SubunitCoefficientProducts
	dst.Rescales += src.Rescales
	dst.Relinearizations += src.Relinearizations
	dst.EncodedConstants += src.EncodedConstants
	dst.CoefficientProducts += src.CoefficientProducts
	dst.ScaleAlignments += src.ScaleAlignments
	if dst.MinCoefficientLogScale == 0 || src.MinCoefficientLogScale < dst.MinCoefficientLogScale {
		dst.MinCoefficientLogScale = src.MinCoefficientLogScale
	}
	if dst.MinAlignmentLogRatio == 0 || src.MinAlignmentLogRatio < dst.MinAlignmentLogRatio {
		dst.MinAlignmentLogRatio = src.MinAlignmentLogRatio
	}
}
