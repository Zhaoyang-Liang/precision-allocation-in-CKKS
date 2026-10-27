package main

import "math"

// Select the *real* EvalMod output target scale so the actual cubic recurrence
// ends at target. Prime rounding errors amplify geometrically through a; using
// nominal bit counts at each node would silently destroy scale. This function
// only plans a scale; it never changes ciphertext metadata or decoded values.
func inverseSqrtInitialLogScale(q []uint64, level, iterations int, target float64) float64 {
	a, y, weightA, weightY := target, target, 1.0, 1.0
	for iteration := 2; iteration <= iterations; iteration++ {
		a = 3*a - math.Log2(float64(q[level])) - math.Log2(float64(q[level-1]))
		weightA *= 3
		level -= 2
		y += a - math.Log2(float64(q[level]))
		weightY += weightA
	}
	return target + (target-y)/weightY
}

// Public interior endpoints avoid diagnosing a rounding of 0.25-ulp as an
// out-of-domain input. Every reference is still recomputed from raw samples.
func scenarioTargets(k, iterations int) []float64 {
	lo, hi := 0.250001, 3.999999
	if iterations == 5 {
		lo, hi = 0.500001, 1.999999
	}
	x := make([]float64, k)
	for i := range x {
		if k == 1 {
			x[i] = math.Sqrt(lo * hi)
		} else {
			x[i] = lo * math.Pow(hi/lo, float64(i)/float64(k-1))
		}
	}
	return x
}

func unscaleReference(t []complex128, divisor float64) []complex128 {
	x := make([]complex128, len(t))
	for i := range x {
		x[i] = t[i] * complex(divisor, 0)
	}
	return x
}

func inverseSqrtReference(t []complex128, divisor float64, R int) []complex128 {
	y := make([]complex128, len(t))
	for j := 0; j < len(y); j += R {
		y[j] = complex(1/math.Sqrt(real(t[j])*divisor), 0)
	}
	return y
}
