package bench

import (
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type tracePoint struct {
	Name         string
	Exponent     int
	Branch       *branchRuntime
	CT           *rlwe.Ciphertext
	NeedsRestore bool
}
type evaluated struct {
	Branch *branchRuntime
	CT     *rlwe.Ciphertext
}

// Source-level counts are recorded by the operations which actually execute.
// They are not NTT counts, FLOP estimates, or hardware performance counters.
func rawMultiply(p ckks.Parameters, ct *rlwe.Ciphertext, k *PublicMultiplier, override *rlwe.Scale, r *recorder, branch, kind string) (*rlwe.Ciphertext, error) {
	if !ct.IsNTT || ct.IsMontgomery || k.Poly.Level() < ct.Level() {
		return nil, fmt.Errorf("raw product requires standard NTT ciphertext and matching multiplier levels")
	}
	out := ct.CopyNew()
	rq := p.RingQ().AtLevel(ct.Level())
	for j := range ct.Value {
		rq.MulCoeffsMontgomery(ct.Value[j], k.Poly, out.Value[j])
	}
	if override != nil {
		out.Scale = *override
	} else {
		out.Scale = ct.Scale.Mul(k.Scale)
	}
	if r != nil {
		r.ops = append(r.ops, Operation{Kind: kind, Branch: branch, InputLevel: ct.Level(), InputDegree: ct.Degree(), ComponentProducts: Count(ct.Degree() + 1), PointwiseWords: Count(uint64(ct.Degree()+1) * uint64(p.N()) * uint64(ct.Level()+1))})
	}
	return out, nil
}

func rescaleInPlace(p ckks.Parameters, ct *rlwe.Ciphertext, count int, scratch ring.Poly, r *recorder, branch string) error {
	if count == 0 {
		return nil
	}
	l := ct.Level()
	if count < 0 || count > l || scratch.Level() < l || !ct.IsNTT {
		return fmt.Errorf("invalid explicit rescale count/level")
	}
	rq := p.RingQ().AtLevel(l)
	for k := 0; k < count; k++ {
		ct.Scale = ct.Scale.Div(rlwe.NewScale(p.Q()[l-k]))
	}
	for i := range ct.Value {
		rq.DivRoundByLastModulusManyNTT(count, ct.Value[i], scratch, ct.Value[i])
	}
	if r != nil {
		r.ops = append(r.ops, Operation{Kind: "rescale", Branch: branch, InputLevel: l, InputDegree: ct.Degree(), RemovedPrimes: count})
	}
	ct.Resize(ct.Degree(), l-count)
	return nil
}

func restore(b *branchRuntime, ct *rlwe.Ciphertext, r *recorder, diagnostic bool) (*rlwe.Ciphertext, error) {
	f := b.Representation.Forward
	if f == nil {
		return ct, nil
	}
	name := "exact_unit_restore"
	if b.Representation.Kind == "integer_nonunit" {
		name = "exact_integer_nonunit_restore"
	}
	if b.Representation.Kind == "diagonal" {
		name = "approximate_diagonal_restore"
	}
	out, e := rawMultiply(b.P, ct, f, nil, r, b.Spec.ID, name)
	if e != nil {
		return nil, e
	}
	// Intermediate diagnostics restore a COPY without spending a level. The
	// temporary result may not decode when its logical phase exceeds current Q.
	// Only the final output executes the configured restore-rescale operation.
	if !diagnostic && b.Spec.RestoreRescaleCount != 0 {
		e = rescaleInPlace(b.P, out, b.Spec.RestoreRescaleCount, b.Scratch, r, b.Spec.ID)
	}
	return out, e
}

func entryExisting(b *branchRuntime, src *existingSource, r *recorder) (*rlwe.Ciphertext, error) {
	p := src.Family.P
	var current *rlwe.Ciphertext
	if b.Spec.Group == "all" {
		l, e := rawMultiply(p, src.Inputs[0], b.EntryMultipliers[0], &b.EntryRawScale, r, b.Spec.ID, "merge_mask_product")
		if e != nil {
			return nil, e
		}
		h, e := rawMultiply(p, src.Inputs[1], b.EntryMultipliers[1], &b.EntryRawScale, r, b.Spec.ID, "merge_mask_product")
		if e != nil {
			return nil, e
		}
		current = l
		rq := p.RingQ().AtLevel(l.Level())
		for j := range current.Value {
			rq.Add(l.Value[j], h.Value[j], current.Value[j])
		}
		r.ops = append(r.ops, Operation{Kind: "ciphertext_add", Branch: b.Spec.ID, InputLevel: l.Level(), InputDegree: 1})
	} else {
		g := 0
		if b.Spec.Group == "high" {
			g = 1
		}
		var e error
		current, e = rawMultiply(p, src.Inputs[g], b.EntryMultipliers[0], &b.EntryRawScale, r, b.Spec.ID, "separate_input_scale_conversion")
		if e != nil {
			return nil, e
		}
	}
	if e := rescaleInPlace(p, current, p.MaxLevel()-b.P.MaxLevel(), b.EntryScratch, r, b.Spec.ID); e != nil {
		return nil, e
	}
	// The public multiplier was constructed using the EXACT integer product of
	// removed primes and intended target D. Intermediate metadata is not used as
	// an approximation to this conversion ratio. Restore the prescribed D here.
	current.Scale = scale(pow2(b.Spec.ScaleBits))
	r.ops = append(r.ops, Operation{Kind: "entry_set_prescribed_scale_metadata", Branch: b.Spec.ID, InputLevel: current.Level(), InputDegree: 1})
	return current, nil
}

func evaluate(s *Suite, branches []*branchRuntime, src *existingSource) (outputs []evaluated, traces []tracePoint, timing OnlineTiming, ops []Operation, err error) {
	r := &recorder{phases: make([]Phase, 0, 64), ops: make([]Operation, 0, 128)}
	// Reserve trace/output records BEFORE timing. Actual ciphertext outputs are
	// retained as immutable references; no diagnostic copies/decryptions in region.
	traces = make([]tracePoint, 0, 12)
	outputs = make([]evaluated, 0, len(branches))
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	start := time.Now()
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("online panic: %v", x)
		}
		var e error
		timing, e = finishTiming(start, mem, r)
		ops = r.ops
		if err == nil {
			err = e
		}
	}()
	for _, b := range branches {
		current := b.Input
		if s.Entry == "native" && s.RetainDiagnosticTraces {
			traces = append(traces, tracePoint{"native_input", 1, b, current, b.Representation.Forward != nil})
		}
		if s.Entry == "existing" {
			err = r.phase(b.Spec.ID, "entry_conversion", func() error { var e error; current, e = entryExisting(b, src, r); return e })
			if err != nil {
				return
			}
			if s.RetainDiagnosticTraces {
				traces = append(traces, tracePoint{"merged_or_converted_input", 1, b, current, b.Representation.Forward != nil})
			}
			err = r.phase(b.Spec.ID, "center", func() error {
				var e error
				current, e = b.Evaluator.SubNew(current, b.Center)
				if e == nil {
					r.ops = append(r.ops, Operation{Kind: "subtract_plaintext", Branch: b.Spec.ID, InputLevel: current.Level(), InputDegree: 1})
				}
				return e
			})
			if err != nil {
				return
			}
		}
		if b.Spec.Algorithm == "chebyshev6" {
			err = r.phase(b.Spec.ID, "chebyshev6_function", func() error { var e error; current, e = evaluateChebyshev6(b, current, r); return e })
			if err != nil {
				return
			}
		} else if s.Task == "mean16" {
			if b.Spec.Paired() {
				err = r.phase(b.Spec.ID, "paired_pre_reorganization", func() error {
					var e error
					current, e = pairedReorganize(b, current, r)
					return e
				})
				if err != nil {
					return
				}
			}
			for _, rot := range rotations(b.Spec) {
				rot := rot
				err = r.phase(b.Spec.ID, fmt.Sprintf("rotate_add_%d", rot), func() error {
					l := current.Level()
					v, e := b.Evaluator.RotateNew(current, rot)
					if e != nil {
						return e
					}
					r.ops = append(r.ops, Operation{Kind: "rotate", Branch: b.Spec.ID, InputLevel: l, InputDegree: 1, Rotation: rot, KeySwitches: 1})
					current, e = b.Evaluator.AddNew(current, v)
					if e != nil {
						return e
					}
					r.ops = append(r.ops, Operation{Kind: "ciphertext_add", Branch: b.Spec.ID, InputLevel: l, InputDegree: 1})
					return nil
				})
				if err != nil {
					return
				}
			}
			err = r.phase(b.Spec.ID, "mean_normalization", func() error {
				// Four AddNew calls already produced an unaliased ciphertext.
				// No input or checkpoint references this final sum.
				divisor := int64(16)
				if b.Spec.Paired() {
					divisor = 32
				}
				current.Scale = current.Scale.Mul(scale(ri(divisor)))
				r.ops = append(r.ops, Operation{Kind: "mean_division_by_scale_metadata", Branch: b.Spec.ID, InputLevel: current.Level(), InputDegree: 1})
				return nil
			})
			if err != nil {
				return
			}
		} else {
			for k, count := range b.Spec.RescaleCounts {
				k, count := k, count
				err = r.phase(b.Spec.ID, fmt.Sprintf("square_%d", k+1), func() error {
					l := current.Level()
					var e error
					if b.Representation.Forward == nil {
						// Give the ordinary baseline the backend's fused square/relin.
						current, e = b.Evaluator.MulRelinNew(current, current)
						if e == nil {
							r.ops = append(r.ops, Operation{Kind: "ciphertext_square", Branch: b.Spec.ID, InputLevel: l, InputDegree: 1})
						}
					} else {
						var tensor *rlwe.Ciphertext
						tensor, e = b.Evaluator.MulNew(current, current)
						if e != nil {
							return e
						}
						r.ops = append(r.ops, Operation{Kind: "ciphertext_square", Branch: b.Spec.ID, InputLevel: l, InputDegree: 1})
						kind := "exact_unit_gate_correction"
						if b.Representation.Kind == "integer_nonunit" {
							kind = "exact_integer_nonunit_gate_correction"
						}
						if b.Representation.Kind == "diagonal" {
							kind = "approximate_diagonal_gate_correction"
						}
						tensor, e = rawMultiply(b.P, tensor, b.Representation.Forward, nil, r, b.Spec.ID, kind)
						if e != nil {
							return e
						}
						current, e = b.Evaluator.RelinearizeNew(tensor)
					}
					if e != nil {
						return e
					}
					r.ops = append(r.ops, Operation{Kind: "relinearize", Branch: b.Spec.ID, InputLevel: l, InputDegree: 2, KeySwitches: 1})
					return rescaleInPlace(b.P, current, count, b.Scratch, r, b.Spec.ID)
				})
				if err != nil {
					return
				}
				if k < 7 && s.RetainDiagnosticTraces {
					traces = append(traces, tracePoint{fmt.Sprintf("power_%d", 1<<(k+1)), 1 << (k + 1), b, current, b.Representation.Forward != nil})
				}
			}
		}
		b.NativeOutput = current
		for _, phase := range r.phases {
			if phase.Branch == b.Spec.ID {
				b.NativePhaseSum += phase.DurationNS
			}
		}
		if b.Representation.Forward != nil {
			err = r.phase(b.Spec.ID, "restore", func() error { var e error; current, e = restore(b, current, r, false); return e })
			if err != nil {
				return
			}
		}
		if n := b.Spec.OutputRescaleCount; n > 0 {
			err = r.phase(b.Spec.ID, "output_rescale", func() error {
				current = current.CopyNew()
				return rescaleInPlace(b.P, current, n, b.Scratch, r, b.Spec.ID)
			})
			if err != nil {
				return
			}
		}
		if n := b.Spec.OutputDropPrimes; n > 0 {
			err = r.phase(b.Spec.ID, "output_modulus_drop", func() error {
				if current.Level() < n {
					return fmt.Errorf("invalid output modulus drop")
				}
				l := current.Level()
				current = current.CopyNew()
				current.Resize(current.Degree(), l-n)
				r.ops = append(r.ops, Operation{Kind: "modulus_drop_without_rescale", Branch: b.Spec.ID, InputLevel: l, InputDegree: 1, RemovedPrimes: n})
				return nil
			})
			if err != nil {
				return
			}
		}
		outputs = append(outputs, evaluated{b, current})
	}
	return
}

func prepareEntry(s *Suite, b *branchRuntime, src *existingSource) error {
	p := src.Family.P
	divisor := new(big.Rat).SetInt(prod(p.Q()[b.P.MaxLevel()+1:]))
	D := pow2(b.Spec.ScaleBits)
	b.EntryRawScale = scale(mul(divisor, D))
	b.EntryScratch = p.RingQ().NewPoly()
	if b.Spec.Group == "all" {
		for j, sgn := range []int64{1, -1} {
			f := div(mul(divisor, D), pow2(s.Source.ScaleBitsLowHigh[j]))
			k, e := mergeMultiplier(p, b.Representation, sgn, f)
			if e != nil {
				return e
			}
			b.EntryMultipliers = append(b.EntryMultipliers, k)
			b.Constants = append(b.Constants, k.Report)
		}
	} else {
		g := 0
		if b.Spec.Group == "high" {
			g = 1
		}
		f := div(mul(divisor, D), pow2(s.Source.ScaleBitsLowHigh[g]))
		k, e := scalarConversion(p, f)
		if e != nil {
			return e
		}
		b.EntryMultipliers = []*PublicMultiplier{k}
		b.Constants = append(b.Constants, k.Report)
	}
	var e error
	b.Center, e = centerPlaintext(b.P, b.P.MaxLevel(), D, b.Representation)
	return e
}
