package bench

import (
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type CipherReport struct {
	SHA256                   string `json:"sha256"`
	Degree                   int    `json:"degree"`
	N                        int    `json:"n"`
	PhysicalSlots            int    `json:"physical_slots"`
	Level                    int    `json:"level"`
	RNSCount                 int    `json:"q_components"`
	Modulus                  string `json:"q_exact"`
	ScaleBeforeSerialization string `json:"scale_before_serialization_exact"`
	WireScale                string `json:"wire_scale_exact"`
	RelativeScaleChange      string `json:"wire_relative_scale_change_exact"`
	PayloadBytes             Count  `json:"coefficient_payload_bytes"`
	SerializedBytes          Count  `json:"serialized_bytes"`
}

func wireCipher(p ckks.Parameters, in *rlwe.Ciphertext) ([]byte, *rlwe.Ciphertext, CipherReport, error) {
	w, e := in.MarshalBinary()
	if e != nil {
		return nil, nil, CipherReport{}, e
	}
	if len(w) != in.BinarySize() {
		return nil, nil, CipherReport{}, fmt.Errorf("ciphertext BinarySize disagrees with actual wire length")
	}
	out := new(rlwe.Ciphertext)
	if e = out.UnmarshalBinary(w); e != nil {
		return nil, nil, CipherReport{}, e
	}
	if out.MetaData == nil || !out.IsNTT || out.Degree() != in.Degree() || out.Level() != in.Level() {
		return nil, nil, CipherReport{}, fmt.Errorf("ciphertext wire metadata mismatch")
	}
	var bytes uint64
	for c, poly := range in.Value {
		for k, a := range poly.Coeffs {
			bytes += 8 * uint64(len(a))
			for j, x := range a {
				if out.Value[c].Coeffs[k][j] != x {
					return nil, nil, CipherReport{}, fmt.Errorf("wire roundtrip changed coefficients")
				}
			}
		}
	}
	orig, ws := scaleRat(in.Scale), scaleRat(out.Scale)
	r := CipherReport{hashBytes(w), out.Degree(), p.N(), p.MaxSlots(), out.Level(), out.Level() + 1, prod(p.Q()[:out.Level()+1]).String(), orig.RatString(), ws.RatString(), div(new(big.Rat).Abs(sub(ws, orig)), orig).RatString(), Count(bytes), Count(len(w))}
	return w, out, r, nil
}

type GroupError struct {
	Group              string   `json:"group"`
	TargetBits         int      `json:"target_bits"`
	Checked            Count    `json:"checked_results"`
	Passing            Count    `json:"passing_results"`
	WorstBusinessIndex int      `json:"worst_business_index"`
	MaxSquared         string   `json:"max_complex_absolute_error_squared_exact_for_decoded_values,omitempty"`
	MaxBusinessSquared string   `json:"max_business_absolute_error_squared_exact_for_decoded_values"`
	Metric             string   `json:"error_metric"`
	MaxAbsoluteApprox  string   `json:"max_absolute_error_display"`
	Bits               *float64 `json:"precision_bits_display"`
	ExactZero          bool     `json:"decoded_error_exactly_zero"`
	Pass               bool     `json:"all_checked_results_pass"`
}

type errorAccumulator struct {
	max             [2]*big.Rat
	counts, passing [2]uint64
	worst           [2]int
	targets         [2]int
	metric          string
}

func newErrors(targets [2]int) *errorAccumulator {
	return &errorAccumulator{max: [2]*big.Rat{ri(0), ri(0)}, worst: [2]int{-1, -1}, targets: targets}
}

func (a *errorAccumulator) addDecoded(got []*bignum.Complex, want []*big.Rat, m SlotMapping) error {
	metric := "complex_absolute_error_to_real_reference"
	if len(m.Components) != 0 {
		if len(m.Components) != len(m.Slots) {
			return fmt.Errorf("component mapping length mismatch")
		}
		metric = "selected_real_or_imag_component_absolute_error"
	}
	if a.metric != "" && a.metric != metric {
		return fmt.Errorf("cannot mix business error metrics in one accumulator")
	}
	a.metric = metric
	for k, slot := range m.Slots {
		i := m.Business[k]
		if slot < 0 || slot >= len(got) || i < 0 || i >= len(want) || got[slot] == nil {
			return fmt.Errorf("invalid decoded result mapping")
		}
		v := got[slot]
		if v[0].IsInf() || v[1].IsInf() {
			return fmt.Errorf("non-finite decoded value")
		}
		re, _ := v[0].Rat(nil)
		im, _ := v[1].Rat(nil)
		r := sub(re, want[i])
		sq := add(mul(r, r), mul(im, im))
		if len(m.Components) != 0 {
			component := m.Components[k]
			if component < 0 || component > 1 {
				return fmt.Errorf("invalid real/imag component")
			}
			value, _ := v[component].Rat(nil)
			difference := sub(value, want[i])
			sq = mul(difference, difference)
		}
		g := i % 2
		a.counts[g]++
		if sq.Cmp(pow2(-2*a.targets[g])) <= 0 {
			a.passing[g]++
		}
		if a.worst[g] < 0 || sq.Cmp(a.max[g]) > 0 {
			a.max[g] = sq
			a.worst[g] = i
		}
	}
	return nil
}
func (a *errorAccumulator) rows() [2]GroupError {
	var rows [2]GroupError
	for g, name := range []string{"low", "high"} {
		x := a.max[g]
		display := new(big.Float).SetPrec(256).Sqrt(bf(x, 256)).Text('g', 24)
		var bits *float64
		if x.Sign() > 0 {
			v := -log2Rat(x) / 2
			bits = &v
		}
		legacy := ""
		if a.metric != "selected_real_or_imag_component_absolute_error" {
			legacy = x.RatString()
		}
		rows[g] = GroupError{Group: name, TargetBits: a.targets[g], Checked: Count(a.counts[g]), Passing: Count(a.passing[g]), WorstBusinessIndex: a.worst[g], MaxSquared: legacy, MaxBusinessSquared: x.RatString(), Metric: a.metric, MaxAbsoluteApprox: display, Bits: bits, ExactZero: x.Sign() == 0, Pass: a.counts[g] > 0 && a.passing[g] == a.counts[g]}
	}
	return rows
}

// A separate, stronger check. Business success does not depend on this check:
// it is possible for each component to meet its own target but the complex
// norm to exceed the high group's target.
type ComplexErrorReport struct {
	Branch     string   `json:"branch"`
	Group      string   `json:"precision_group,omitempty"`
	TargetBits int      `json:"target_bits"`
	Checked    Count    `json:"checked_complex_slots"`
	Passing    Count    `json:"passing_complex_slots"`
	WorstSlot  int      `json:"worst_slot"`
	MaxSquared string   `json:"max_complex_absolute_error_squared_exact_for_decoded_values"`
	Bits       *float64 `json:"precision_bits_display"`
	Pass       bool     `json:"all_checked_slots_pass"`
}

func checkBranchComplex(s *Suite, b *branchRuntime, got []*bignum.Complex, want []*big.Rat) ([]ComplexErrorReport, error) {
	if !b.Spec.Paired() {
		r, e := checkComplexComponents(got, want, b.Map, b.Spec.ID, max(s.TargetsLowHigh[0], s.TargetsLowHigh[1]))
		if e != nil || r == nil {
			return nil, e
		}
		return []ComplexErrorReport{*r}, nil
	}
	var rows []ComplexErrorReport
	for g, name := range []string{"low", "high"} {
		m := SlotMapping{}
		for k, i := range b.Map.Business {
			if i%2 == g {
				m.Business = append(m.Business, i)
				m.Slots = append(m.Slots, b.Map.Slots[k])
				m.Components = append(m.Components, b.Map.Components[k])
			}
		}
		if len(m.Business) == 0 {
			continue
		}
		r, e := checkComplexComponents(got, want, m, b.Spec.ID, s.TargetsLowHigh[g])
		if e != nil {
			return nil, e
		}
		r.Group = name
		rows = append(rows, *r)
	}
	return rows, nil
}

func checkComplexComponents(got []*bignum.Complex, want []*big.Rat, m SlotMapping, branch string, target int) (*ComplexErrorReport, error) {
	if len(m.Components) == 0 {
		return nil, nil
	}
	if len(m.Slots) != len(m.Business) || len(m.Slots) != len(m.Components) {
		return nil, fmt.Errorf("complex check mapping length mismatch")
	}
	refs := make([][2]*big.Rat, len(got))
	for k, slot := range m.Slots {
		component, business := m.Components[k], m.Business[k]
		if slot < 0 || slot >= len(got) || component < 0 || component > 1 || business < 0 || business >= len(want) || refs[slot][component] != nil {
			return nil, fmt.Errorf("invalid/duplicate complex reference component")
		}
		refs[slot][component] = want[business]
	}
	r := &ComplexErrorReport{Branch: branch, TargetBits: target, WorstSlot: -1}
	maximum := ri(0)
	for slot, pair := range refs {
		if pair[0] == nil && pair[1] == nil {
			continue
		}
		if pair[0] == nil || pair[1] == nil || got[slot] == nil || got[slot][0].IsInf() || got[slot][1].IsInf() {
			return nil, fmt.Errorf("incomplete or non-finite complex reference")
		}
		x, _ := got[slot][0].Rat(nil)
		y, _ := got[slot][1].Rat(nil)
		dx, dy := sub(x, pair[0]), sub(y, pair[1])
		sq := add(mul(dx, dx), mul(dy, dy))
		r.Checked++
		if sq.Cmp(pow2(-2*target)) <= 0 {
			r.Passing++
		}
		if r.WorstSlot < 0 || sq.Cmp(maximum) > 0 {
			maximum, r.WorstSlot = sq, slot
		}
	}
	r.MaxSquared = maximum.RatString()
	if maximum.Sign() > 0 {
		bits := -log2Rat(maximum) / 2
		r.Bits = &bits
	}
	r.Pass = r.Checked > 0 && r.Checked == r.Passing
	return r, nil
}

func decodeWire(s *Suite, b *branchRuntime, ct *rlwe.Ciphertext) ([]*bignum.Complex, error) {
	v := make([]*bignum.Complex, b.P.MaxSlots())
	pt := rlwe.NewDecryptor(b.P, b.Family.SK).DecryptNew(ct)
	if e := b.Encoder.Decode(pt, v); e != nil {
		return nil, e
	}
	return v, nil
}

type Operation struct {
	Kind              string `json:"kind"`
	Branch            string `json:"branch"`
	InputLevel        int    `json:"input_level"`
	InputDegree       int    `json:"input_degree"`
	RemovedPrimes     int    `json:"removed_primes,omitempty"`
	Rotation          int    `json:"rotation,omitempty"`
	ComponentProducts Count  `json:"component_polynomial_products,omitempty"`
	PointwiseWords    Count  `json:"component_q_pointwise_products,omitempty"`
	KeySwitches       int    `json:"key_switch_calls"`
}
type OperationTotals struct {
	RepresentationPrimeDivisions Count            `json:"representation_component_prime_divisions"`
	CallsByKind                  map[string]Count `json:"calls_by_kind"`
	KeySwitchCalls               Count            `json:"key_switch_calls"`
	PublicComponentProducts      Count            `json:"public_component_polynomial_products"`
	PublicPointwiseWords         Count            `json:"public_component_q_pointwise_products"`
	CiphertextRescalePrimeSteps  Count            `json:"ciphertext_rescale_prime_steps"`
	ComponentPrimeDivisions      Count            `json:"component_rescale_prime_divisions"`
}

func operationTotals(ops []Operation) OperationTotals {
	x := OperationTotals{CallsByKind: map[string]Count{}}
	for _, op := range ops {
		x.CallsByKind[op.Kind]++
		x.KeySwitchCalls += Count(op.KeySwitches)
		x.PublicComponentProducts += op.ComponentProducts
		x.PublicPointwiseWords += op.PointwiseWords
		if op.Kind == "tuple_DCP" {
			x.RepresentationPrimeDivisions += Count(op.InputDegree + 1)
		}
		if op.Kind == "rescale" {
			x.CiphertextRescalePrimeSteps += Count(op.RemovedPrimes)
			x.ComponentPrimeDivisions += Count((op.InputDegree + 1) * op.RemovedPrimes)
		}
	}
	return x
}

type Phase struct {
	Name       string `json:"name"`
	Branch     string `json:"branch"`
	DurationNS Count  `json:"duration_ns"`
}
type MemoryDelta struct {
	AllocatedBytes Count  `json:"go_allocated_bytes"`
	Allocations    Count  `json:"go_allocation_count"`
	GCCount        Count  `json:"gc_count"`
	GCPauseNS      Count  `json:"gc_pause_ns"`
	HeapBefore     Count  `json:"go_heap_alloc_before_bytes"`
	HeapAfter      Count  `json:"go_heap_alloc_after_bytes"`
	Scope          string `json:"scope"`
}
type OnlineTiming struct {
	TotalNS         Count       `json:"wall_ns"`
	PhaseSumNS      Count       `json:"phase_sum_ns"`
	OutsidePhasesNS Count       `json:"outside_phases_ns"`
	Phases          []Phase     `json:"phases"`
	Memory          MemoryDelta `json:"memory"`
}
type recorder struct {
	phases []Phase
	ops    []Operation
}

func (r *recorder) phase(branch, name string, f func() error) (err error) {
	t := time.Now()
	defer func() {
		r.phases = append(r.phases, Phase{name, branch, Count(time.Since(t).Nanoseconds())})
	}()
	return f()
}
func finishTiming(t time.Time, m0 runtime.MemStats, r *recorder) (OnlineTiming, error) {
	ns := uint64(time.Since(t).Nanoseconds())
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	var sum uint64
	for _, p := range r.phases {
		sum += uint64(p.DurationNS)
	}
	if sum > ns {
		return OnlineTiming{}, fmt.Errorf("phase accounting exceeds enclosing wall interval")
	}
	return OnlineTiming{Count(ns), Count(sum), Count(ns - sum), r.phases, MemoryDelta{Count(m1.TotalAlloc - m0.TotalAlloc), Count(m1.Mallocs - m0.Mallocs), Count(m1.NumGC - m0.NumGC), Count(m1.PauseTotalNs - m0.PauseTotalNs), Count(m0.HeapAlloc), Count(m1.HeapAlloc), "process-wide Go counters around online region; NOT peak RSS or peak heap"}}, nil
}

type KeyTotals struct {
	PublicBytes     Count `json:"public_key_bytes"`
	EvaluationBytes Count `json:"evaluation_key_bytes"`
	TotalBytes      Count `json:"total_public_plus_evaluation_key_bytes"`
	PayloadBytes    Count `json:"coefficient_payload_bytes"`
	DistinctKeys    int   `json:"distinct_keys"`
}

func keyTotals(rows []KeyReport) (KeyTotals, error) {
	var out KeyTotals
	seen := map[string]KeyReport{}
	for _, r := range rows {
		if prev, ok := seen[r.ID]; ok {
			if prev.SerializedBytes != r.SerializedBytes || prev.Kind != r.Kind {
				return out, fmt.Errorf("key id collision")
			}
			continue
		}
		seen[r.ID] = r
		out.DistinctKeys++
		out.PayloadBytes += r.CoefficientPayloadBytes
		if r.Kind == "public" {
			out.PublicBytes += r.SerializedBytes
		} else {
			out.EvaluationBytes += r.SerializedBytes
		}
	}
	out.TotalBytes = out.PublicBytes + out.EvaluationBytes
	return out, nil
}
