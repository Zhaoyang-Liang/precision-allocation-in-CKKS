package bench

// This file belongs ONLY to the independent diagnostic engine. Its timings
// are invalid for performance comparisons. Secret keys are never serialized.
import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type traceComplex [2]*big.Rat
type branchTrace struct {
	inputs        [][]*big.Rat
	previous      []traceComplex
	previousScale *big.Rat
	beforeRelin   *rlwe.Ciphertext
	beforeRescale *rlwe.Ciphertext
	kappa         []traceComplex
	initialized   bool
}

var traceRoot string
var traceConfig *ProfileConfig
var traceBranches map[*profileRuntime]*branchTrace

func initErrorTrace(out string, c *ProfileConfig) {
	traceRoot = filepath.Join(out, "error_trace")
	if e := os.Mkdir(traceRoot, 0755); e != nil {
		panic(e)
	}
	traceConfig = c
	traceBranches = map[*profileRuntime]*branchTrace{}
	mustTrace(writeProfileJSON(filepath.Join(traceRoot, "README.json"), map[string]any{
		"schema": "independent-error-trace-v1", "performance_timing_valid": false,
		"diagnostic_bits": c.Precision, "norm": "maximum complex magnitude over every physical slot; grouped by actual business mapping",
		"floating_observer": "exact rationals of high-precision FFT outputs; numerical observations, not exact algebraic embeddings",
		"closure_threshold": "2^-400", "secret_keys_saved": false,
	}))
}
func mustTrace(e error) {
	if e != nil {
		panic(e)
	}
}
func tc0() traceComplex                    { return traceComplex{ri(0), ri(0)} }
func tcAdd(a, b traceComplex) traceComplex { return traceComplex{add(a[0], b[0]), add(a[1], b[1])} }
func tcSub(a, b traceComplex) traceComplex { return traceComplex{sub(a[0], b[0]), sub(a[1], b[1])} }
func tcScale(a traceComplex, x *big.Rat) traceComplex {
	return traceComplex{mul(a[0], x), mul(a[1], x)}
}
func tcMul(a, b traceComplex) traceComplex {
	return traceComplex{sub(mul(a[0], b[0]), mul(a[1], b[1])), add(mul(a[0], b[1]), mul(a[1], b[0]))}
}
func tcNorm2(a traceComplex) *big.Rat { return add(mul(a[0], a[0]), mul(a[1], a[1])) }
func traceWeight(b *profileRuntime, j int) *big.Rat {
	x, _ := b.weights[j%len(b.weights)].Rat(nil)
	return x
}
func traceState(b *profileRuntime) *branchTrace {
	if traceBranches[b] == nil {
		traceBranches[b] = &branchTrace{}
	}
	return traceBranches[b]
}
func traceDecode(b *profileRuntime, pt *rlwe.Plaintext) []traceComplex {
	got := make([]*bignum.Complex, b.p.MaxSlots())
	mustTrace(b.encoder.Decode(pt, got))
	values := make([]traceComplex, len(got))
	for i, z := range got {
		values[i][0], _ = z[0].Rat(nil)
		values[i][1], _ = z[1].Rat(nil)
	}
	return values
}
func tracePhase(b *profileRuntime, ct *rlwe.Ciphertext) *rlwe.Plaintext {
	return rlwe.NewDecryptor(b.p, b.family.SK).DecryptNew(ct)
}
func tracePlain(b *profileRuntime, poly ring.Poly, level int, sc *big.Rat) *rlwe.Plaintext {
	pt := tracePhase(b, b.inputs[0])
	pt.Resize(0, level)
	pt.Value.Copy(poly)
	pt.Scale = scale(sc)
	return pt
}
func traceCoefficients(b *profileRuntime, pt *rlwe.Plaintext) []*big.Int {
	rq := b.p.RingQ().AtLevel(pt.Level())
	p := pt.Value.CopyNew()
	if pt.IsNTT {
		rq.INTT(*p, *p)
	}
	if pt.IsMontgomery {
		rq.IMForm(*p, *p)
	}
	coeff := make([]*big.Int, b.p.N())
	for i := range coeff {
		coeff[i] = new(big.Int)
	}
	rq.PolyToBigintCentered(*p, 1, coeff)
	return coeff
}
func traceSavePoly(name string, coeff []*big.Int) {
	f, e := os.OpenFile(filepath.Join(traceRoot, name+".coefficients.jsonl.gz"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	mustTrace(e)
	z := gzip.NewWriter(f)
	enc := json.NewEncoder(z)
	for i, c := range coeff {
		mustTrace(enc.Encode(map[string]any{"coefficient": i, "integer": c.String()}))
	}
	mustTrace(z.Close())
	mustTrace(f.Close())
}
func traceRecord(b *profileRuntime, batch int, name string, values []traceComplex, extra map[string]any) {
	prefix := fmt.Sprintf("%s_batch%d_%s", b.spec.ID, batch, name)
	f, e := os.OpenFile(filepath.Join(traceRoot, prefix+".slots.jsonl.gz"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	mustTrace(e)
	z := gzip.NewWriter(f)
	enc := json.NewEncoder(z)
	assigned := map[int]ProfileAssignment{}
	for _, a := range b.maps[batch].Values {
		assigned[a.Slot] = a
	}
	max := map[int]*big.Rat{}
	witness := map[int]int{}
	counts := map[int]int{}
	for j, v := range values {
		g, ix := -1, -1
		if a, ok := assigned[j]; ok {
			g, ix = a.Group, a.Index
		}
		n := tcNorm2(v)
		counts[g]++
		if max[g] == nil || n.Cmp(max[g]) > 0 {
			max[g] = n
			witness[g] = j
		}
		mustTrace(enc.Encode(map[string]any{"slot": j, "group": g, "index": ix, "real": v[0].RatString(), "imag": v[1].RatString()}))
	}
	mustTrace(z.Close())
	mustTrace(f.Close())
	rows := []map[string]any{}
	for g := -1; g < len(traceConfig.Targets); g++ {
		if m := max[g]; m != nil {
			var lg any
			if m.Sign() > 0 {
				lg = log2Rat(m) / 2
			}
			rows = append(rows, map[string]any{"group": g, "count": counts[g], "maximum_squared_exact_for_observer": m.RatString(), "log2_maximum_display": lg, "witness_slot": witness[g]})
		}
	}
	if extra == nil {
		extra = map[string]any{}
	}
	extra["kind"] = name
	extra["branch"] = b.spec.ID
	extra["batch"] = batch
	extra["groups"] = rows
	mustTrace(writeProfileJSON(filepath.Join(traceRoot, prefix+".json"), extra))
}
func traceRestoredErrors(b *profileRuntime, ct *rlwe.Ciphertext, batch, depth int, alreadyRestored bool) ([]traceComplex, *rlwe.Plaintext) {
	pt := tracePhase(b, ct)
	if b.forward != nil && !alreadyRestored {
		b.p.RingQ().AtLevel(ct.Level()).MulCoeffsMontgomery(pt.Value, b.forward.Poly, pt.Value)
	}
	values := traceDecode(b, pt)
	for _, v := range b.maps[batch].Values {
		values[v.Slot][0] = sub(values[v.Slot][0], profileReference(traceState(b).inputs[v.Group][v.Index], depth))
	}
	return values, pt
}
func traceFresh(b *profileRuntime, pt *rlwe.Plaintext, ct *rlwe.Ciphertext, m ProfileBatchMap, inputs [][]*big.Rat) {
	state := traceState(b)
	state.inputs = inputs
	phase := tracePhase(b, ct)
	rq := b.p.RingQ().AtLevel(ct.Level())
	noise := phase.CopyNew()
	rq.Sub(phase.Value, pt.Value, noise.Value)
	noise.Scale = scale(ri(1))
	nv := traceDecode(b, noise)
	traceRecord(b, m.Batch, "fresh_decryption_noise", nv, map[string]any{"symbol": "sigma(e_dec)", "scale_exact": "1"})
	traceSavePoly(fmt.Sprintf("%s_batch%d_e_dec", b.spec.ID, m.Batch), traceCoefficients(b, noise))
	enc := pt.CopyNew()
	enc.Scale = scale(ri(1))
	ev := traceDecode(b, enc)
	D := scaleRat(pt.Scale)
	for _, v := range m.Values {
		target := div(mul(D, inputs[v.Group][v.Index]), traceWeight(b, v.Slot))
		ev[v.Slot][0] = sub(ev[v.Slot][0], target)
	}
	traceRecord(b, m.Batch, "fresh_encoding_error", ev, map[string]any{"symbol": "sigma(e_enc)", "scale_exact": D.RatString(), "ideal_weight_note": "1024-bit midpoint of certified algebraic enclosure; enclosure width tracked in certificate"})
	traceSavePoly(fmt.Sprintf("%s_batch%d_encoded_mu", b.spec.ID, m.Batch), traceCoefficients(b, pt))
	e, restored := traceRestoredErrors(b, ct, m.Batch, 0, false)
	traceRecord(b, m.Batch, "fresh_restored_error", e, map[string]any{"symbol": "e_0 = sigma(p) eta_0"})
	traceSavePoly(fmt.Sprintf("%s_batch%d_fresh_M", b.spec.ID, m.Batch), traceCoefficients(b, restored))
	if !state.initialized {
		sk := pt.CopyNew()
		sk.Scale = scale(ri(1))
		sk.Value.Copy(b.family.SK.Value.Q)
		rq.IMForm(sk.Value, sk.Value)
		sv := traceDecode(b, sk)
		maximum := ri(0)
		for _, value := range sv {
			n := tcNorm2(value)
			if n.Cmp(maximum) > 0 {
				maximum = n
			}
		}
		mustTrace(writeProfileJSON(filepath.Join(traceRoot, b.spec.ID+"_secret_norm.json"), map[string]any{"symbol": "max_j |sigma_j(s)|", "maximum_squared_for_observer": maximum.RatString(), "log2_maximum_display": log2Rat(maximum) / 2, "secret_coefficients_or_embeddings_saved": false}))
		state.initialized = true
	}
}
func traceBeforeSquare(b *profileRuntime, ct *rlwe.Ciphertext, batch, layer int) {
	s := traceState(b)
	s.previous, _ = traceRestoredErrors(b, ct, batch, layer, false)
	s.previousScale = scaleRat(ct.Scale)
	if b.forward == nil {
		var e error
		s.beforeRelin, e = b.evaluator.MulNew(ct, ct)
		mustTrace(e)
	}
}
func traceBeforeRelin(b *profileRuntime, ct *rlwe.Ciphertext) {
	traceState(b).beforeRelin = ct.CopyNew()
}
func traceAfterRelin(b *profileRuntime, ct *rlwe.Ciphertext, batch, layer int) {
	s := traceState(b)
	before := tracePhase(b, s.beforeRelin)
	after := tracePhase(b, ct)
	b.p.RingQ().AtLevel(ct.Level()).Sub(after.Value, before.Value, after.Value)
	after.Scale = scale(ri(1))
	s.kappa = traceDecode(b, after)
	name := fmt.Sprintf("layer%d_kappa", layer+1)
	traceRecord(b, batch, name, s.kappa, map[string]any{"symbol": "sigma(kappa_v)", "definition": "centered phase(after relinearization)-phase(before relinearization), modulo active Q"})
	traceSavePoly(fmt.Sprintf("%s_batch%d_%s", b.spec.ID, batch, name), traceCoefficients(b, after))
	s.beforeRescale = ct.CopyNew()
}
func traceAfterRescale(b *profileRuntime, ct *rlwe.Ciphertext, batch, layer int) {
	s := traceState(b)
	before := s.beforeRescale
	level := before.Level()
	rq := b.p.RingQ().AtLevel(level)
	D := prod(b.p.Q()[ct.Level()+1 : level+1])
	Q := prod(b.p.Q()[:level+1])
	halfD := new(big.Int).Rsh(new(big.Int).Set(D), 1)
	residues := make([]ring.Poly, 2)
	componentMax := make([]string, 2)
	for k := 0; k < 2; k++ {
		oldpt := tracePhase(b, before)
		oldpt.Value.Copy(before.Value[k])
		old := traceCoefficients(b, oldpt)
		newpt := tracePhase(b, ct)
		newpt.Value.Copy(ct.Value[k])
		next := traceCoefficients(b, newpt)
		rho := make([]*big.Int, len(old))
		max := new(big.Int)
		for i := range old {
			rho[i] = new(big.Int).Mod(old[i], D)
			if rho[i].Cmp(halfD) > 0 {
				rho[i].Sub(rho[i], D)
			}
			abs := new(big.Int).Abs(rho[i])
			if abs.Cmp(max) > 0 {
				max.Set(abs)
			}
			relation := new(big.Int).Sub(old[i], new(big.Int).Mul(D, next[i]))
			relation.Sub(relation, rho[i])
			relation.Mod(relation, Q)
			if relation.Sign() != 0 {
				panic("rescale component identity failed")
			}
		}
		componentMax[k] = max.String()
		residues[k] = rq.NewPoly()
		rq.SetCoefficientsBigint(rho, residues[k])
		rq.NTT(residues[k], residues[k])
		traceSavePoly(fmt.Sprintf("%s_batch%d_layer%d_rho%d", b.spec.ID, batch, layer+1, k), rho)
	}
	R := rq.NewPoly()
	rq.MulCoeffsMontgomery(residues[1], b.family.SK.Value.Q, R)
	rq.Add(residues[0], R, R)
	rpt := tracePhase(b, before)
	rpt.Value.Copy(R)
	rpt.Scale = scale(ri(1))
	rv := traceDecode(b, rpt)
	nextScale := scaleRat(ct.Scale)
	divisor := new(big.Rat).SetInt(D)
	rhoMeta := div(mul(s.previousScale, s.previousScale), mul(divisor, nextScale))
	actual, mpt := traceRestoredErrors(b, ct, batch, layer+1, false)
	components := map[string][]traceComplex{}
	for _, key := range []string{"propagated", "key_switch_contribution", "rescale_contribution", "metadata_contribution", "closure_residual", "normalized_residual"} {
		components[key] = make([]traceComplex, len(actual))
	}
	intended := make([]*big.Rat, len(actual))
	for i := range intended {
		intended[i] = ri(0)
	}
	for _, a := range b.maps[batch].Values {
		intended[a.Slot] = profileReference(s.inputs[a.Group][a.Index], layer)
	}
	maximumClosure := ri(0)
	for j := range actual {
		w := traceWeight(b, j)
		e := s.previous[j]
		x := intended[j]
		propagated := tcScale(tcAdd(tcScale(e, mul(ri(2), x)), tcMul(e, e)), rhoMeta)
		ks := tcScale(s.kappa[j], div(w, mul(divisor, nextScale)))
		rs := tcScale(rv[j], neg(div(w, mul(divisor, nextScale))))
		meta := traceComplex{mul(sub(rhoMeta, ri(1)), mul(x, x)), ri(0)}
		closure := tcSub(actual[j], tcAdd(tcAdd(propagated, ks), tcAdd(rs, meta)))
		components["propagated"][j] = propagated
		components["key_switch_contribution"][j] = ks
		components["rescale_contribution"][j] = rs
		components["metadata_contribution"][j] = meta
		components["closure_residual"][j] = closure
		components["normalized_residual"][j] = tcScale(actual[j], div(ri(1), w))
		n := tcNorm2(closure)
		if n.Cmp(maximumClosure) > 0 {
			maximumClosure = n
		}
	}
	tag := fmt.Sprintf("layer%d_", layer+1)
	common := map[string]any{"layer": layer + 1, "Q_before_count": level + 1, "Q_after_count": ct.Level() + 1, "Q_after_exact": prod(b.p.Q()[:ct.Level()+1]).String(), "divisor_exact": D.String(), "scale_before_exact": s.previousScale.RatString(), "scale_after_exact": nextScale.RatString(), "metadata_rho_exact": rhoMeta.RatString(), "rho_component_coefficient_max": componentMax, "rescale_component_identity_pass": true, "closure_max_squared": maximumClosure.RatString(), "closure_pass": maximumClosure.Cmp(pow2(-800)) <= 0}
	traceRecord(b, batch, tag+"rescale_numerator", rv, map[string]any{"symbol": "sigma(rho_0+rho_1*s)", "divisor_exact": D.String()})
	traceRecord(b, batch, tag+"restored_error", actual, common)
	for key, v := range components {
		traceRecord(b, batch, tag+key, v, nil)
	}
	traceSavePoly(fmt.Sprintf("%s_batch%d_layer%d_M", b.spec.ID, batch, layer+1), traceCoefficients(b, mpt))
	if maximumClosure.Cmp(pow2(-800)) > 0 {
		panic("diagnostic error recurrence failed closure at 2^-400")
	}
}
func traceFinal(b *profileRuntime, ct *rlwe.Ciphertext, batch int) {
	e, pt := traceRestoredErrors(b, ct, batch, traceConfig.Depth, true)
	coeff := traceCoefficients(b, pt)
	max := new(big.Int)
	for _, c := range coeff {
		a := new(big.Int).Abs(c)
		if a.Cmp(max) > 0 {
			max.Set(a)
		}
	}
	Q := prod(b.p.Q()[:ct.Level()+1])
	ratio := new(big.Rat).SetFrac(new(big.Int).Lsh(max, 1), Q)
	traceRecord(b, batch, "final_restored_error", e, map[string]any{"M_centered_coefficient_infinity": max.String(), "Q_exact": Q.String(), "scale_exact": scaleRat(ct.Scale).RatString(), "centered_coefficient_ratio_2M_over_Q": ratio.RatString(), "range_note": "Centered representative observation; no-wrap is established separately by the propagated certificate, not by this ratio alone."})
}
