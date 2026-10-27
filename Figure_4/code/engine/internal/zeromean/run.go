package zeromean

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type experiment struct {
	s          Settings
	u          Unit
	p          ckks.Parameters
	enc        *ckks.Encoder
	dec        *rlwe.Decryptor
	eval       *ckks.Evaluator
	sk         *rlwe.SecretKey
	unitCoeffs []*big.Int
	unitMont   ring.Poly
	truth      []*big.Rat
	input      string
	out        string
	secretL1   *big.Int
}

func Run(settingsPath, unitPath, keyDir, input, out string) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("diagnostic execution error: %v", x)
			if out != "" {
				_ = WriteJSON(filepath.Join(out, "execution_error.json"), map[string]any{"error": err.Error(), "experimental_failure": false})
			}
		}
	}()
	if input != "grow" && input != "shrink" {
		return fmt.Errorf("input must be grow or shrink")
	}
	var s Settings
	var u Unit
	must(ReadJSON(settingsPath, &s))
	must(ReadJSON(unitPath, &u))
	p, e := s.Params()
	must(e)
	if u.Period != 1 && u.Period != 2 && u.Period != 4 {
		return fmt.Errorf("expected two or four equal classes")
	}
	if s.Messages < 2 || s.Messages*u.Period > p.MaxSlots() {
		return fmt.Errorf("effective messages do not fit")
	}
	totalDrop := 0
	for _, c := range s.RescaleCounts {
		totalDrop += c
	}
	if len(s.RescaleCounts) != s.Depth || len(s.Q) != s.BottomCount+totalDrop {
		return fmt.Errorf("chain/depth mismatch")
	}
	if s.Precision != rlwe.ScalePrecision {
		return fmt.Errorf("encoding and scale precision must agree")
	}
	must(os.Mkdir(out, 0755))
	kg := rlwe.NewKeyGenerator(p)
	sk, pk := kg.GenKeyPairNew()
	rk := kg.GenRelinearizationKeyNew(sk)
	zeroPt := ckks.NewPlaintext(p, p.MaxLevel())
	zeroPt.Scale = ScaleBits(s.ScaleBits)
	zero, e := rlwe.NewEncryptor(p, pk).EncryptNew(zeroPt)
	must(e)
	exp := &experiment{s: s, u: u, p: p, sk: sk, dec: rlwe.NewDecryptor(p, sk), eval: ckks.NewEvaluator(p, rlwe.NewMemEvaluationKeySet(rk)), unitCoeffs: ParseInts(u.Coefficients), input: input, out: out}
	must(VerifySmallInverse(exp.unitCoeffs, ParseInts(u.Inverse)))
	secret := Coefficients(p.RingQ(), sk.Value.Q, true, true)
	exp.secretL1 = new(big.Int)
	for _, v := range secret {
		if new(big.Int).Abs(v).Cmp(big.NewInt(1)) > 0 {
			return fmt.Errorf("non-ternary secret")
		}
		exp.secretL1.Add(exp.secretL1, new(big.Int).Abs(v))
	}
	dense := Ints(p.N())
	stride := p.N() / len(exp.unitCoeffs)
	for i, v := range exp.unitCoeffs {
		dense[i*stride].Set(v)
	}
	exp.unitMont = p.RingQ().NewPoly()
	p.RingQ().SetCoefficientsBigint(dense, exp.unitMont)
	p.RingQ().NTT(exp.unitMont, exp.unitMont)
	p.RingQ().MForm(exp.unitMont, exp.unitMont)
	start := time.Now()
	pt, mu := exp.encodeWide()
	ct := zero.CopyNew()
	p.RingQ().Add(ct.Value[0], pt.Value, ct.Value[0])
	ct.Scale = pt.Scale
	phase := exp.dec.DecryptNew(ct)
	noise := phase.CopyNew()
	p.RingQ().Sub(phase.Value, pt.Value, noise.Value)
	edec := Coefficients(p.RingQ(), noise.Value, true, false)
	freshBound := big.NewInt(int64(20*(2*p.N()+1) + (p.N() + 1)))
	if new(big.Int).Lsh(new(big.Int).Set(freshBound), 1).Cmp(Product(s.Q)) >= 0 {
		return fmt.Errorf("fresh small-error lift not certified unique")
	}
	if MaxAbs(edec).Cmp(freshBound) > 0 {
		return fmt.Errorf("fresh noise exceeds conservative lifting guard")
	}
	a := Ints(p.N())
	for i := range a {
		a[i].Add(mu[i], edec[i])
	}
	M := SparseMultiply(a, exp.unitCoeffs)
	layers := []any{}
	terminal := "requested_depth_completed"
	firstFailure := -1
	lastValid := -1
	for depth := 0; depth <= s.Depth; depth++ {
		row, wrapped := exp.record(depth, ct, M)
		layers = append(layers, row)
		fmt.Printf("classes=%d theta=%g input=%s depth=%d wrap=%v precision=%v\n", u.Period, u.Theta, input, depth, wrapped, row["useful_precision_bits"])
		if wrapped {
			terminal = "restoration_wrap"
			firstFailure = depth
			break
		}
		lastValid = depth
		if depth == s.Depth {
			break
		}
		ct, M = exp.step(depth+1, ct, M)
		for i, x := range exp.truth {
			exp.truth[i] = new(big.Rat).Mul(x, x)
		}
	}
	host, _ := os.Hostname()
	exe, _ := os.Executable()
	result := map[string]any{"schema": "ckks-zero-mean-result-v1", "status": "completed", "terminal_reason": terminal, "first_failure_depth": firstFailure, "last_recoverable_depth": lastValid, "chain_depth_limit": s.Depth, "classes": u.Period, "requested_theta": u.Theta, "actual_log2_unit_weights": u.ActualLogs, "input_family": input, "effective_messages": s.Messages, "settings_sha256": HashFile(settingsPath), "unit_sha256": HashFile(unitPath), "fresh_noise_coefficient_max": MaxAbs(edec).String(), "fresh_noise_coefficient_bound": freshBound.String(), "binary_sha256": HashFile(exe), "host": host, "slurm_job_id": os.Getenv("SLURM_JOB_ID"), "slurm_array_task_id": os.Getenv("SLURM_ARRAY_TASK_ID"), "go_version": runtime.Version(), "diagnostic_wall_seconds": time.Since(start).Seconds(), "layers": layers, "criteria": "Exact intended restored-polynomial lift differs from its centered residue; precision and sufficient-bound violations are not stopping criteria. Chain limit is the fixed schedule's limit, not an optimized universal depth.", "integer_lift_convention": "Fresh and relinearization lifts use explicit deterministic coefficient bounds below Q/2; rescale numerator has an independent integer bound. The restored shadow is never centered before classifying wrap."}
	must(WriteJSON(filepath.Join(out, "result.json"), result))
	manifest := map[string]string{}
	entries, e := os.ReadDir(out)
	must(e)
	for _, entry := range entries {
		if !entry.IsDir() {
			manifest[entry.Name()] = HashFile(filepath.Join(out, entry.Name()))
		}
	}
	must(WriteJSON(filepath.Join(out, "manifest.json"), map[string]any{"files": manifest, "all_internal_integer_checks_pass": true, "new_HE_run": true}))
	return nil
}

func (e *experiment) encodeWide() (*rlwe.Plaintext, []*big.Int) {
	minLog := 0.0
	for _, x := range e.u.ActualLogs {
		if x < minLog {
			minLog = x
		}
	}
	bits := e.s.ScaleBits + int(math.Ceil(-minLog)) + e.s.LogN + 64
	qs := append([]uint64{}, e.s.Q...)
	prod := Product(qs)
	gen := ring.NewNTTFriendlyPrimesGenerator(59, uint64(2*e.p.N()))
	for prod.BitLen() < bits {
		q, err := gen.NextDownstreamPrime()
		must(err)
		qs = append(qs, q)
		prod.Mul(prod, new(big.Int).SetUint64(q))
	}
	wide, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: e.s.LogN, Q: qs, LogDefaultScale: 40})
	must(err)
	e.enc = ckks.NewEncoder(wide, e.s.Precision)
	weights := make([]*big.Float, e.u.Period)
	for i, v := range e.u.Embeddings {
		lo, ok := new(big.Rat).SetString(v.Lower)
		if !ok {
			panic("invalid interval")
		}
		hi, ok := new(big.Rat).SetString(v.Upper)
		if !ok {
			panic("invalid interval")
		}
		mid := new(big.Rat).Add(lo, hi)
		mid.Quo(mid, big.NewRat(2, 1))
		weights[i] = NewFloat(e.s.Precision).SetRat(mid)
	}
	values := make([]*big.Float, e.p.MaxSlots())
	for i := range values {
		values[i] = NewFloat(e.s.Precision)
	}
	e.truth = make([]*big.Rat, e.s.Messages)
	for i := range e.truth {
		x := big.NewRat(int64(e.s.Messages-1+i), int64(e.s.Messages-1))
		if e.input == "shrink" {
			x.Inv(x)
		}
		e.truth[i] = x
		values[i*e.u.Period].Quo(NewFloat(e.s.Precision).SetRat(x), weights[0])
	}
	pt := ckks.NewPlaintext(wide, wide.MaxLevel())
	pt.Scale = ScaleBits(e.s.ScaleBits)
	must(e.enc.Encode(values, pt))
	mu := Coefficients(wide.RingQ(), pt.Value, true, false)
	if new(big.Int).Lsh(MaxAbs(mu), 2).Cmp(prod) >= 0 {
		panic("wide encoding modulus has insufficient margin")
	}
	pt.Resize(0, e.p.MaxLevel())
	if !Congruent(mu, Coefficients(e.p.RingQ(), pt.Value, true, false), Product(e.s.Q)) {
		panic("encoding reduction mismatch")
	}
	must(WriteJSON(filepath.Join(e.out, "encoding.json"), map[string]any{"diagnostic_encoding_modulus_bits": prod.BitLen(), "ciphertext_modulus_bits": Product(e.s.Q).BitLen(), "encoded_coefficient_max": MaxAbs(mu).String(), "arithmetic_precision_bits": e.s.Precision, "input_recipe": "x_i=1+i/(M-1); grow uses x_i, shrink uses exact reciprocal; active slot i*classes, all other inputs zero", "wide_encoding_note": "Wide modulus only obtains the unwrapped rounded encoding coefficients. Plaintext is reduced to fixed actual Q before encryption; diagnostic moduli never enter encrypted parameters or security estimates."}))
	return pt, mu
}

func (e *experiment) multiplyUnit(ct *rlwe.Ciphertext) *rlwe.Ciphertext {
	out := ct.CopyNew()
	r := e.p.RingQ().AtLevel(ct.Level())
	for i := range out.Value {
		r.MulCoeffsMontgomery(ct.Value[i], e.unitMont, out.Value[i])
	}
	return out
}

func (e *experiment) step(depth int, ct *rlwe.Ciphertext, M []*big.Int) (*rlwe.Ciphertext, []*big.Int) {
	beforeLevel := ct.Level()
	r := e.p.RingQ().AtLevel(beforeLevel)
	Q := Product(e.s.Q[:beforeLevel+1])
	squared, err := e.eval.MulNew(ct, ct)
	must(err)
	corrected := e.multiplyUnit(squared)
	beforeRelin := e.dec.DecryptNew(corrected)
	after, err := e.eval.RelinearizeNew(corrected)
	must(err)
	phaseAfter := e.dec.DecryptNew(after)
	r.Sub(phaseAfter.Value, beforeRelin.Value, phaseAfter.Value)
	kappa := Coefficients(r, phaseAfter.Value, true, false)
	P := Product(e.s.P)
	sumBlocks := new(big.Int)
	for i := 0; i <= beforeLevel; i += len(e.s.P) {
		end := i + len(e.s.P)
		if end > beforeLevel+1 {
			end = beforeLevel + 1
		}
		sumBlocks.Add(sumBlocks, Product(e.s.Q[i:end]))
	}
	kapBound := new(big.Int).Mul(sumBlocks, big.NewInt(int64(4*e.p.N()*20)))
	kapBound.Add(kapBound, new(big.Int).Sub(P, big.NewInt(1)))
	kapBound.Quo(kapBound, P)
	kapBound.Add(kapBound, big.NewInt(int64(e.p.N()+1)))
	if new(big.Int).Lsh(new(big.Int).Set(kapBound), 1).Cmp(Q) >= 0 {
		panic("relinearization lift not certified unique")
	}
	if MaxAbs(kappa).Cmp(kapBound) > 0 {
		panic("relinearization noise exceeds conservative lifting guard")
	}
	before := after.CopyNew()
	count := e.s.RescaleCounts[depth-1]
	D := Product(e.s.Q[beforeLevel-count+1 : beforeLevel+1])
	halfD := new(big.Int).Rsh(new(big.Int).Set(D), 1)
	rho := make([][]*big.Int, 2)
	rhoPoly := make([]ring.Poly, 2)
	for component := 0; component < 2; component++ {
		old := Coefficients(r, before.Value[component], true, false)
		rho[component] = Centered(old, D)
		rhoPoly[component] = r.NewPoly()
		r.SetCoefficientsBigint(rho[component], rhoPoly[component])
		r.NTT(rhoPoly[component], rhoPoly[component])
	}
	scratch := r.NewPoly()
	for i := range after.Value {
		r.DivRoundByLastModulusManyNTT(count, after.Value[i], scratch, after.Value[i])
	}
	for j := 0; j < count; j++ {
		after.Scale = after.Scale.Div(rlwe.NewScale(e.s.Q[beforeLevel-j]))
	}
	after.Resize(1, beforeLevel-count)
	for component := 0; component < 2; component++ {
		old := Coefficients(r, before.Value[component], true, false)
		next := Coefficients(e.p.RingQ().AtLevel(after.Level()), after.Value[component], true, false)
		t := new(big.Int)
		for i := range old {
			t.Mul(D, next[i])
			t.Add(t, rho[component][i])
			t.Sub(old[i], t)
			t.Mod(t, Q)
			if t.Sign() != 0 {
				panic("actual rescale coefficient identity failed")
			}
		}
	}
	Rpoly := r.NewPoly()
	r.MulCoeffsMontgomery(rhoPoly[1], e.sk.Value.Q, Rpoly)
	r.Add(Rpoly, rhoPoly[0], Rpoly)
	R := Coefficients(r, Rpoly, true, false)
	Rbound := new(big.Int).Mul(halfD, new(big.Int).Add(e.secretL1, big.NewInt(1)))
	if new(big.Int).Lsh(new(big.Int).Set(Rbound), 1).Cmp(Q) >= 0 || MaxAbs(R).Cmp(Rbound) > 0 {
		panic("rescale numerator is not uniquely lifted")
	}
	next, shadowBits, err := ExactSquare(M)
	must(err)
	uk := SparseMultiply(kappa, e.unitCoeffs)
	ur := SparseMultiply(R, e.unitCoeffs)
	rem := new(big.Int)
	for i := range next {
		next[i].Add(next[i], uk[i])
		next[i].Sub(next[i], ur[i])
		next[i].QuoRem(next[i], D, rem)
		if rem.Sign() != 0 {
			panic("integer shadow rescale is not exact")
		}
	}
	prefix := filepath.Join(e.out, fmt.Sprintf("step_%02d", depth))
	must(WriteJSON(prefix+".json", map[string]any{"depth": depth, "rescale_divisor": D.String(), "Q_before": Q.String(), "Q_after": Product(e.s.Q[:after.Level()+1]).String(), "auxiliary_square_modulus_bits": shadowBits, "kappa_coefficient_max": MaxAbs(kappa).String(), "kappa_coefficient_bound": kapBound.String(), "rescale_numerator_coefficient_bound": Rbound.String(), "rescale_numerator_coefficient_max": MaxAbs(R).String(), "rescale_component_congruences_pass": true, "shadow_divisibility_pass": true}))
	return after, next
}

func (e *experiment) record(depth int, ct *rlwe.Ciphertext, M []*big.Int) (map[string]any, bool) {
	restored := e.multiplyUnit(ct)
	pt := e.dec.DecryptNew(restored)
	r := e.p.RingQ().AtLevel(ct.Level())
	actual := Coefficients(r, pt.Value, true, false)
	Q := Product(e.s.Q[:ct.Level()+1])
	halfQ := new(big.Int).Rsh(new(big.Int).Set(Q), 1)
	if !Congruent(M, actual, Q) || !Equals(Centered(M, Q), actual) {
		panic("shadow/actual restored phase mismatch")
	}
	wrapped := MaxAbs(M).Cmp(halfQ) > 0
	different := !Equals(M, actual)
	if wrapped != different {
		panic("wrap classification inconsistent")
	}
	prefix := filepath.Join(e.out, fmt.Sprintf("layer_%02d", depth))
	values := make([]*bignum.Complex, e.p.MaxSlots())
	must(e.enc.Decode(pt, values))
	maxErr := NewFloat(e.s.Precision)
	worst := 0
	maxRef := NewFloat(e.s.Precision)
	for i, ref := range e.truth {
		v := values[i*e.u.Period]
		refFloat := NewFloat(e.s.Precision).SetRat(ref)
		er := NewFloat(e.s.Precision).Sub(v[0], refFloat)
		er.Mul(er, er)
		im := NewFloat(e.s.Precision).Mul(v[1], v[1])
		er.Add(er, im)
		if er.Cmp(maxErr) > 0 {
			maxErr.Set(er)
			worst = i
		}
		if refFloat.Cmp(maxRef) > 0 {
			maxRef.Set(refFloat)
		}
	}
	dummyMax := NewFloat(e.s.Precision)
	for j, v := range values {
		if j%e.u.Period == 0 {
			continue
		}
		z := NewFloat(e.s.Precision).Mul(v[0], v[0])
		z.Add(z, NewFloat(e.s.Precision).Mul(v[1], v[1]))
		if z.Cmp(dummyMax) > 0 {
			dummyMax.Set(z)
		}
	}
	errorRat, _ := maxErr.Rat(nil)
	scaleRat, _ := ct.Scale.Value.Rat(nil)
	row := map[string]any{"depth": depth, "wrap": wrapped, "target_20_bits_pass": !wrapped && errorRat.Cmp(new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 40))) <= 0, "max_dummy_magnitude_log2": SafeNumber(0.5 * LogFloat(dummyMax)), "Q_exact": Q.String(), "Q_bits": LogInt(Q), "remaining_Q_primes": ct.Level() + 1, "scale_exact": scaleRat.RatString(), "scale_log2": LogFloat(&ct.Scale.Value), "shadow_coefficient_max": MaxAbs(M).String(), "centered_coefficient_max": MaxAbs(actual).String(), "allowed_coefficient_max": halfQ.String(), "shadow_to_halfQ_log2": SafeNumber(LogInt(MaxAbs(M)) - LogInt(halfQ)), "shadow_actual_congruence_pass": true, "useful_precision_bits": SafeNumber(-0.5 * LogFloat(maxErr)), "max_observed_error_squared_exact": errorRat.RatString(), "max_reference_log2": LogFloat(maxRef), "worst_message": worst, "worst_slot": worst * e.u.Period, "worst_reference_exact": e.truth[worst].RatString(), "worst_observed_real_hex": values[worst*e.u.Period][0].Text('p', 0), "worst_observed_imag_hex": values[worst*e.u.Period][1].Text('p', 0), "observer_precision_bits": e.s.Precision, "observer_note": "Exact rational serialization of the finite-precision observer; not an exact algebraic embedding."}
	must(WriteJSON(prefix+".json", row))
	return row, wrapped
}

// Ensure map diagnostics can be encoded without silently accepting nonfinite values.
var _ = json.Valid
