package bench

import (
	"ckks-precision-experiments/neighbor"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type NativeView struct {
	VerificationMode  string         `json:"verification_mode"`
	Outputs           []OutputReport `json:"outputs"`
	PhaseSumNS        Count          `json:"core_phase_sum_ns"`
	ConversionPhaseNS Count          `json:"interop_conversion_phase_sum_ns"`
	PayloadBytes      Count          `json:"coefficient_payload_bytes"`
	SerializedBytes   Count          `json:"serialized_bytes"`
	Errors            [2]GroupError  `json:"client_decode_errors_low_high"`
	Continuation      string         `json:"continuation_contract"`
	Scope             string         `json:"timing_scope"`
}
type TupleReport struct {
	BaseParameters     ParamReport  `json:"actual_base_parameters"`
	ExtendedParameters ParamReport  `json:"actual_extended_key_parameters"`
	LowParameters      *ParamReport `json:"actual_ordinary_low_parameters,omitempty"`
	QDiv               string       `json:"q_div_exact"`
	ContextID          string       `json:"context_id"`
	CaseReport
	TupleConfiguration TupleCase       `json:"tuple_configuration"`
	Native             NativeView      `json:"native_view"`
	Layers             []GraphState    `json:"actual_tuple_layers"`
	KeyReuse           string          `json:"key_reuse"`
	SharedKey          *SharedKeyAudit `json:"shared_key_audit,omitempty"`
}

// The base view is a logical key, not an additional stored/transmitted key.
// Its standalone serialized size is diagnostic and excluded from Keys/Totals.
type SharedKeyAudit struct {
	Mode                       string    `json:"mode"`
	OwnerSHA256                string    `json:"owner_sha256"`
	BaseView                   KeyReport `json:"base_view_if_serialized_separately_NOT_CHARGED"`
	AdditionalCoefficientBytes Count     `json:"additional_base_coefficient_bytes"`
	AdditionalSerializedBytes  Count     `json:"additional_base_serialized_key_bytes"`
	AliasesVerified            bool      `json:"all_coefficient_arrays_alias_owner"`
	OwnerUnchanged             bool      `json:"owner_unchanged_after_evaluation"`
	ViewUnchanged              bool      `json:"view_unchanged_after_evaluation"`
	Contract                   string    `json:"storage_and_wire_contract"`
}

func tupleDataSuite(s *TupleSuite) *Suite {
	return &Suite{ID: s.ID, Task: "pow16", Entry: "native", GroupSize: s.GroupSize, TargetsLowHigh: s.Targets, Seed: s.Seed, Precision: s.Precision, GOMAXPROCS: s.GOMAXPROCS}
}
func publicKeyProjection(c *neighbor.Context, p *rlwe.PublicKey) *rlwe.PublicKey {
	o := rlwe.NewPublicKey(c.Base)
	for k := range o.Value {
		for i := range o.Value[k].Q.Coeffs {
			copy(o.Value[k].Q.Coeffs[i], p.Value[k].Q.Coeffs[i+1])
		}
		for i := range o.Value[k].P.Coeffs {
			copy(o.Value[k].P.Coeffs[i], p.Value[k].P.Coeffs[i])
		}
	}
	return o
}
func tupleRunCase(s *TupleSuite, c TupleCase, d *Dataset, dir string) (report TupleReport) {
	report.CaseReport = CaseReport{ID: c.ID, Status: "started", Config: CaseSpec{ID: c.ID, Kind: c.Kind, Branches: []BranchSpec{{ID: "tuple", Parameters: c.Extended, ScaleBits: c.ScaleBits, RescaleCounts: c.RescaleCounts}}}}
	report.TupleConfiguration = c
	if c.Low != nil {
		report.Config.Branches = append(report.Config.Branches, *c.Low)
	}
	stage := "preparation"
	defer func() {
		if v := recover(); v != nil {
			report.Status = "panic"
			report.Failure = fmt.Sprint(v)
			report.FailureStage = stage
		}
	}()
	fail := func(e error) { report.Status = "error"; report.Failure = e.Error(); report.FailureStage = stage }
	prepStart := time.Now()
	ds := tupleDataSuite(s)
	ctx, e := tupleContext(c)
	if e != nil {
		fail(e)
		return
	}
	report.BaseParameters = paramReport(ctx.Base)
	report.ExtendedParameters = paramReport(ctx.Extended)
	report.QDiv = fmt.Sprint(ctx.QDiv)
	report.ContextID = ctx.ID
	if !securityCap(ctx.Extended) {
		fail(fmt.Errorf("extended Q*qDiv*P exceeds documented security cap"))
		return
	}
	report.Preparation.ParameterConstructionNS = Count(time.Since(prepStart).Nanoseconds())
	start := time.Now()
	kg := rlwe.NewKeyGenerator(ctx.Extended)
	skExt := kg.GenSecretKeyNew()
	skBase, e := ctx.ProjectSecret(skExt)
	if e != nil {
		fail(e)
		return
	}
	pk := kg.GenPublicKeyNew(skExt)
	var rkBase, rkExt *rlwe.RelinearizationKey
	if c.RelinStorage == "shared_single_p" {
		rkExt = kg.GenRelinearizationKeyNew(skExt)
		rkBase, e = ctx.ProjectRelinearizationKeySingleP(rkExt)
		if e != nil {
			fail(e)
			return
		}
		if e = ctx.CheckRelinearizationKeyView(rkBase, rkExt); e != nil {
			fail(e)
			return
		}
		report.SharedKey = &SharedKeyAudit{Mode: c.RelinStorage, AliasesVerified: true,
			Contract: "Only the extended owner is stored and serialized as key material. Base view is reconstructed from the public context by dropping gadget row zero and Q limb zero; P retained. Slice headers/Go object overhead and protocol framing are not coefficient payload. No base key generation or coefficient copy. Shared errors need not be independent."}
	} else {
		kgb := rlwe.NewKeyGenerator(ctx.Base)
		rkBase = kgb.GenRelinearizationKeyNew(skBase)
		rkExt = kg.GenRelinearizationKeyNew(skExt)
	}
	report.Preparation.KeyGenerationNS = Count(time.Since(start).Nanoseconds())
	start = time.Now()
	for _, key := range []struct {
		kind string
		w    binaryWriter
		g    *rlwe.GadgetCiphertext
	}{{"tuple_base_relinearization", rkBase, &rkBase.GadgetCiphertext}, {"tuple_extended_relinearization", rkExt, &rkExt.GadgetCiphertext}} {
		row, err := gadgetReport(key.kind, key.w, key.g, 0)
		if err != nil {
			fail(err)
			return
		}
		if report.SharedKey != nil {
			if key.kind == "tuple_base_relinearization" {
				report.SharedKey.BaseView = row
				continue
			}
			report.SharedKey.OwnerSHA256 = row.SHA256
		}
		report.Keys = append(report.Keys, row)
	}
	row, e := publicKeyReport(pk)
	if e != nil {
		fail(e)
		return
	}
	report.Keys = append(report.Keys, row)
	report.Preparation.KeyAccountingNS += Count(time.Since(start).Nanoseconds())
	start = time.Now()
	keysBase := rlwe.NewMemEvaluationKeySet(rkBase)
	evBase := ckks.NewEvaluator(ctx.Base, keysBase)
	evExt := ckks.NewEvaluator(ctx.Extended, rlwe.NewMemEvaluationKeySet(rkExt))
	report.Preparation.ServerPreparationNS += Count(time.Since(start).Nanoseconds())
	start = time.Now()
	encoder := ckks.NewEncoder(ctx.Extended, s.Precision)
	encoderBase := ckks.NewEncoder(ctx.Base, s.Precision)
	report.Preparation.ClientPreparationNS += Count(time.Since(start).Nanoseconds())
	start = time.Now()
	group, layout := "all", "interleaved"
	if c.Kind == "tuple_high_ordinary_low" {
		group, layout = "high", "compact"
	}
	m := mapping(ds, BranchSpec{Group: group, Layout: layout})
	values := make([]*big.Float, ctx.Extended.MaxSlots())
	for i := range values {
		values[i] = bf(ri(0), s.Precision)
	}
	for i, j := range m.Slots {
		values[j] = bf(d.Values[m.Business[i]], s.Precision)
	}
	pt := ckks.NewPlaintext(ctx.Extended, ctx.Extended.MaxLevel())
	pt.Scale = scale(pow2(c.ScaleBits))
	if e = encoder.Encode(values, pt); e != nil {
		fail(e)
		return
	}
	input, e := rlwe.NewEncryptor(ctx.Extended, pk).EncryptNew(pt)
	if e != nil {
		fail(e)
		return
	}
	pair, e := ctx.Decompose(input)
	if e != nil {
		fail(e)
		return
	}
	report.Preparation.ClientEncodeEncryptNS += Count(time.Since(start).Nanoseconds())
	// Send both native components. Do not charge a nonexistent ordinary input.
	start = time.Now()
	for _, ct := range []*rlwe.Ciphertext{pair.Pair.Hi, pair.Pair.Lo} {
		_, wire, cr, err := wireCipher(ctx.Base, ct)
		if err != nil {
			fail(err)
			return
		}
		*ct = *wire
		report.InputReports = append(report.InputReports, cr)
	}
	report.Preparation.InputWireNS += Count(time.Since(start).Nanoseconds())
	initialHi, initialLo := report.InputReports[0].SHA256, report.InputReports[1].SHA256
	var low *branchRuntime
	if c.Low != nil {
		lp, err := c.Low.Parameters.Build()
		if err != nil {
			fail(err)
			return
		}
		pr := paramReport(lp)
		report.LowParameters = &pr
		if !securityCap(lp) {
			fail(fmt.Errorf("low security cap"))
			return
		}
		var family *keyFamily
		if compatiblePrefix(ctx.Base, lp) {
			family = &keyFamily{P: ctx.Base, SK: skBase, PK: publicKeyProjection(ctx, pk), Keys: keysBase}
			report.KeyReuse = "ordinary low reuses base evaluation key and projected extended public key; projection needs no new key material"
		} else {
			family, err = newKeyFamily(lp)
			if err != nil {
				fail(err)
				return
			}
			g, a, err := family.prepareKeys(nil, lp.MaxLevel(), -1)
			if err != nil {
				fail(err)
				return
			}
			report.Preparation.KeyGenerationNS += family.KeygenNS + g
			report.Preparation.KeyAccountingNS += family.AccountingNS + a
			report.Keys = append(report.Keys, family.Rows...)
			report.KeyReuse = "ordinary low Q/P or N incompatible: separate context; two Tuple relinearization keys are still reused at all layers"
		}
		low = &branchRuntime{Spec: *c.Low, P: lp, Family: family, Encoder: ckks.NewEncoder(lp, s.Precision), Evaluator: ckks.NewEvaluator(lp, family.Keys), Map: mapping(ds, *c.Low), Scratch: lp.RingQ().NewPoly()}
		low.Representation, err = NewRepresentation(lp, CaseSpec{Kind: "ordinary_split"}, s.Precision)
		if err != nil {
			fail(err)
			return
		}
		start = time.Now()
		low.Input, err = encodeInput(ds, d, low)
		if err != nil {
			fail(err)
			return
		}
		report.Preparation.ClientEncodeEncryptNS += Count(time.Since(start).Nanoseconds())
		w, wire, cr, err := wireCipher(lp, low.Input)
		if err != nil {
			fail(err)
			return
		}
		low.Input = wire
		low.InputWire = w
		report.InputReports = append(report.InputReports, cr)
	} else {
		report.KeyReuse = "two relinearization keys total, reused at every active prefix; one extended public key"
	}
	if report.SharedKey != nil {
		report.KeyReuse = "Tuple base and extended evaluators share one extended owner via a read-only single-P base view; reused at every layer."
		if low != nil {
			if compatiblePrefix(ctx.Base, low.P) {
				report.KeyReuse += " Ordinary low reuses the base view and projected public key."
			} else {
				report.KeyReuse += " Ordinary low Q/P or N incompatible: separate context charged."
			}
		}
	}
	report.KeyTotals, e = keyTotals(report.Keys)
	if e != nil {
		fail(e)
		return
	}
	report.Preparation.TotalWallNS = Count(time.Since(prepStart).Nanoseconds())
	ps := report.Preparation.ParameterConstructionNS + report.Preparation.KeyGenerationNS + report.Preparation.KeyAccountingNS + report.Preparation.ClientPreparationNS + report.Preparation.ClientEncodeEncryptNS + report.Preparation.InputWireNS + report.Preparation.ServerPreparationNS
	if ps > report.Preparation.TotalWallNS {
		fail(fmt.Errorf("preparation accounting overlaps"))
		return
	}
	report.Preparation.OtherNS = report.Preparation.TotalWallNS - ps
	stage = "online"
	report.OnlineAttempted = true
	r := &recorder{}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	start = time.Now()
	current := pair
	var lowOut *rlwe.Ciphertext
	if low != nil {
		lowOut = low.Input
	}
	for k, n := range c.RescaleCounts {
		err := r.phase("tuple", fmt.Sprintf("square_%d", k+1), func() error {
			l := current.Pair.Hi.Level()
			var er error
			current, er = ctx.Square(current, evBase, evExt)
			if er != nil {
				return er
			}
			r.ops = append(r.ops, Operation{Kind: "ciphertext_square", Branch: "tuple_hi", InputLevel: l, InputDegree: 1}, Operation{Kind: "ciphertext_multiply", Branch: "tuple_cross", InputLevel: l, InputDegree: 1}, Operation{Kind: "relinearize", Branch: "tuple_base", InputLevel: l, InputDegree: 2, KeySwitches: 1}, Operation{Kind: "relinearize", Branch: "tuple_extended", InputLevel: l + 1, InputDegree: 2, KeySwitches: 1}, Operation{Kind: "tuple_exact_lift", Branch: "tuple", InputLevel: l, InputDegree: 2, ComponentProducts: 3, PointwiseWords: Count(3 * ctx.Base.N() * (l + 1))}, Operation{Kind: "tuple_DCP", Branch: "tuple", InputLevel: l + 1, InputDegree: 1, ComponentProducts: 2, PointwiseWords: Count(2 * ctx.Base.N() * (l + 1))}, Operation{Kind: "tuple_cross_times_two", Branch: "tuple", InputLevel: l, InputDegree: 2, ComponentProducts: 3, PointwiseWords: Count(3 * ctx.Base.N() * (l + 1))}, Operation{Kind: "tuple_low_add", Branch: "tuple", InputLevel: l, InputDegree: 1})
			for j := 0; j < n; j++ {
				before := current.Pair.Hi.Level()
				current, er = ctx.RescaleOne(current)
				if er != nil {
					return er
				}
				for _, part := range []string{"tuple_hi", "tuple_recombined"} {
					r.ops = append(r.ops, Operation{Kind: "rescale", Branch: part, InputLevel: before, InputDegree: 1, RemovedPrimes: 1})
				}
				r.ops = append(r.ops, Operation{Kind: "tuple_RS2_recombine_and_low_correction", Branch: "tuple", InputLevel: before, InputDegree: 1, ComponentProducts: 4, PointwiseWords: Count(2 * ctx.Base.N() * (2*before + 1))})
			}
			report.Layers = append(report.Layers, graphState(current.Pair.Hi))
			return nil
		})
		if err != nil {
			report.Online, _ = finishTiming(start, mem, r)
			fail(err)
			return
		}
	}
	if low != nil {
		for k, n := range low.Spec.RescaleCounts {
			err := r.phase("low", fmt.Sprintf("square_%d", k+1), func() error {
				l := lowOut.Level()
				var er error
				lowOut, er = low.Evaluator.MulRelinNew(lowOut, lowOut)
				if er != nil {
					return er
				}
				r.ops = append(r.ops, Operation{Kind: "ciphertext_square", Branch: "low", InputLevel: l, InputDegree: 1, KeySwitches: 1})
				return rescaleInPlace(low.P, lowOut, n, low.Scratch, r, "low")
			})
			if err != nil {
				report.Online, _ = finishTiming(start, mem, r)
				fail(err)
				return
			}
		}
	}
	for _, p := range r.phases {
		report.Native.PhaseSumNS += p.DurationNS
	}
	var combined *rlwe.Ciphertext
	e = r.phase("tuple", "ordinary_CKKS_interop_recombine", func() error {
		var err error
		combined, err = ctx.Recombine(current)
		r.ops = append(r.ops, Operation{Kind: "tuple_RCB", Branch: "tuple", InputLevel: current.Pair.Hi.Level(), InputDegree: 1, ComponentProducts: 2, PointwiseWords: Count(2 * ctx.Base.N() * (current.Pair.Hi.Level() + 1))})
		return err
	})
	report.Native.ConversionPhaseNS = r.phases[len(r.phases)-1].DurationNS
	report.Online, _ = finishTiming(start, mem, r)
	report.Operations = r.ops
	report.OperationTotals = operationTotals(r.ops)
	if e != nil {
		fail(e)
		return
	}
	report.OnlineCompleted = true
	stage = "verification"
	verificationStart := time.Now()
	defer func() { report.VerificationNS = Count(time.Since(verificationStart).Nanoseconds()) }()
	if report.SharedKey != nil {
		if e = ctx.CheckRelinearizationKeyView(rkBase, rkExt); e != nil {
			fail(e)
			return
		}
		_, ownerHash, err := measureSerialized(rkExt)
		if err != nil {
			fail(err)
			return
		}
		_, viewHash, err := measureSerialized(rkBase)
		if err != nil {
			fail(err)
			return
		}
		report.SharedKey.OwnerUnchanged = ownerHash == report.SharedKey.OwnerSHA256
		report.SharedKey.ViewUnchanged = viewHash == report.SharedKey.BaseView.SHA256
		if !report.SharedKey.OwnerUnchanged || !report.SharedKey.ViewUnchanged {
			fail(fmt.Errorf("shared evaluation key mutated"))
			return
		}
	}
	expected := pair.Pair.Hi.Scale
	expectedLevel := ctx.Base.MaxLevel()
	for k, actual := range report.Layers {
		expected = expected.Mul(expected).Div(rlwe.NewScale(ctx.QDiv))
		for j := 0; j < c.RescaleCounts[k]; j++ {
			expected = expected.Div(rlwe.NewScale(ctx.Base.Q()[expectedLevel-j]))
		}
		expectedLevel -= c.RescaleCounts[k]
		if actual.Level != expectedLevel || actual.Scale != scaleRat(expected).RatString() {
			fail(fmt.Errorf("Tuple actual metadata differs from plan"))
			return
		}
	}

	ref := d.Reference("pow16", 16)
	acc := newErrors(s.Targets)
	nativeAcc := newErrors(s.Targets)
	addOutput := func(name string, p ckks.Parameters, ct *rlwe.Ciphertext, native bool) (*rlwe.Ciphertext, error) {
		wire, v, cr, err := wireCipher(p, ct)
		if err != nil {
			return nil, err
		}
		o := OutputReport{Branch: name, Group: group, Ciphertext: cr}
		if name == "low" {
			o.Group = "low"
		}
		if native {
			report.Native.Outputs = append(report.Native.Outputs, o)
			report.Native.PayloadBytes += cr.PayloadBytes
			report.Native.SerializedBytes += cr.SerializedBytes
		} else {
			report.Outputs = append(report.Outputs, o)
		}
		if err = writeBytesNew(filepath.Join(dir, name+".ct"), wire); err != nil {
			return nil, err
		}
		return v, nil
	}
	hi, e := addOutput("tuple_native_hi", ctx.Base, current.Pair.Hi, true)
	if e != nil {
		fail(e)
		return
	}
	lo, e := addOutput("tuple_native_lo", ctx.Base, current.Pair.Lo, true)
	if e != nil {
		fail(e)
		return
	}
	out, e := addOutput("tuple_interop", ctx.Base, combined, false)
	if e != nil {
		fail(e)
		return
	}
	decode := func(p ckks.Parameters, enc *ckks.Encoder, sk *rlwe.SecretKey, ct *rlwe.Ciphertext) ([]*bignum.Complex, error) {
		v := make([]*bignum.Complex, p.MaxSlots())
		er := enc.Decode(rlwe.NewDecryptor(p, sk).DecryptNew(ct), v)
		return v, er
	}
	vh, e := decode(ctx.Base, encoderBase, skBase, hi)
	if e != nil {
		fail(e)
		return
	}
	vl, e := decode(ctx.Base, encoderBase, skBase, lo)
	if e != nil {
		fail(e)
		return
	}
	qd := new(big.Float).SetPrec(s.Precision).SetUint64(ctx.QDiv)
	for i := range vh {
		for j := 0; j < 2; j++ {
			vh[i][j].Mul(vh[i][j], qd)
			vh[i][j].Add(vh[i][j], vl[i][j])
		}
	}
	if e = nativeAcc.addDecoded(vh, ref, m); e != nil {
		fail(e)
		return
	}
	v, e := decode(ctx.Base, encoderBase, skBase, out)
	if e != nil {
		fail(e)
		return
	}
	if e = acc.addDecoded(v, ref, m); e != nil {
		fail(e)
		return
	}
	if low != nil {
		lowWire, err := addOutput("low", low.P, lowOut, false)
		if err != nil {
			fail(err)
			return
		}
		cr := report.Outputs[len(report.Outputs)-1]
		report.Native.Outputs = append(report.Native.Outputs, cr)
		report.Native.PayloadBytes += cr.Ciphertext.PayloadBytes
		report.Native.SerializedBytes += cr.Ciphertext.SerializedBytes
		v, err := decode(low.P, low.Encoder, low.Family.SK, lowWire)
		if err != nil {
			fail(err)
			return
		}
		if err = acc.addDecoded(v, ref, low.Map); err != nil {
			fail(err)
			return
		}
		if err = nativeAcc.addDecoded(v, ref, low.Map); err != nil {
			fail(err)
			return
		}
	}
	_, _, h, _ := wireCipher(ctx.Base, pair.Pair.Hi)
	_, _, l, _ := wireCipher(ctx.Base, pair.Pair.Lo)
	report.InputsUnchanged = h.SHA256 == initialHi && l.SHA256 == initialLo
	if low != nil {
		w, err := low.Input.MarshalBinary()
		if err != nil || hashBytes(w) != hashBytes(low.InputWire) {
			report.InputsUnchanged = false
		}
	}
	if !report.InputsUnchanged {
		fail(fmt.Errorf("input modified"))
		return
	}
	report.Errors = acc.rows()
	report.Native.Errors = nativeAcc.rows()
	report.ObservedPass = report.Errors[0].Pass && report.Errors[1].Pass && report.Native.Errors[0].Pass && report.Native.Errors[1].Pass
	report.Status = "completed"
	report.Native.VerificationMode = "Native Hi/Lo decoded separately, combined at client and checked against exact x^16; interop output independently checked."
	report.Native.Continuation = "Same-context addition and exact integer scalar operations preserve native semantics. A further Tuple square requires degree one, the next Lo/error recurrence and enough Q; no additional square has been certified or run at this endpoint."
	report.Native.Scope = "Core phase sums include all arithmetic and public corrections; full online wall includes interop conversion and instrumentation; do not compare a phase sum with another method's wall time."
	report.Business = BusinessReport{RequestedLowHigh: [2]int{s.GroupSize, s.GroupSize}, InputCiphertexts: len(report.InputReports), OutputCiphertexts: len(report.Outputs), AllRequestedValid: report.ObservedPass, Scope: "ordinary-CKKS interoperability view; native two-component view reported separately; no compression"}
	for _, r := range report.InputReports {
		report.Business.InputBytes += r.SerializedBytes
		report.Business.InputPhysicalSlots += r.PhysicalSlots
	}
	for _, o := range report.Outputs {
		report.Business.OutputBytes += o.Ciphertext.SerializedBytes
		report.Business.OutputPayloadBytes += o.Ciphertext.PayloadBytes
		report.Business.OutputPhysicalSlots += o.Ciphertext.PhysicalSlots
	}
	report.Business.OutputBytesPerRequestedResult = new(big.Rat).SetFrac(new(big.Int).SetUint64(uint64(report.Business.OutputBytes)), big.NewInt(int64(2*s.GroupSize))).RatString()
	return
}
func RunTuple(s *TupleSuite, raw []byte, dir, selected string) error {
	if s.Targets != [2]int{22, 72} {
		return fmt.Errorf("112/32 is public-planning-only in this handoff")
	}
	if e := backendCheck(); e != nil {
		return e
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	runtime.GOMAXPROCS(s.GOMAXPROCS)
	ds := tupleDataSuite(s)
	data := NewDataset(ds)
	var reports []TupleReport
	ids := map[string]bool{}
	if selected != "" {
		for _, id := range strings.Split(selected, ",") {
			ids[id] = true
		}
	}
	for _, c := range s.Cases {
		if len(ids) > 0 && !ids[c.ID] {
			continue
		}
		subdir := filepath.Join(dir, c.ID)
		if e := os.Mkdir(subdir, 0700); e != nil {
			return e
		}
		reports = append(reports, tupleRunCase(s, c, data, subdir))
	}
	if len(reports) == 0 {
		return fmt.Errorf("no selected Tuple case")
	}
	return writeNew(filepath.Join(dir, "results.json"), map[string]any{"schema": "tuple2-runtime-v1", "backend": Backend, "config_sha256": hashBytes(raw), "dataset_sha256": data.SHA256, "cases": reports, "HE_execution_count": len(reports), "note": "reference implementation; no claim of author-optimized Tuple performance; no compressed communication measurement"})
}
