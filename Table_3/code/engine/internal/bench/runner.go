package bench

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

type BranchReport struct {
	ID              string           `json:"id"`
	Group           string           `json:"group"`
	Layout          string           `json:"layout"`
	Parameters      ParamReport      `json:"work_parameters"`
	KeyParameters   ParamReport      `json:"key_family_parameters"`
	BusinessResults int              `json:"business_results"`
	PublicKeyID     string           `json:"public_key_id"`
	Constants       []ConstantReport `json:"public_constants"`
}
type Checkpoint struct {
	Name                    string               `json:"name"`
	Branch                  string               `json:"branch"`
	Ciphertext              CipherReport         `json:"diagnostic_restored_wire_ciphertext"`
	Errors                  [2]GroupError        `json:"errors_low_high"`
	ComplexError            *ComplexErrorReport  `json:"complex_vector_error,omitempty"`
	ComplexGroupErrors      []ComplexErrorReport `json:"complex_group_errors,omitempty"`
	Note                    string               `json:"scope"`
	StoredScale             string               `json:"stored_scale_exact"`
	StoredQComponents       int                  `json:"stored_q_components"`
	CumulativeBranchPhaseNS Count                `json:"cumulative_branch_phase_ns"`
}
type OutputReport struct {
	Branch     string       `json:"branch"`
	Group      string       `json:"group"`
	Ciphertext CipherReport `json:"ciphertext"`
}
type BusinessReport struct {
	RequestedLowHigh              [2]int      `json:"requested_low_high"`
	InputCiphertexts              int         `json:"input_ciphertexts"`
	InputPhysicalSlots            int         `json:"input_physical_slots"`
	OutputCiphertexts             int         `json:"output_ciphertexts"`
	OutputPhysicalSlots           int         `json:"output_physical_slots"`
	InputBytes                    Count       `json:"input_serialized_bytes"`
	OutputBytes                   Count       `json:"output_serialized_bytes"`
	OutputPayloadBytes            Count       `json:"output_coefficient_payload_bytes"`
	AllRequestedValid             bool        `json:"all_requested_results_valid"`
	OutputBytesPerRequestedResult string      `json:"output_bytes_per_requested_result_exact"`
	ValidResultsPerSecond         *float64    `json:"observed_valid_results_per_second"`
	ValidResultsPerSecondExact    *string     `json:"observed_valid_results_per_second_exact"`
	ValidLowHighPerSecond         [2]*float64 `json:"observed_valid_low_high_per_second"`
	Scope                         string      `json:"scope"`
}

type CaseReport struct {
	Native                  *NativeView                 `json:"native_view,omitempty"`
	ApproximationChecks     map[string]any              `json:"polynomial_accuracy_breakdown,omitempty"`
	PolynomialGraphs        map[string]*PolynomialGraph `json:"actual_polynomial_graphs,omitempty"`
	OnlineAttempted         bool                        `json:"online_attempted"`
	OnlineCompleted         bool                        `json:"online_completed"`
	ID                      string                      `json:"id"`
	Status                  string                      `json:"status"`
	Failure                 string                      `json:"failure,omitempty"`
	FailureStage            string                      `json:"failure_stage,omitempty"`
	Config                  CaseSpec                    `json:"configuration"`
	Preparation             Preparation                 `json:"preparation"`
	Branches                []BranchReport              `json:"branches"`
	Keys                    []KeyReport                 `json:"keys"`
	KeyTotals               KeyTotals                   `json:"key_totals_deduplicated"`
	InputReports            []CipherReport              `json:"inputs"`
	Outputs                 []OutputReport              `json:"outputs"`
	Online                  OnlineTiming                `json:"online"`
	Operations              []Operation                 `json:"executed_operations"`
	OperationTotals         OperationTotals             `json:"operation_totals"`
	Checkpoints             []Checkpoint                `json:"checkpoints"`
	Errors                  [2]GroupError               `json:"final_errors_low_high"`
	ComplexErrors           []ComplexErrorReport        `json:"final_complex_vector_errors,omitempty"`
	ComplexGroupTargetsPass *bool                       `json:"paired_complex_group_targets_pass,omitempty"`
	Business                BusinessReport              `json:"business"`
	InputsUnchanged         bool                        `json:"inputs_unchanged"`
	VerificationNS          Count                       `json:"verification_serialization_diagnostics_ns"`
	ObservedPass            bool                        `json:"observed_targets_pass"`
	Certified               bool                        `json:"formally_certified_by_this_program"`
}

func writeNew(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func writeBytesNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

func backendCheck() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("missing Go dependency build information")
	}
	for _, m := range info.Deps {
		if m.Path == "github.com/tuneinsight/lattigo/v6" {
			if m.Version != "v6.2.0" || m.Replace != nil {
				return fmt.Errorf("backend must be unmodified Lattigo v6.2.0, found %+v", m)
			}
			return nil
		}
	}
	return fmt.Errorf("Lattigo module absent from build information")
}

func runCase(s *Suite, c CaseSpec, d *Dataset, src *existingSource, outDir string) (report CaseReport) {
	report = CaseReport{ID: c.ID, Status: "started", Config: c, Certified: false}
	stage := "preparation"
	defer func() {
		if x := recover(); x != nil {
			report.Status = "panic"
			report.Failure = fmt.Sprint(x)
			report.FailureStage = stage
		}
	}()
	fail := func(e error) { report.Status = "error"; report.Failure = e.Error(); report.FailureStage = stage }
	p, e := prepareCase(s, c, d, src)
	if p != nil {
		report.Preparation = p.Preparation
	}
	if e != nil {
		fail(e)
		return
	}
	report.InputReports = p.InputReports
	for _, b := range p.Branches {
		report.Branches = append(report.Branches, BranchReport{b.Spec.ID, b.Spec.Group, b.Spec.Layout, paramReport(b.P), paramReport(b.Family.P), len(b.Map.Business), b.Family.Rows[0].ID, b.Constants})
	}
	for _, f := range p.Families {
		report.Keys = append(report.Keys, f.Rows...)
	}
	report.KeyTotals, e = keyTotals(report.Keys)
	if e != nil {
		fail(e)
		return
	}
	stage = "online"
	report.OnlineAttempted = true
	outputs, traces, timing, ops, e := evaluate(s, p.Branches, src)
	report.Online, report.Operations = timing, ops
	report.PolynomialGraphs = map[string]*PolynomialGraph{}
	for _, b := range p.Branches {
		if b.ActualGraph != nil {
			report.PolynomialGraphs[b.Spec.ID] = b.ActualGraph
		}
	}
	report.OperationTotals = operationTotals(ops)
	if e != nil {
		fail(e)
		return
	}
	stage = "verification"
	for _, b := range p.Branches {
		if b.Spec.Algorithm == "chebyshev6" {
			if err := auditPolynomialGraph(b.ActualGraph, b.ExpectedGraph); err != nil {
				fail(err)
				return
			}
		}
	}
	report.OnlineCompleted = true
	start := time.Now()
	defer func() { report.VerificationNS = Count(time.Since(start).Nanoseconds()) }()
	if e = verifyUnchanged(p, src); e != nil {
		fail(e)
		return
	}
	report.InputsUnchanged = true
	errors := newErrors(s.TargetsLowHigh)
	ref := d.Reference(s.Task, 256)
	report.Native = &NativeView{VerificationMode: "Logical result checked via the recorded public restoration/output conversion; not a second independent native decryption.", Continuation: "Native representation supports same-layout addition and exact integer scalar operations with updated error/range. Further nonlinear gates require remaining modulus and a fresh error check; no extra gate certified here.", Scope: "Core phase sum versus separately itemized interop phases; full online wall remains the primary existing timing. Native serialization is outside online timing."}
	for _, b := range p.Branches {
		if b.NativeOutput == nil {
			continue
		}
		_, _, cr, er := wireCipher(b.P, b.NativeOutput)
		if er != nil {
			fail(er)
			return
		}
		report.Native.Outputs = append(report.Native.Outputs, OutputReport{Branch: b.Spec.ID, Group: b.Spec.Group, Ciphertext: cr})
		report.Native.PhaseSumNS += b.NativePhaseSum
		report.Native.PayloadBytes += cr.PayloadBytes
		report.Native.SerializedBytes += cr.SerializedBytes
	}
	report.Native.ConversionPhaseNS = report.Online.PhaseSumNS - report.Native.PhaseSumNS
	report.ApproximationChecks = map[string]any{}

	for _, o := range outputs {
		wire, ct, cr, err := wireCipher(o.Branch.P, o.CT)
		if err != nil {
			fail(err)
			return
		}
		got, err := decodeWire(s, o.Branch, ct)
		if err != nil {
			fail(err)
			return
		}
		if o.Branch.Spec.Algorithm == "chebyshev6" {
			approxRef := approximationReference(d)
			ea := newErrors(s.TargetsLowHigh)
			if er := ea.addDecoded(got, approxRef, o.Branch.Map); er != nil {
				fail(er)
				return
			}
			_, tail := power16Chebyshev()
			report.ApproximationChecks[o.Branch.Spec.ID] = map[string]any{"uniform_approximation_error_upper_exact": tail.RatString(), "observed_error_to_exact_P6": ea.rows()[0], "note": "Observed error to P6 includes input propagation and HE error; these cannot be experimentally separated by subtracting error magnitudes. Final success is checked against exact x^16."}
		}
		if err = errors.addDecoded(got, ref, o.Branch.Map); err != nil {
			fail(err)
			return
		}
		complexErrors, err := checkBranchComplex(s, o.Branch, got, ref)
		if err != nil {
			fail(err)
			return
		}
		report.ComplexErrors = append(report.ComplexErrors, complexErrors...)
		report.Outputs = append(report.Outputs, OutputReport{o.Branch.Spec.ID, o.Branch.Spec.Group, cr})
		if err = writeBytesNew(filepath.Join(outDir, c.ID+"_"+o.Branch.Spec.ID+"_output.bin"), wire); err != nil {
			fail(err)
			return
		}
	}
	report.Errors = errors.rows()
	if report.Native != nil {
		report.Native.Errors = report.Errors
	}
	report.ObservedPass = report.Errors[0].Pass && report.Errors[1].Pass
	if p.Branches[0].Spec.Paired() {
		passed := true
		var counts [2]Count
		for _, row := range report.ComplexErrors {
			g := 0
			if row.Group == "high" {
				g = 1
			} else if row.Group != "low" {
				fail(fmt.Errorf("missing paired precision group"))
				return
			}
			counts[g] += row.Checked
			passed = passed && row.Pass
		}
		if counts[0] != Count(s.GroupSize/2) || counts[1] != Count(s.GroupSize/2) {
			fail(fmt.Errorf("wrong number of paired complex results"))
			return
		}
		report.ComplexGroupTargetsPass = &passed
	}
	if errors.counts[0] != uint64(s.GroupSize) || errors.counts[1] != uint64(s.GroupSize) {
		fail(fmt.Errorf("wrong number of checked business results"))
		return
	}
	for _, tr := range traces {
		ct := tr.CT
		if tr.NeedsRestore {
			ct, e = restore(tr.Branch, ct, nil, true)
			if e != nil {
				fail(e)
				return
			}
		}
		_, wireCT, cr, err := wireCipher(tr.Branch.P, ct)
		if err != nil {
			fail(err)
			return
		}
		got, err := decodeWire(s, tr.Branch, wireCT)
		if err != nil {
			fail(err)
			return
		}
		ea := newErrors(s.TargetsLowHigh)
		want := d.Reference("pow256", tr.Exponent)
		if tr.Name == "native_input" && s.Task == "mean16" {
			want = d.Reference("centered_input", 1)
		}
		if err = ea.addDecoded(got, want, tr.Branch.Map); err != nil {
			fail(err)
			return
		}
		stop := "entry_conversion"
		if tr.Name != "merged_or_converted_input" {
			k := 0
			for n := tr.Exponent; n > 1; n /= 2 {
				k++
			}
			stop = fmt.Sprintf("square_%d", k)
		}
		var cumulative Count
		for _, phase := range report.Online.Phases {
			if tr.Name == "native_input" {
				break
			}
			if phase.Branch != tr.Branch.Spec.ID {
				continue
			}
			cumulative += phase.DurationNS
			if phase.Name == stop {
				break
			}
		}
		complexErrors, err := checkBranchComplex(s, tr.Branch, got, want)
		if err != nil {
			fail(err)
			return
		}
		var legacyComplex *ComplexErrorReport
		var grouped []ComplexErrorReport
		if tr.Branch.Spec.Paired() {
			grouped = complexErrors
		} else if len(complexErrors) == 1 {
			legacyComplex = &complexErrors[0]
		}
		report.Checkpoints = append(report.Checkpoints, Checkpoint{Name: tr.Name, Branch: tr.Branch.Spec.ID, Ciphertext: cr, Errors: ea.rows(), ComplexError: legacyComplex, ComplexGroupErrors: grouped, Note: "diagnostic only; restored copy; excluded from online timing and operation counts; final thresholds are not imposed on intermediate results", StoredScale: scaleRat(tr.CT.Scale).RatString(), StoredQComponents: tr.CT.Level() + 1, CumulativeBranchPhaseNS: cumulative})
	}
	b := BusinessReport{RequestedLowHigh: [2]int{s.GroupSize, s.GroupSize}, InputCiphertexts: len(report.InputReports), OutputCiphertexts: len(report.Outputs), AllRequestedValid: report.ObservedPass, Scope: "prescribed business outputs, not algebraic rank; serial branches with fixed GOMAXPROCS; single observation, no stable-speed claim"}
	for _, i := range report.InputReports {
		b.InputBytes += i.SerializedBytes
		b.InputPhysicalSlots += i.PhysicalSlots
	}
	for _, o := range report.Outputs {
		b.OutputBytes += o.Ciphertext.SerializedBytes
		b.OutputPayloadBytes += o.Ciphertext.PayloadBytes
		b.OutputPhysicalSlots += o.Ciphertext.PhysicalSlots
	}
	b.OutputBytesPerRequestedResult = new(big.Rat).SetFrac(new(big.Int).SetUint64(uint64(b.OutputBytes)), big.NewInt(int64(2*s.GroupSize))).RatString()
	if report.ObservedPass && report.Online.TotalNS > 0 {
		numerator := new(big.Int).Mul(big.NewInt(int64(2*s.GroupSize)), big.NewInt(1000000000))
		exactRate := new(big.Rat).SetFrac(numerator, new(big.Int).SetUint64(uint64(report.Online.TotalNS))).RatString()
		b.ValidResultsPerSecondExact = &exactRate
		v := float64(2*s.GroupSize) * 1e9 / float64(report.Online.TotalNS)
		b.ValidResultsPerSecond = &v
		for i := 0; i < 2; i++ {
			v := float64(s.GroupSize) * 1e9 / float64(report.Online.TotalNS)
			b.ValidLowHighPerSecond[i] = &v
		}
	}
	report.Business = b
	report.Status = "completed"
	if !report.ObservedPass {
		report.Status = "observed_precision_failure"
	} else if report.ComplexGroupTargetsPass != nil && !*report.ComplexGroupTargetsPass {
		report.Status = "observed_paired_complex_precision_failure"
	}
	return
}

func Run(s *Suite, configBytes []byte, outDir, selection string) error {
	return runSuite(s, configBytes, outDir, selection, nil)
}

func runSuite(s *Suite, configBytes []byte, outDir, selection string, qualification map[string]any) error {
	if e := backendCheck(); e != nil {
		return e
	}
	if e := s.Validate(); e != nil {
		return e
	}
	chosen := map[string]bool{}
	if selection != "" {
		for _, id := range strings.Split(selection, ",") {
			chosen[id] = true
		}
	}
	var cases []CaseSpec
	for _, c := range s.Cases {
		if selection == "" || chosen[c.ID] {
			cases = append(cases, c)
			delete(chosen, c.ID)
		}
	}
	if len(chosen) != 0 || len(cases) == 0 {
		return fmt.Errorf("unknown/empty case selection")
	}
	if e := os.MkdirAll(filepath.Dir(outDir), 0755); e != nil {
		return e
	}
	if e := os.Mkdir(outDir, 0755); e != nil {
		return fmt.Errorf("output directory must be new: %w", e)
	}
	if e := writeBytesNew(filepath.Join(outDir, "configuration.json"), configBytes); e != nil {
		return e
	}
	old := runtime.GOMAXPROCS(s.GOMAXPROCS)
	defer runtime.GOMAXPROCS(old)
	started := time.Now().UTC().Format(time.RFC3339Nano)
	info, _ := debug.ReadBuildInfo()
	meta := map[string]any{"schema": "ckks-precision-results-v1", "suite": s.ID, "backend": Backend, "started_utc": started, "go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "cpu_count": runtime.NumCPU(), "gomaxprocs": s.GOMAXPROCS, "build": info, "config_sha256": hashBytes(configBytes), "runs_per_case": 1, "warmup": false, "manual_gc": false, "secret_exported": false, "security_target_bits": s.SecurityTarget, "security_assessment": s.SecurityAssessment, "formal_error_certificate": "not established by this program; observed decoded errors are not certified bounds", "numerical_decode_bits": s.Precision, "scope": "online excludes key generation, client input construction, public constant/evaluator preparation, serialization, diagnostics, disk IO; these are separately reported", "trace_policy": "final-only by default; diagnostic traces are opt-in and must match across compared paths", "selected_cases": cases}
	meta["study_status"] = "CORRECTNESS_DIAGNOSTIC_ONLY"
	if qualification != nil {
		meta["study_status"] = "FORMAL_TEN_REPEAT"
		meta["security_qualification"] = qualification
	}
	if e := writeNew(filepath.Join(outDir, "started.json"), meta); e != nil {
		return e
	}
	d := NewDataset(s)
	meta["dataset_sha256"] = d.SHA256
	meta["dataset"] = "SHA256(public seed||business index), first 120 bits; x=255/256+integer/2^128; high/low parity; no client pre-evaluation"
	meta["comparison_contract"] = s.ComparisonContract
	meta["retain_diagnostic_traces"] = s.RetainDiagnosticTraces
	meta["trace_policy"] = "final-only by default; diagnostic traces are opt-in and must match across compared paths"
	// Generate every reference before measured server regions. Exact arithmetic
	// is not included in online time or used to replace homomorphic operations.
	d.Reference(s.Task, 256)
	if s.Task == "pow256" {
		for _, e := range []int{1, 2, 4, 8, 16, 32, 64, 128} {
			d.Reference("pow256", e)
		}
	}
	var src *existingSource
	if s.Entry == "existing" {
		t := time.Now()
		var e error
		src, e = prepareSource(s, d)
		if e != nil {
			_ = writeNew(filepath.Join(outDir, "source_failure.json"), map[string]string{"error": e.Error()})
			return e
		}
		meta["common_source_setup_wall_ns"] = Count(time.Since(t).Nanoseconds())
		meta["common_source_client_value_encode_encrypt_ns"] = src.ClientNS
		meta["common_source_key_generation_ns"] = src.Family.KeygenNS
		meta["common_source_key_serialization_accounting_ns"] = src.Family.AccountingNS
		meta["common_source_parameters"] = paramReport(src.Family.P)
		meta["common_source_inputs"] = src.Reports
		for i, w := range src.Wire {
			if e = writeBytesNew(filepath.Join(outDir, fmt.Sprintf("common_input_%d.bin", i)), w); e != nil {
				return e
			}
		}
	}
	var reports []CaseReport
	allPass := true
	for _, c := range cases {
		fmt.Printf("%s/%s: one evaluation, no warmup\n", s.ID, c.ID)
		r := runCase(s, c, d, src, outDir)
		reports = append(reports, r)
		if !r.ObservedPass || r.Status != "completed" {
			allPass = false
		}
		if e := writeNew(filepath.Join(outDir, c.ID+".json"), r); e != nil {
			return e
		}
		fmt.Printf("  status=%s all_targets=%v online_ns=%d output_bytes=%d\n", r.Status, r.ObservedPass, r.Online.TotalNS, r.Business.OutputBytes)
	}
	meta["finished_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	meta["all_observed_targets_pass"] = allPass
	meta["cases"] = reports
	if e := writeNew(filepath.Join(outDir, "results.json"), meta); e != nil {
		return e
	}
	if !allPass {
		return fmt.Errorf("one or more paths failed; every attempted path is retained in results")
	}
	return nil
}
