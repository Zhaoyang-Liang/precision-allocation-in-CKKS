package bench

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type profileRuntime struct {
	spec            ProfileBranch
	p               ckks.Parameters
	family          *keyFamily
	encoder         *ckks.Encoder
	evaluator       *ckks.Evaluator
	forward         *PublicMultiplier
	weights         []*big.Float
	scratch         ring.Poly
	maps            []ProfileBatchMap
	inputs, outputs []*rlwe.Ciphertext
	inputReports    []CipherReport
}
type profileObservedLayer struct {
	branch                        string
	batch, layer, qBefore, qAfter int
	scale                         rlwe.Scale
}

func writeProfileJSON(path string, value any) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
func saveDecodedProfile(path string, got []*bignum.Complex, m ProfileBatchMap) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	zip := gzip.NewWriter(f)
	enc := json.NewEncoder(zip)
	lookup := map[int]ProfileAssignment{}
	for _, a := range m.Values {
		lookup[a.Slot] = a
	}
	for slot, z := range got {
		if z == nil || z[0].IsInf() || z[1].IsInf() {
			zip.Close()
			f.Close()
			return fmt.Errorf("nonfinite diagnostic")
		}
		re, _ := z[0].Rat(nil)
		im, _ := z[1].Rat(nil)
		a, ok := lookup[slot]
		g, index := -1, -1
		if ok {
			g, index = a.Group, a.Index
		}
		if e = enc.Encode(map[string]any{"slot": slot, "group": g, "business_index": index, "effective": ok, "real_exact": re.RatString(), "imag_exact": im.RatString()}); e != nil {
			zip.Close()
			f.Close()
			return e
		}
	}
	if e = zip.Close(); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}

func RunProfile(configPath, outDir string) (err error) {
	runtime.GOMAXPROCS(1)
	c, raw, e := LoadProfile(configPath)
	if e != nil {
		return e
	}
	plan, e := PlanProfile(c, raw)
	if e != nil {
		return e
	}
	dir := filepath.Dir(configPath)
	security, certificates, e := profileEvidence(c, plan, dir)
	if e != nil {
		return e
	}
	if e = os.Mkdir(outDir, 0755); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(outDir, "config.json"), raw, 0644); e != nil {
		return e
	}
	if e = writeProfileJSON(filepath.Join(outDir, "plan.json"), plan); e != nil {
		return e
	}
	initErrorTrace(outDir, c)
	started := time.Now()
	result := map[string]any{"schema": "ckks-profile-result-v1", "id": c.ID, "question_id": c.QuestionID, "repeat": c.Repeat,
		"plaintext_seed": c.Seed, "config_sha256": hashBytes(raw), "contract_sha256": plan.ContractSHA256,
		"backend": plan.Backend, "scale_metadata_bits": rlwe.ScalePrecision, "encoder_decode_bits": c.Precision,
		"certification_status": c.CertificationStatus, "security_files": security, "certificate_files": certificates,
		"status": "incomplete", "HE_executions": 0, "generated_key_families": 0, "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "go_version": runtime.Version(), "gomaxprocs": 1,
		"timing_scope": "online includes all batches, correction and ordinary restoration; excludes preparation, serialization and verification"}
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("profile run panic: %v", x)
		}
		result["total_process_work_ns"] = Count(time.Since(started).Nanoseconds())
		var usage syscall.Rusage
		if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) == nil {
			rss := usage.Maxrss
			if runtime.GOOS != "darwin" {
				rss *= 1024
			}
			result["process_peak_rss_bytes"] = Count(rss)
		}
		if err != nil {
			result["status"] = "failed"
			result["error"] = err.Error()
		}
		if e := writeProfileJSON(filepath.Join(outDir, "result.json"), result); e != nil && err == nil {
			err = e
		}
	}()
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	exeBytes, e := os.ReadFile(executable)
	if e != nil {
		return e
	}
	result["binary_sha256"] = hashBytes(exeBytes)
	exeBytes = nil
	t := time.Now()
	seed, _ := strconv.ParseUint(c.Seed, 10, 64)
	inputs := make([][]*big.Rat, len(c.Targets))
	truth := make([][]*big.Rat, len(c.Targets))
	effective := 0
	for g, size := range c.GroupSizes {
		effective += size
		inputs[g] = make([]*big.Rat, size)
		truth[g] = make([]*big.Rat, size)
		for i := 0; i < size; i++ {
			inputs[g][i] = profileInput(seed, g, i)
			truth[g][i] = profileReference(inputs[g][i], c.Depth)
		}
	}
	result["reference_generation_ns"] = Count(time.Since(t).Nanoseconds())
	result["effective_results"] = effective
	runtimes := make([]*profileRuntime, len(c.Branches))
	var families []*keyFamily
	preparation := map[string]Count{}
	allMaps := []ProfileBatchMap{}
	for i, b := range c.Branches {
		t = time.Now()
		p, e := b.Parameters.Build()
		if e != nil {
			return e
		}
		preparation["parameter_objects_ns"] += Count(time.Since(t).Nanoseconds())
		maps, e := makeProfileMaps(c, b, p.MaxSlots())
		if e != nil {
			return e
		}
		allMaps = append(allMaps, maps...)
		runtimes[i] = &profileRuntime{spec: b, p: p, maps: maps}
	}
	if e = validateProfileMaps(c, allMaps); e != nil {
		return e
	}
	if e = writeProfileJSON(filepath.Join(outDir, "business_mapping.json"), allMaps); e != nil {
		return e
	}
	order := append([]*profileRuntime(nil), runtimes...)
	sort.SliceStable(order, func(i, j int) bool { return order[i].p.MaxLevel() > order[j].p.MaxLevel() })
	for _, b := range order {
		for _, f := range families {
			if compatiblePrefix(f.P, b.p) {
				b.family = f
				break
			}
		}
		if b.family == nil {
			f, e := newKeyFamily(b.p)
			if e != nil {
				return e
			}
			b.family = f
			families = append(families, f)
			result["generated_key_families"] = len(families)
			preparation["key_generation_ns"] += f.KeygenNS
			preparation["key_accounting_ns"] += f.AccountingNS
		}
	}
	keys := []KeyReport{}
	sampled := map[int]map[string]int{}
	for _, f := range families {
		relin := -1
		for _, b := range runtimes {
			if b.family == f && b.p.MaxLevel() > relin {
				relin = b.p.MaxLevel()
			}
		}
		generation, accounting, e := f.prepareKeys(nil, relin, -1)
		if e != nil {
			return e
		}
		preparation["key_generation_ns"] += generation
		preparation["key_accounting_ns"] += accounting
		keys = append(keys, f.Rows...)
		if sampled[f.P.N()] == nil {
			sampled[f.P.N()] = map[string]int{}
		}
		sampled[f.P.N()]["secret_polynomials_upper"]++
		// Conservative count: public-key errors plus <=4 noise polynomials per
		// gadget column. Actual no-bit implementation uses fewer.
		sampled[f.P.N()]["error_polynomials_upper"] += 4
		for _, row := range f.Rows {
			if row.Kind != "public" {
				for _, digits := range row.DigitCounts {
					sampled[f.P.N()]["error_polynomials_upper"] += 4 * digits
				}
			}
		}
	}
	keyStats, e := keyTotals(keys)
	if e != nil {
		return e
	}
	result["keys"] = keys
	result["key_totals"] = keyStats
	var evalPayload, pkPayload Count
	for _, k := range keys {
		if k.Kind == "public" {
			pkPayload += k.CoefficientPayloadBytes
		} else {
			evalPayload += k.CoefficientPayloadBytes
		}
	}
	result["evaluation_key_coefficient_payload_bytes"] = evalPayload
	result["public_key_coefficient_payload_bytes"] = pkPayload
	if evalPayload != plan.SharedRelinPayload || pkPayload != plan.SharedPublicKeyPayload || len(families) != len(plan.KeyFamilies) {
		return fmt.Errorf("actual shared key objects differ from public resource plan")
	}
	inputRows := []map[string]any{}
	for _, b := range runtimes {
		sampled[b.p.N()]["secret_polynomials_upper"] += len(b.maps)
		sampled[b.p.N()]["error_polynomials_upper"] += 4 * len(b.maps)
		if sampled[b.p.N()]["secret_polynomials_upper"] > 256 || sampled[b.p.N()]["error_polynomials_upper"] > 4096 {
			return fmt.Errorf("sampled-family certificate count exceeded")
		}
		t = time.Now()
		b.encoder = ckks.NewEncoder(b.p, c.Precision)
		b.evaluator = ckks.NewEvaluator(b.p, b.family.Keys)
		b.scratch = b.p.RingQ().NewPoly()
		b.forward, b.weights, e = profileMultiplier(b.p, b.spec.Multiplier, c.Precision)
		if e != nil {
			return e
		}
		preparation["encoder_evaluator_constants_ns"] += Count(time.Since(t).Nanoseconds())
		encryptor := rlwe.NewEncryptor(b.p, b.family.PK)
		for _, mapping := range b.maps {
			t = time.Now()
			pt, e := encodeProfilePlain(c, b.spec, b.p, b.encoder, mapping, b.weights, inputs)
			if e != nil {
				return e
			}
			preparation["input_transform_encode_ns"] += Count(time.Since(t).Nanoseconds())
			t = time.Now()
			ct, e := encryptor.EncryptNew(pt)
			if e != nil {
				return e
			}
			traceFresh(b, pt, ct, mapping, inputs)
			result["HE_executions"] = 1
			preparation["encrypt_ns"] += Count(time.Since(t).Nanoseconds())
			t = time.Now()
			_, ct, rep, e := wireCipher(b.p, ct)
			if e != nil {
				return e
			}
			if rep.RelativeScaleChange != "0" {
				return fmt.Errorf("input wire scale changed; outside new certificate")
			}
			preparation["input_wire_check_ns"] += Count(time.Since(t).Nanoseconds())
			b.inputs = append(b.inputs, ct)
			b.inputReports = append(b.inputReports, rep)
			inputRows = append(inputRows, map[string]any{"branch": b.spec.ID, "batch": mapping.Batch, "ciphertext": rep})
		}
	}
	result["input_ciphertexts"] = inputRows
	result["sampled_family_counts_upper"] = sampled
	for n, expected := range plan.SampleCounts {
		for key, value := range expected {
			if sampled[n][key] != value {
				return fmt.Errorf("sampled polynomial counts differ from public plan")
			}
		}
	}
	result["preparation"] = preparation
	timing, ops, layers, e := evaluateProfile(c, runtimes)
	result["online"] = timing
	result["operations"] = ops
	result["operation_totals"] = operationTotals(ops)
	if e != nil {
		return e
	}
	observed := []map[string]any{}
	index := 0
	for bi, b := range runtimes {
		for batch := range b.maps {
			for layer, expected := range plan.Branches[bi].Layers {
				if index >= len(layers) {
					return fmt.Errorf("missing observed layer")
				}
				got := layers[index]
				index++
				actualScale := scaleRat(got.scale).RatString()
				if got.branch != b.spec.ID || got.batch != batch || got.layer != layer+1 || got.qBefore != expected.QBefore || got.qAfter != expected.QAfter || actualScale != expected.ScaleAfter {
					return fmt.Errorf("actual layer differs from public plan")
				}
				observed = append(observed, map[string]any{"branch": got.branch, "batch": got.batch, "layer": got.layer, "Q_before": got.qBefore, "Q_after": got.qAfter, "scale_exact": actualScale})
			}
		}
	}
	if index != len(layers) {
		return fmt.Errorf("unexpected observed layers")
	}
	result["actual_layers"] = observed
	acc := newProfileErrors(c)
	outputs := []map[string]any{}
	var outputPayload, outputSerialized Count
	verification := map[string]Count{}
	for bi, b := range runtimes {
		for batch, ct := range b.outputs {
			if ct.Level()+1 != plan.Branches[bi].OutputQCount || scaleRat(ct.Scale).RatString() != plan.Branches[bi].OutputScale {
				return fmt.Errorf("actual output differs from public plan")
			}
			t = time.Now()
			wire, read, rep, e := wireCipher(b.p, ct)
			if e != nil {
				return e
			}
			if rep.RelativeScaleChange != "0" {
				return fmt.Errorf("output wire scale changed; outside new certificate")
			}
			prefix := fmt.Sprintf("%s_batch%d", b.spec.ID, batch)
			file := prefix + ".ct.bin"
			if e = os.WriteFile(filepath.Join(outDir, file), wire, 0644); e != nil {
				return e
			}
			verification["output_serialize_write_ns"] += Count(time.Since(t).Nanoseconds())
			outputPayload += rep.PayloadBytes
			outputSerialized += rep.SerializedBytes
			t = time.Now()
			pt := rlwe.NewDecryptor(b.p, b.family.SK).DecryptNew(read)
			got := make([]*bignum.Complex, b.p.MaxSlots())
			if e = b.encoder.Decode(pt, got); e != nil {
				return e
			}
			verification["decrypt_decode_ns"] += Count(time.Since(t).Nanoseconds())
			t = time.Now()
			if e = acc.add(got, b.maps[batch], truth); e != nil {
				return e
			}
			if e = saveDecodedProfile(filepath.Join(outDir, prefix+".decoded.jsonl.gz"), got, b.maps[batch]); e != nil {
				return e
			}
			verification["accuracy_and_diagnostic_write_ns"] += Count(time.Since(t).Nanoseconds())
			outputs = append(outputs, map[string]any{"branch": b.spec.ID, "batch": batch, "file": file, "ciphertext": rep})
			// All input ciphertexts must remain unchanged through evaluation.
			bytes, e := b.inputs[batch].MarshalBinary()
			if e != nil {
				return e
			}
			if hashBytes(bytes) != b.inputReports[batch].SHA256 {
				return fmt.Errorf("evaluation mutated an input")
			}
		}
	}
	for _, f := range families {
		pk, e := publicKeyReport(f.PK)
		if e != nil {
			return e
		}
		if pk.SHA256 != f.Rows[0].SHA256 {
			return fmt.Errorf("public key mutated")
		}
		rk, e := f.Keys.GetRelinearizationKey()
		if e != nil {
			return e
		}
		row, e := gadgetReport("relinearization", rk, &rk.GadgetCiphertext, 0)
		if e != nil {
			return e
		}
		found := false
		for _, old := range f.Rows {
			if old.Kind == "relinearization" {
				found = row.SHA256 == old.SHA256
			}
		}
		if !found {
			return fmt.Errorf("evaluation key mutated")
		}
	}
	accuracy, e := acc.finish()
	if e != nil {
		return e
	}
	allPass := true
	for _, a := range accuracy {
		allPass = allPass && a.Pass
	}
	result["accuracy"] = accuracy
	result["all_effective_results_pass"] = allPass
	result["dummy_or_padding_slots_checked"] = acc.dummyChecked
	result["dummy_max_complex_magnitude_squared"] = acc.dummyMaximum.RatString()
	result["outputs"] = outputs
	result["verification"] = verification
	result["output_coefficient_payload_bytes"] = outputPayload
	result["output_serialized_bytes"] = outputSerialized
	result["output_coefficient_bytes_per_effective_result"] = float64(outputPayload) / float64(effective)
	result["effective_results_per_second"] = float64(effective) * 1e9 / float64(timing.TotalNS)
	result["status"] = "completed"
	if !allPass {
		result["status"] = "accuracy_failed"
	}
	return nil
}

func evaluateProfile(c *ProfileConfig, branches []*profileRuntime) (timing OnlineTiming, ops []Operation, layers []profileObservedLayer, err error) {
	r := &recorder{}
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("online panic: %v", x)
		}
		var e error
		timing, e = finishTiming(start, before, r)
		ops = r.ops
		if err == nil {
			err = e
		}
	}()
	for _, b := range branches {
		for batch, input := range b.inputs {
			current := input
			label := fmt.Sprintf("%s_batch%d", b.spec.ID, batch)
			for layer, count := range b.spec.RescaleCounts {
				qBefore := current.Level() + 1
				traceBeforeSquare(b, current, batch, layer)
				if b.forward == nil {
					err = r.phase(label, "square_and_relinearize", func() error { var e error; current, e = b.evaluator.MulRelinNew(current, current); return e })
					if err != nil {
						return
					}
					r.ops = append(r.ops, Operation{Kind: "ciphertext_square", Branch: label, InputLevel: qBefore - 1, InputDegree: 1}, Operation{Kind: "relinearize", Branch: label, InputLevel: qBefore - 1, InputDegree: 2, KeySwitches: 1})
				} else {
					err = r.phase(label, "square", func() error { var e error; current, e = b.evaluator.MulNew(current, current); return e })
					if err != nil {
						return
					}
					r.ops = append(r.ops, Operation{Kind: "ciphertext_square", Branch: label, InputLevel: qBefore - 1, InputDegree: 1})
					err = r.phase(label, "public_gate_correction", func() error {
						var e error
						current, e = rawMultiply(b.p, current, b.forward, nil, r, label, "exact_unit_gate_correction")
						return e
					})
					if err != nil {
						return
					}
					traceBeforeRelin(b, current)
					err = r.phase(label, "relinearize", func() error { var e error; current, e = b.evaluator.RelinearizeNew(current); return e })
					if err != nil {
						return
					}
					r.ops = append(r.ops, Operation{Kind: "relinearize", Branch: label, InputLevel: qBefore - 1, InputDegree: 2, KeySwitches: 1})
				}
				traceAfterRelin(b, current, batch, layer)
				if count > 0 {
					err = r.phase(label, "rescale", func() error { return rescaleInPlace(b.p, current, count, b.scratch, r, label) })
					if err != nil {
						return
					}
				}
				traceAfterRescale(b, current, batch, layer)
				meta := rlwe.Scale{Value: *new(big.Float).Copy(&current.Scale.Value)}
				layers = append(layers, profileObservedLayer{b.spec.ID, batch, layer + 1, qBefore, current.Level() + 1, meta})
			}
			if b.forward != nil {
				err = r.phase(label, "restore_ordinary_output", func() error {
					var e error
					current, e = rawMultiply(b.p, current, b.forward, nil, r, label, "exact_unit_restore")
					return e
				})
				if err != nil {
					return
				}
			}
			if b.spec.OutputDropPrimes > 0 {
				err = r.phase(label, "drop_unused_output_primes", func() error {
					if current == input {
						current = current.CopyNew()
					}
					current.Resize(1, current.Level()-b.spec.OutputDropPrimes)
					return nil
				})
				if err != nil {
					return
				}
				r.ops = append(r.ops, Operation{Kind: "output_modulus_drop", Branch: label, InputLevel: current.Level() + b.spec.OutputDropPrimes, InputDegree: 1, RemovedPrimes: b.spec.OutputDropPrimes})
			}
			traceFinal(b, current, batch)
			b.outputs = append(b.outputs, current)
		}
	}
	return
}
