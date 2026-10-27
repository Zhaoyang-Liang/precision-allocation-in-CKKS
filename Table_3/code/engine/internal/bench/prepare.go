package bench

import (
	"fmt"
	"sort"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type Preparation struct {
	TotalWallNS             Count `json:"total_wall_ns"`
	ParameterConstructionNS Count `json:"parameter_construction_ns"`
	KeyGenerationNS         Count `json:"key_generation_ns"`
	KeyAccountingNS         Count `json:"key_serialization_hash_accounting_ns"`
	ClientPreparationNS     Count `json:"encoder_initialization_ns"`
	ClientEncodeEncryptNS   Count `json:"client_transform_encode_encrypt_ns"`
	InputWireNS             Count `json:"input_wire_roundtrip_and_hash_ns"`
	ServerPreparationNS     Count `json:"server_evaluator_constants_buffers_ns"`
	OtherNS                 Count `json:"unattributed_preparation_ns"`
}
type preparedCase struct {
	Branches     []*branchRuntime
	Families     []*keyFamily
	Preparation  Preparation
	InputReports []CipherReport
}

func prepareCase(s *Suite, c CaseSpec, d *Dataset, src *existingSource) (out *preparedCase, err error) {
	start := time.Now()
	out = &preparedCase{}
	defer func() {
		p := &out.Preparation
		p.TotalWallNS = Count(time.Since(start).Nanoseconds())
		sum := p.ParameterConstructionNS + p.KeyGenerationNS + p.KeyAccountingNS + p.ClientPreparationNS + p.ClientEncodeEncryptNS + p.InputWireNS + p.ServerPreparationNS
		if sum > p.TotalWallNS {
			if err == nil {
				err = fmt.Errorf("preparation phase accounting overlaps")
			}
		} else {
			p.OtherNS = p.TotalWallNS - sum
		}
	}()
	for _, spec := range c.Branches {
		t := time.Now()
		p, e := spec.Parameters.Build()
		out.Preparation.ParameterConstructionNS += Count(time.Since(t).Nanoseconds())
		if e != nil {
			return out, e
		}
		out.Branches = append(out.Branches, &branchRuntime{Spec: spec, P: p, Map: mapping(s, spec)})
	}
	ms := []SlotMapping{}
	for _, b := range out.Branches {
		ms = append(ms, b.Map)
	}
	if e := validateMappings(s, ms); e != nil {
		return out, e
	}
	if src != nil {
		base := src.Family
		f := &keyFamily{P: base.P, SK: base.SK, PK: base.PK, KG: base.KG, Rows: append([]KeyReport(nil), base.Rows...)}
		out.Families = []*keyFamily{f}
		for _, b := range out.Branches {
			b.Family = f
		}
		out.InputReports = append(out.InputReports, src.Reports[:]...)
	} else {
		// Form prefix-compatible key families BEFORE key generation. Two split
		// ciphertexts do not imply two public keys or two rotation-key collections.
		order := append([]*branchRuntime(nil), out.Branches...)
		sort.SliceStable(order, func(i, j int) bool { return order[i].P.MaxLevel() > order[j].P.MaxLevel() })
		for _, b := range order {
			for _, f := range out.Families {
				if compatiblePrefix(f.P, b.P) {
					b.Family = f
					break
				}
			}
			if b.Family == nil {
				f, e := newKeyFamily(b.P)
				if e != nil {
					return out, e
				}
				b.Family = f
				out.Families = append(out.Families, f)
				out.Preparation.KeyGenerationNS += f.KeygenNS
				out.Preparation.KeyAccountingNS += f.AccountingNS
			}
		}
	}
	for _, f := range out.Families {
		levels := map[int]int{}
		rl := -1
		conjugateLevel := -1
		for _, b := range out.Branches {
			if b.Family != f {
				continue
			}
			if s.Task == "mean16" {
				if b.Spec.Paired() && b.P.MaxLevel() > conjugateLevel {
					conjugateLevel = b.P.MaxLevel()
				}
				for _, rot := range rotations(b.Spec) {
					l, ok := levels[rot]
					if !ok || b.P.MaxLevel() > l {
						levels[rot] = b.P.MaxLevel()
					}
				}
			} else if b.P.MaxLevel() > rl {
				rl = b.P.MaxLevel()
			}
		}
		g, a, e := f.prepareKeys(levels, rl, conjugateLevel)
		out.Preparation.KeyGenerationNS += g
		out.Preparation.KeyAccountingNS += a
		if e != nil {
			return out, e
		}
	}
	for _, b := range out.Branches {
		t := time.Now()
		b.Encoder = ckks.NewEncoder(b.P, s.Precision)
		out.Preparation.ClientPreparationNS += Count(time.Since(t).Nanoseconds())
		t = time.Now()
		b.Evaluator = ckks.NewEvaluator(b.P, b.Family.Keys)
		b.Representation, err = NewRepresentation(b.P, c, s.Precision)
		if err != nil {
			return out, err
		}
		if b.Representation.Forward != nil {
			b.Constants = append(b.Constants, b.Representation.Forward.Report)
		}
		if s.Task == "mean16" {
			if err = b.Representation.CheckRotations(b.P, rotations(b.Spec)); err != nil {
				return out, err
			}
			if b.Spec.Paired() {
				if err = b.Representation.CheckConjugation(b.P); err != nil {
					return out, err
				}
				b.Imaginary = imaginaryMultiplier(b.P)
				b.Constants = append(b.Constants, b.Imaginary.Report)
			}
		}
		b.Scratch = b.P.RingQ().NewPoly()
		if b.Spec.Algorithm == "chebyshev6" {
			prepareApproximation(b)
		}
		if src != nil {
			if err = prepareEntry(s, b, src); err != nil {
				return out, err
			}
		}
		out.Preparation.ServerPreparationNS += Count(time.Since(t).Nanoseconds())
		if src == nil {
			t = time.Now()
			b.Input, err = encodeInput(s, d, b)
			out.Preparation.ClientEncodeEncryptNS += Count(time.Since(t).Nanoseconds())
			if err != nil {
				return out, err
			}
			t = time.Now()
			b.InputWire, b.Input, b.InputReport, err = wireCipher(b.P, b.Input)
			out.Preparation.InputWireNS += Count(time.Since(t).Nanoseconds())
			if err != nil {
				return out, err
			}
			out.InputReports = append(out.InputReports, b.InputReport)
		}
	}
	return out, nil
}

// Assert that online code never modified a shared source or a native input.
func verifyUnchanged(p *preparedCase, src *existingSource) error {
	if src != nil {
		for i, c := range src.Inputs {
			w, e := c.MarshalBinary()
			if e != nil {
				return e
			}
			if hashBytes(w) != src.Reports[i].SHA256 {
				return fmt.Errorf("shared source %d was mutated", i)
			}
		}
	} else {
		for _, b := range p.Branches {
			w, e := b.Input.MarshalBinary()
			if e != nil {
				return e
			}
			if hashBytes(w) != b.InputReport.SHA256 {
				return fmt.Errorf("native input %s was mutated", b.Spec.ID)
			}
		}
	}
	return nil
}

// References to private keys stay in memory only. There is intentionally no
// method which serializes a SecretKey, and no import of someone else's key.
var _ *rlwe.SecretKey
