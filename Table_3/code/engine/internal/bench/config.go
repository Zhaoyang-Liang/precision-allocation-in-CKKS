package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const Backend = "github.com/tuneinsight/lattigo/v6@v6.2.0"

type ParamSpec struct {
	LogN             int      `json:"log_n"`
	Q                []string `json:"q,omitempty"`
	P                []string `json:"p,omitempty"`
	LogQ             []int    `json:"log_q,omitempty"`
	LogP             []int    `json:"log_p,omitempty"`
	DefaultScaleBits int      `json:"default_scale_bits"`
}

func (s ParamSpec) Build() (ckks.Parameters, error) {
	if s.LogN < 4 || s.LogN > 20 {
		return ckks.Parameters{}, fmt.Errorf("invalid log_n")
	}
	if (len(s.Q) == 0) == (len(s.LogQ) == 0) || (len(s.P) == 0) == (len(s.LogP) == 0) {
		return ckks.Parameters{}, fmt.Errorf("specify Q or LogQ, P or LogP, exclusively")
	}
	parse := func(ss []string) ([]uint64, error) {
		if len(ss) == 0 {
			// Lattigo distinguishes nil (unspecified) from a non-nil empty list.
			return nil, nil
		}
		v := make([]uint64, len(ss))
		for i, s := range ss {
			n, e := strconv.ParseUint(s, 10, 64)
			if e != nil {
				return nil, e
			}
			v[i] = n
		}
		return v, nil
	}
	q, e := parse(s.Q)
	if e != nil {
		return ckks.Parameters{}, e
	}
	p, e := parse(s.P)
	if e != nil {
		return ckks.Parameters{}, e
	}
	params, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: s.LogN, Q: q, P: p, LogQ: s.LogQ, LogP: s.LogP, LogDefaultScale: s.DefaultScaleBits, RingType: ring.Standard, Xs: ring.Ternary{H: 128}, Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}})
	if e != nil {
		return ckks.Parameters{}, e
	}
	// Mixed LogQ + explicit P can collide: backend GenModuli does not know
	// the explicit P when choosing Q. All CRT moduli must be pairwise coprime.
	seen := map[uint64]bool{}
	for _, prime := range append(append([]uint64(nil), params.Q()...), params.P()...) {
		if seen[prime] {
			return ckks.Parameters{}, fmt.Errorf("duplicate RNS prime %d across Q/P; generate both bases jointly or choose disjoint explicit primes", prime)
		}
		seen[prime] = true
	}
	return params, nil
}

type BranchSpec struct {
	ID         string    `json:"id"`
	Group      string    `json:"group"`  // all, low, high
	Layout     string    `json:"layout"` // interleaved, compact, or native ordinary mean real_imag
	Parameters ParamSpec `json:"parameters"`
	ScaleBits  int       `json:"scale_bits"`
	Algorithm  string    `json:"algorithm,omitempty"` // square_chain (default), chebyshev6
	// Number of top Q primes to remove after each square, in execution order.
	RescaleCounts       []int `json:"rescale_counts,omitempty"`
	OutputDropPrimes    int   `json:"output_drop_primes,omitempty"` // modulus only, no division
	OutputRescaleCount  int   `json:"output_rescale_count,omitempty"`
	RestoreRescaleCount int   `json:"restore_rescale_count,omitempty"`
}

type CaseSpec struct {
	ID                    string       `json:"id"`
	Kind                  string       `json:"kind"` // ordinary_joint, ordinary_split, diagonal, unit, integer_nonunit
	UnitPower             int          `json:"unit_power,omitempty"`
	DyadicBits            int          `json:"dyadic_bits,omitempty"`
	MultiplierScaleBits   int          `json:"multiplier_scale_bits,omitempty"`
	MatchQuantizedWeights bool         `json:"match_quantized_weights,omitempty"`
	Branches              []BranchSpec `json:"branches"`
	ParameterStatus       string       `json:"parameter_status"`
	CertificateNote       string       `json:"certificate_note"`
}

func (b BranchSpec) Paired() bool {
	return b.Layout == "paired_interleaved" || b.Layout == "paired_compact"
}

type SourceSpec struct {
	Parameters       ParamSpec `json:"parameters"`
	ScaleBitsLowHigh [2]int    `json:"scale_bits_low_high"`
}
type Suite struct {
	Schema                 string      `json:"schema"`
	ID                     string      `json:"id"`
	Task                   string      `json:"task"`  // mean16 or pow256
	Entry                  string      `json:"entry"` // native or existing
	GroupSize              int         `json:"group_size"`
	TargetsLowHigh         [2]int      `json:"target_bits_low_high"`
	Seed                   string      `json:"plaintext_seed"`
	Precision              uint        `json:"encoder_decode_bits"`
	GOMAXPROCS             int         `json:"gomaxprocs"`
	SecurityTarget         int         `json:"security_target_bits"`
	SecurityAssessment     string      `json:"security_assessment"`
	Source                 *SourceSpec `json:"source,omitempty"`
	Cases                  []CaseSpec  `json:"cases"`
	ComparisonContract     string      `json:"comparison_contract,omitempty"` // fixed_circuit or function_tolerance
	RetainDiagnosticTraces bool        `json:"retain_diagnostic_traces"`
}

func Load(path string) (*Suite, []byte, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	s := new(Suite)
	if e = d.Decode(s); e != nil {
		return nil, nil, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return nil, nil, fmt.Errorf("trailing JSON data")
	}
	if e = s.Validate(); e != nil {
		return nil, nil, e
	}
	return s, b, nil
}

var safeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func (s *Suite) Validate() error {
	if s.Schema != "ckks-precision-suite-v1" || !safeID.MatchString(s.ID) {
		return fmt.Errorf("invalid schema or suite id")
	}
	if s.Task != "mean16" && s.Task != "pow256" {
		return fmt.Errorf("unknown task")
	}
	if s.ComparisonContract != "" && s.ComparisonContract != "fixed_circuit" && s.ComparisonContract != "function_tolerance" {
		return fmt.Errorf("unknown comparison_contract")
	}
	if s.Entry != "native" && s.Entry != "existing" {
		return fmt.Errorf("unknown entry")
	}
	if s.GroupSize < 16 || s.GroupSize&(s.GroupSize-1) != 0 {
		return fmt.Errorf("group_size must be a power of two >=16")
	}
	if s.Precision < 256 || s.Precision > 8192 || s.GOMAXPROCS < 1 {
		return fmt.Errorf("encoder precision or thread budget invalid")
	}
	if _, e := strconv.ParseUint(s.Seed, 10, 64); e != nil {
		return fmt.Errorf("plaintext_seed: %w", e)
	}
	for _, b := range s.TargetsLowHigh {
		if b < 1 || b > int(s.Precision)/2 {
			return fmt.Errorf("target bits incompatible with diagnostic precision")
		}
	}
	if len(s.Cases) == 0 {
		return fmt.Errorf("empty suite")
	}
	if s.SecurityTarget <= 0 || s.SecurityAssessment == "" {
		return fmt.Errorf("explicit security status required")
	}
	var source ckks.Parameters
	if s.Entry == "existing" {
		if s.Task != "mean16" || s.Source == nil {
			return fmt.Errorf("existing entry is implemented for mean16 only")
		}
		var e error
		source, e = s.Source.Parameters.Build()
		if e != nil {
			return e
		}
		if source.MaxSlots() != 2*s.GroupSize {
			return fmt.Errorf("existing-source layout requires exactly 2*group_size slots")
		}
		for _, bits := range s.Source.ScaleBitsLowHigh {
			if bits <= 0 || bits > 128 {
				return fmt.Errorf("source scales must lie in 1..128 bits")
			}
		}
	} else if s.Source != nil {
		return fmt.Errorf("native suite cannot contain source")
	}
	ids := map[string]bool{}
	for _, c := range s.Cases {
		if !safeID.MatchString(c.ID) || ids[c.ID] {
			return fmt.Errorf("invalid or duplicate case id %q", c.ID)
		}
		ids[c.ID] = true
		if c.Kind != "ordinary_joint" && c.Kind != "ordinary_split" && c.Kind != "diagonal" && c.Kind != "unit" && c.Kind != "integer_nonunit" {
			return fmt.Errorf("unknown kind %q", c.Kind)
		}
		if c.ParameterStatus == "" || c.CertificateNote == "" {
			return fmt.Errorf("%s needs explicit parameter/certificate status", c.ID)
		}
		if (c.Kind == "unit" || c.Kind == "integer_nonunit") && (c.UnitPower <= 0 || c.UnitPower%2 != 0 || c.UnitPower > 128) {
			return fmt.Errorf("unit requires positive even power <=128")
		}
		if c.Kind == "diagonal" && (c.DyadicBits <= 0 || c.MultiplierScaleBits <= 0) {
			return fmt.Errorf("diagonal needs dyadic_bits and multiplier_scale_bits")
		}
		if s.Entry == "existing" && (c.Kind == "diagonal" || c.Kind == "integer_nonunit") {
			return fmt.Errorf("nonunit existing-source conversion is outside the three appendix paths")
		}
		n := 1
		if c.Kind == "ordinary_split" {
			n = 2
		}
		if len(c.Branches) != n {
			return fmt.Errorf("%s: wrong branch count", c.ID)
		}
		groups := map[string]bool{}
		branchIDs := map[string]bool{}
		for _, b := range c.Branches {
			if b.Algorithm != "" && b.Algorithm != "square_chain" && b.Algorithm != "chebyshev6" {
				return fmt.Errorf("unknown branch algorithm")
			}
			if b.Algorithm == "chebyshev6" && (s.Task != "pow256" || s.Entry != "native" || s.ComparisonContract != "function_tolerance" || c.Kind != "ordinary_split" || b.Group != "low") {
				return fmt.Errorf("chebyshev6 is the native ordinary low-group function-tolerance path")
			}
			if branchIDs[b.ID] {
				return fmt.Errorf("duplicate branch id %q", b.ID)
			}
			branchIDs[b.ID] = true
			if !safeID.MatchString(b.ID) || b.ScaleBits <= 0 || b.ScaleBits > 128 || b.OutputDropPrimes < 0 || b.OutputRescaleCount < 0 || b.RestoreRescaleCount < 0 {
				return fmt.Errorf("invalid branch")
			}
			if groups[b.Group] {
				return fmt.Errorf("duplicate output group")
			}
			groups[b.Group] = true
			if n == 1 && b.Group != "all" || n == 2 && (b.Group != "low" && b.Group != "high") {
				return fmt.Errorf("bad business-group mapping")
			}
			p, e := b.Parameters.Build()
			if e != nil {
				return fmt.Errorf("%s/%s: %w", c.ID, b.ID, e)
			}
			if b.Layout != "interleaved" && b.Layout != "compact" && b.Layout != "real_imag" && !b.Paired() {
				return fmt.Errorf("invalid layout")
			}
			if b.Layout == "real_imag" && (s.Entry != "native" || s.Task != "mean16" || c.Kind != "ordinary_joint") {
				return fmt.Errorf("real_imag is only implemented for native ordinary joint mean16")
			}
			if b.Paired() {
				if s.Entry != "native" || s.Task != "mean16" {
					return fmt.Errorf("paired layouts require native mean16")
				}
				if b.Layout == "paired_interleaved" && c.Kind != "unit" && c.Kind != "ordinary_joint" {
					return fmt.Errorf("paired joint requires unit or ordinary_joint")
				}
				if b.Layout == "paired_compact" && c.Kind != "ordinary_split" {
					return fmt.Errorf("paired compact requires ordinary_split")
				}
			}
			if n == 1 && b.Layout != "interleaved" && b.Layout != "real_imag" && b.Layout != "paired_interleaved" {
				return fmt.Errorf("joint layouts must be interleaved or real_imag")
			}
			active := s.GroupSize
			if b.Layout == "interleaved" {
				active *= 2
			}
			if b.Layout == "paired_compact" {
				active /= 2
			}
			if active > p.MaxSlots() {
				return fmt.Errorf("business values exceed capacity")
			}
			if b.Algorithm == "chebyshev6" && active != p.MaxSlots() {
				return fmt.Errorf("chebyshev6 currently requires full compact input: zero padding maps outside its approximation interval")
			}
			if s.Task == "mean16" && active != p.MaxSlots() {
				return fmt.Errorf("mean16 requires a full cyclic domain, not silently rotating into zero padding")
			}
			removed := b.OutputDropPrimes + b.RestoreRescaleCount + b.OutputRescaleCount
			if b.Algorithm == "chebyshev6" {
				if len(b.RescaleCounts) != 0 {
					return fmt.Errorf("polynomial evaluator owns its rescale schedule")
				}
				if p.MaxLevel() < 3*p.LevelsConsumedPerRescaling() {
					return fmt.Errorf("degree-six polynomial needs three backend levels")
				}
			} else if s.Task == "pow256" {
				if len(b.RescaleCounts) != 8 {
					return fmt.Errorf("pow256 needs eight explicit rescale counts")
				}
				for _, v := range b.RescaleCounts {
					if v < 0 {
						return fmt.Errorf("negative rescale count")
					}
					removed += v
				}
			} else if len(b.RescaleCounts) != 0 {
				return fmt.Errorf("mean16 has no square rescale schedule")
			}
			if removed > p.MaxLevel() {
				return fmt.Errorf("%s/%s: rescale/drop exhausts Q", c.ID, b.ID)
			}
			if c.Kind != "diagonal" && b.RestoreRescaleCount != 0 {
				return fmt.Errorf("only approximate restoration has a rescale")
			}
			if s.Entry == "existing" {
				if b.Layout != "interleaved" || p.N() != source.N() || p.MaxLevel() > source.MaxLevel() {
					return fmt.Errorf("existing inputs cannot change ring/layout or raise level")
				}
				for i, q := range p.Q() {
					if q != source.Q()[i] {
						return fmt.Errorf("existing branch Q must be source prefix")
					}
				}
				if fmt.Sprint(p.P()) != fmt.Sprint(source.P()) {
					return fmt.Errorf("existing P mismatch")
				}
			}
		}
	}
	return nil
}
