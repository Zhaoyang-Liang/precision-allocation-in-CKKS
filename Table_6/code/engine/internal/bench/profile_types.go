package bench

// New experiment schema: arbitrary precision groups and real business counts.
// The old two-group runners remain unchanged and are not rerun.
import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
)

type EmbeddingInterval struct {
	Lower string `json:"lower"`
	Upper string `json:"upper"`
}
type ProfileMultiplier struct {
	Period             int                 `json:"period"`
	Coefficients       []string            `json:"coefficients"`
	Inverse            []string            `json:"inverse_coefficients"`
	Embeddings         []EmbeddingInterval `json:"embedding_intervals"`
	ConstructionSHA256 string              `json:"construction_sha256"`
}
type ProfileBranch struct {
	ID     string `json:"id"`
	Groups []int  `json:"groups"`
	// Empty pattern packs all assigned business contiguously (ordinary only).
	// Otherwise slot j has the group pattern[j%len(pattern)], or dummy -1.
	Pattern          []int              `json:"slot_pattern,omitempty"`
	Parameters       ParamSpec          `json:"parameters"`
	ScaleBits        int                `json:"scale_bits"`
	RescaleCounts    []int              `json:"rescale_counts"`
	OutputDropPrimes int                `json:"output_drop_primes"`
	Multiplier       *ProfileMultiplier `json:"multiplier,omitempty"`
	SecurityFile     string             `json:"security_file,omitempty"`
	SecuritySHA256   string             `json:"security_sha256,omitempty"`
	EncodingFile     string             `json:"encoding_certificate_file,omitempty"`
}
type ProfileConfig struct {
	Schema              string          `json:"schema"`
	ID                  string          `json:"id"`
	QuestionID          string          `json:"question_id"`
	Repeat              int             `json:"repeat"`
	Seed                string          `json:"plaintext_seed"`
	Precision           uint            `json:"encoder_decode_bits"`
	Depth               int             `json:"depth"`
	Targets             []int           `json:"target_bits"`
	GroupSizes          []int           `json:"group_sizes"`
	Branches            []ProfileBranch `json:"branches"`
	CertificationStatus string          `json:"certification_status"`
	CertificateFile     string          `json:"certificate_file,omitempty"`
}

func LoadProfile(path string) (*ProfileConfig, []byte, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var c ProfileConfig
	if e = dec.Decode(&c); e != nil {
		return nil, nil, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		return nil, nil, fmt.Errorf("trailing JSON")
	}
	if e = c.Validate(); e != nil {
		return nil, nil, e
	}
	return &c, raw, nil
}

func (c *ProfileConfig) Validate() error {
	if c.Schema != "ckks-profile-experiment-v1" || !safeID.MatchString(c.ID) || !safeID.MatchString(c.QuestionID) {
		return fmt.Errorf("invalid schema or IDs")
	}
	if c.Repeat < 1 || c.Repeat > 2 || (c.Precision != 512 && c.Precision != 768 && c.Precision != 1024) || c.Depth < 1 || c.Depth > 4 {
		return fmt.Errorf("repeat, arithmetic precision or circuit depth outside design")
	}
	if _, e := strconv.ParseUint(c.Seed, 10, 64); e != nil {
		return fmt.Errorf("invalid seed: %w", e)
	}
	if len(c.Targets) == 0 || len(c.Targets) != len(c.GroupSizes) {
		return fmt.Errorf("group dimensions")
	}
	for g, b := range c.Targets {
		if b < 1 || b > 224 || c.GroupSizes[g] < 1 {
			return fmt.Errorf("invalid group")
		}
	}
	if len(c.Branches) == 0 {
		return fmt.Errorf("missing branches")
	}
	coverage := make([]int, len(c.Targets))
	ids := map[string]bool{}
	for _, b := range c.Branches {
		if !safeID.MatchString(b.ID) || ids[b.ID] {
			return fmt.Errorf("invalid or duplicate branch ID")
		}
		ids[b.ID] = true
		if len(b.Groups) == 0 {
			return fmt.Errorf("empty branch")
		}
		assigned := map[int]bool{}
		for _, g := range b.Groups {
			if g < 0 || g >= len(coverage) || assigned[g] {
				return fmt.Errorf("invalid branch group")
			}
			assigned[g] = true
			coverage[g]++
		}
		if len(b.RescaleCounts) != c.Depth || b.ScaleBits < 1 || b.ScaleBits > 512 || b.OutputDropPrimes < 0 {
			return fmt.Errorf("invalid scale schedule")
		}
		for _, cnt := range b.RescaleCounts {
			if cnt < 0 {
				return fmt.Errorf("negative rescale count")
			}
		}
		seen := map[int]bool{}
		for _, g := range b.Pattern {
			if g == -1 {
				continue
			}
			if !assigned[g] {
				return fmt.Errorf("pattern references unassigned group")
			}
			seen[g] = true
		}
		if len(b.Pattern) > 0 {
			for g := range assigned {
				if !seen[g] {
					return fmt.Errorf("group absent from slot pattern")
				}
			}
		}
		if b.Multiplier != nil {
			m := b.Multiplier
			r := m.Period
			if r < 2 || r&(r-1) != 0 || r > 16 || len(b.Pattern) != r || len(m.Coefficients) != 2*r || len(m.Inverse) != 2*r || len(m.Embeddings) != r {
				return fmt.Errorf("invalid multiplier or periodic layout")
			}
			p, e := parseIntegerCoefficients(m.Coefficients)
			if e != nil {
				return e
			}
			inv, e := parseIntegerCoefficients(m.Inverse)
			if e != nil {
				return e
			}
			// Complex conjugation sends z^i to -z^(2r-i), for 0<i<2r.
			// Both the encoder and the real-weight error ledger require p real.
			for i := 1; i < len(p); i++ {
				if new(big.Int).Add(p[i], p[len(p)-i]).Sign() != 0 {
					return fmt.Errorf("multiplier must have real canonical embeddings")
				}
			}
			prod := negacyclicBig(p, inv)
			for i, v := range prod {
				want := int64(0)
				if i == 0 {
					want = 1
				}
				if v.Cmp(big.NewInt(want)) != 0 {
					return fmt.Errorf("multiplier inverse identity failed")
				}
			}
			for _, row := range m.Embeddings {
				lo, e := rat(row.Lower)
				if e != nil {
					return e
				}
				hi, e := rat(row.Upper)
				if e != nil {
					return e
				}
				if lo.Cmp(hi) > 0 || lo.Sign()*hi.Sign() <= 0 {
					return fmt.Errorf("unresolved signed embedding interval")
				}
			}
		}
	}
	for _, v := range coverage {
		if v != 1 {
			return fmt.Errorf("each effective group must be assigned exactly once")
		}
	}
	if c.CertificationStatus != "conditional_certified" && c.CertificationStatus != "numerical_only" {
		return fmt.Errorf("explicit certification status required")
	}
	return nil
}

func parseIntegerCoefficients(ss []string) ([]*big.Int, error) {
	out := make([]*big.Int, len(ss))
	for i, s := range ss {
		var ok bool
		out[i], ok = new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("invalid integer coefficient")
		}
	}
	return out, nil
}
func negacyclicBig(a, b []*big.Int) []*big.Int {
	d := len(a)
	out := make([]*big.Int, d)
	for i := range out {
		out[i] = new(big.Int)
	}
	for i, x := range a {
		for j, y := range b {
			v := new(big.Int).Mul(x, y)
			if i+j >= d {
				v.Neg(v)
			}
			out[(i+j)%d].Add(out[(i+j)%d], v)
		}
	}
	return out
}

type ProfileAssignment struct {
	Slot  int `json:"slot"`
	Group int `json:"group"`
	Index int `json:"business_index_in_group"`
}
type ProfileBatchMap struct {
	Branch        string              `json:"branch"`
	Batch         int                 `json:"batch"`
	PhysicalSlots int                 `json:"physical_slots"`
	Values        []ProfileAssignment `json:"values"`
}

func makeProfileMaps(c *ProfileConfig, b ProfileBranch, slots int) ([]ProfileBatchMap, error) {
	if slots < 1 {
		return nil, fmt.Errorf("invalid physical slots")
	}
	next := make([]int, len(c.GroupSizes))
	remain := 0
	for _, g := range b.Groups {
		remain += c.GroupSizes[g]
	}
	var maps []ProfileBatchMap
	compactGroup := 0
	for remain > 0 {
		m := ProfileBatchMap{Branch: b.ID, Batch: len(maps), PhysicalSlots: slots}
		for slot := 0; slot < slots; slot++ {
			var g int
			if len(b.Pattern) > 0 {
				g = b.Pattern[slot%len(b.Pattern)]
				if g < 0 || next[g] >= c.GroupSizes[g] {
					continue
				}
			} else {
				for compactGroup < len(b.Groups) && next[b.Groups[compactGroup]] >= c.GroupSizes[b.Groups[compactGroup]] {
					compactGroup++
				}
				if compactGroup == len(b.Groups) {
					break
				}
				g = b.Groups[compactGroup]
			}
			m.Values = append(m.Values, ProfileAssignment{slot, g, next[g]})
			next[g]++
			remain--
		}
		if len(m.Values) == 0 {
			return nil, fmt.Errorf("layout cannot make progress")
		}
		maps = append(maps, m)
	}
	return maps, nil
}

func validateProfileMaps(c *ProfileConfig, maps []ProfileBatchMap) error {
	seen := map[[2]int]bool{}
	batchSeen := map[string]bool{}
	for _, m := range maps {
		key := fmt.Sprintf("%s:%d", m.Branch, m.Batch)
		if batchSeen[key] {
			return fmt.Errorf("duplicate batch")
		}
		batchSeen[key] = true
		slots := map[int]bool{}
		for _, a := range m.Values {
			if a.Group < 0 || a.Group >= len(c.GroupSizes) || a.Index < 0 || a.Index >= c.GroupSizes[a.Group] || a.Slot < 0 || a.Slot >= m.PhysicalSlots {
				return fmt.Errorf("invalid business map")
			}
			k := [2]int{a.Group, a.Index}
			if seen[k] || slots[a.Slot] {
				return fmt.Errorf("duplicate business or slot")
			}
			seen[k] = true
			slots[a.Slot] = true
		}
	}
	total := 0
	for _, n := range c.GroupSizes {
		total += n
	}
	if len(seen) != total {
		return fmt.Errorf("missing business outputs")
	}
	return nil
}

func profileInput(seed uint64, group, index int) *big.Rat {
	// Exact endpoints and midpoint precede independent dyadic interior points.
	switch index {
	case 0:
		return big.NewRat(3, 4)
	case 1:
		return big.NewRat(7, 8)
	case 2:
		return big.NewRat(13, 16)
	}
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint64(buf, seed)
	binary.LittleEndian.PutUint64(buf[8:], uint64(group))
	binary.LittleEndian.PutUint64(buf[16:], uint64(index))
	h := sha256.Sum256(buf)
	v := new(big.Int).SetBytes(h[:])
	return add(big.NewRat(3, 4), new(big.Rat).SetFrac(v, new(big.Int).Lsh(big.NewInt(1), 259)))
}

func profileReference(x *big.Rat, depth int) *big.Rat {
	e := big.NewInt(int64(1 << depth))
	return new(big.Rat).SetFrac(new(big.Int).Exp(x.Num(), e, nil), new(big.Int).Exp(x.Denom(), e, nil))
}
