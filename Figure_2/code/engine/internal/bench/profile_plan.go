package bench

import (
	"fmt"
	"math/big"
	"sort"
)

type ProfileLayer struct {
	Layer               int    `json:"layer"`
	QBefore             int    `json:"Q_before"`
	QAfter              int    `json:"Q_after"`
	ScaleBefore         string `json:"scale_before_exact"`
	ScaleAfter          string `json:"scale_after_exact"`
	Divisor             string `json:"divisor_exact"`
	Rho                 string `json:"metadata_rho_exact"`
	DecompositionBlocks int    `json:"decomposition_blocks"`
}
type ProfileBranchPlan struct {
	ID                string            `json:"id"`
	Parameters        ParamReport       `json:"parameters"`
	Layers            []ProfileLayer    `json:"layers"`
	Batches           int               `json:"batches"`
	EffectiveMessages int               `json:"effective_messages"`
	OutputQCount      int               `json:"output_Q_count"`
	OutputScale       string            `json:"output_scale_exact"`
	InputPayload      Count             `json:"input_coefficient_payload_bytes"`
	OutputPayload     Count             `json:"output_coefficient_payload_bytes"`
	RelinPayload      Count             `json:"unshared_relin_coefficient_payload_bytes"`
	PublicKeyPayload  Count             `json:"unshared_public_key_coefficient_payload_bytes"`
	Maps              []ProfileBatchMap `json:"batch_maps"`
}
type ProfilePlan struct {
	Schema                 string                 `json:"schema"`
	ID                     string                 `json:"id"`
	ConfigSHA256           string                 `json:"config_sha256"`
	Backend                string                 `json:"backend"`
	HEExecutions           int                    `json:"HE_executions"`
	SecurityEstimated      bool                   `json:"security_estimated"`
	Certified              bool                   `json:"certified"`
	Branches               []ProfileBranchPlan    `json:"branches"`
	Contract               map[string]any         `json:"contract"`
	ContractSHA256         string                 `json:"contract_sha256"`
	KeyFamilies            []ProfileKeyFamilyPlan `json:"key_family_plan"`
	SharedRelinPayload     Count                  `json:"shared_relin_coefficient_payload_bytes"`
	SharedPublicKeyPayload Count                  `json:"shared_public_key_coefficient_payload_bytes"`
	MemoryGuard            Count                  `json:"preflight_memory_guard_bytes"`
	SampleCounts           map[int]map[string]int `json:"sampled_family_counts_upper"`
}

type ProfileKeyFamilyPlan struct {
	Provider         string   `json:"provider_branch"`
	Branches         []string `json:"branches"`
	RelinPayload     Count    `json:"relin_coefficient_payload_bytes"`
	PublicKeyPayload Count    `json:"public_key_coefficient_payload_bytes"`
}

func compatibleProfileParameters(a, b ParamReport) bool {
	if a.N != b.N || len(a.P) != len(b.P) || len(a.Q) < len(b.Q) {
		return false
	}
	for i, x := range b.Q {
		if a.Q[i] != x {
			return false
		}
	}
	for i, x := range b.P {
		if a.P[i] != x {
			return false
		}
	}
	return true
}

func planProfileKeyFamilies(out *ProfilePlan) {
	order := make([]int, len(out.Branches))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return len(out.Branches[order[i]].Parameters.Q) > len(out.Branches[order[j]].Parameters.Q)
	})
	providers := []int{}
	out.SampleCounts = map[int]map[string]int{}
	var data Count
	for _, index := range order {
		b := out.Branches[index]
		p := b.Parameters
		data += b.InputPayload + b.OutputPayload
		if out.SampleCounts[p.N] == nil {
			out.SampleCounts[p.N] = map[string]int{}
		}
		s := out.SampleCounts[p.N]
		s["secret_polynomials_upper"] += b.Batches
		s["error_polynomials_upper"] += 4 * b.Batches
		family := -1
		for f, provider := range providers {
			if compatibleProfileParameters(out.Branches[provider].Parameters, p) {
				family = f
				break
			}
		}
		if family < 0 {
			family = len(providers)
			providers = append(providers, index)
			out.KeyFamilies = append(out.KeyFamilies, ProfileKeyFamilyPlan{Provider: b.ID, RelinPayload: b.RelinPayload, PublicKeyPayload: b.PublicKeyPayload})
			out.SharedRelinPayload += b.RelinPayload
			out.SharedPublicKeyPayload += b.PublicKeyPayload
			s["secret_polynomials_upper"]++
			s["error_polynomials_upper"] += 4 + 4*((len(p.Q)+len(p.P)-1)/len(p.P))
		}
		out.KeyFamilies[family].Branches = append(out.KeyFamilies[family].Branches, b.ID)
	}
	out.MemoryGuard = 4 * (data + out.SharedRelinPayload + out.SharedPublicKeyPayload)
}

func PlanProfile(c *ProfileConfig, raw []byte) (*ProfilePlan, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	out := &ProfilePlan{Schema: "ckks-profile-public-plan-v1", ID: c.ID, ConfigSHA256: hashBytes(raw), Backend: Backend + "+ScalePrecision1024+VariableExponentIO"}
	var all []ProfileBatchMap
	for _, b := range c.Branches {
		p, e := b.Parameters.Build()
		if e != nil {
			return nil, e
		}
		if p.N() < 32 {
			return nil, fmt.Errorf("public plan requires N>=32")
		}
		if b.Multiplier != nil && p.N()%len(b.Multiplier.Coefficients) != 0 {
			return nil, fmt.Errorf("subring not contained")
		}
		maps, e := makeProfileMaps(c, b, p.MaxSlots())
		if e != nil {
			return nil, e
		}
		all = append(all, maps...)
		row := ProfileBranchPlan{ID: b.ID, Parameters: paramReport(p), Maps: maps, Batches: len(maps)}
		for _, m := range maps {
			row.EffectiveMessages += len(m.Values)
		}
		q, pcount := len(p.Q()), len(p.P())
		row.InputPayload = Count(16 * p.N() * q * len(maps))
		row.RelinPayload = Count(16 * p.N() * ((q + pcount - 1) / pcount) * (q + pcount))
		row.PublicKeyPayload = Count(16 * p.N() * (q + pcount))
		level := p.MaxLevel()
		meta := scale(pow2(b.ScaleBits))
		for k, count := range b.RescaleCounts {
			if count > level {
				return nil, fmt.Errorf("branch %s: rescale would remove every Q prime", b.ID)
			}
			before := scaleRat(meta)
			divisor := new(big.Int).SetInt64(1)
			meta = meta.Mul(meta)
			for j := 0; j < count; j++ {
				prime := p.Q()[level-j]
				divisor.Mul(divisor, new(big.Int).SetUint64(prime))
				meta = meta.Div(scale(new(big.Rat).SetInt(new(big.Int).SetUint64(prime))))
			}
			after := scaleRat(meta)
			rho := div(mul(before, before), mul(new(big.Rat).SetInt(divisor), after))
			row.Layers = append(row.Layers, ProfileLayer{k + 1, level + 1, level + 1 - count, before.RatString(), after.RatString(), divisor.String(), rho.RatString(), (level + 1 + pcount - 1) / pcount})
			level -= count
		}
		level -= b.OutputDropPrimes
		if level < 0 {
			return nil, fmt.Errorf("output drop removes every prime")
		}
		row.OutputQCount = level + 1
		row.OutputScale = scaleRat(meta).RatString()
		row.OutputPayload = Count(16 * p.N() * (level + 1) * len(maps))
		out.Branches = append(out.Branches, row)
	}
	if e := validateProfileMaps(c, all); e != nil {
		return nil, e
	}
	planProfileKeyFamilies(out)
	var e error
	out.Contract, out.ContractSHA256, e = profileContract(c, out)
	if e != nil {
		return nil, e
	}
	return out, nil
}
