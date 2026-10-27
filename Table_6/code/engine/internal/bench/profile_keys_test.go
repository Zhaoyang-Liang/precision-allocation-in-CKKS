package bench

import "testing"

func TestProfilePrefixKeyFamilyPlan(t *testing.T) {
	a := ProfileBranchPlan{ID: "high", Parameters: ParamReport{N: 8192, Q: []string{"11", "13", "17", "19"}, P: []string{"23", "29"}}, Batches: 1, InputPayload: 20, OutputPayload: 8, RelinPayload: 100, PublicKeyPayload: 60}
	b := ProfileBranchPlan{ID: "low", Parameters: ParamReport{N: 8192, Q: []string{"11", "13"}, P: []string{"23", "29"}}, Batches: 3, InputPayload: 30, OutputPayload: 8, RelinPayload: 40, PublicKeyPayload: 40}
	plan := &ProfilePlan{Branches: []ProfileBranchPlan{b, a}}
	planProfileKeyFamilies(plan)
	if len(plan.KeyFamilies) != 1 || plan.KeyFamilies[0].Provider != "high" || plan.SharedRelinPayload != 100 || plan.SharedPublicKeyPayload != 60 {
		t.Fatal("prefix family was double counted")
	}
	if plan.MemoryGuard != 4*(20+8+30+8+100+60) {
		t.Fatal("shared memory guard")
	}
	if plan.SampleCounts[8192]["secret_polynomials_upper"] != 5 || plan.SampleCounts[8192]["error_polynomials_upper"] != 28 {
		t.Fatal("sampled event count")
	}
	b.Parameters.P = []string{"31", "37"}
	plan = &ProfilePlan{Branches: []ProfileBranchPlan{a, b}}
	planProfileKeyFamilies(plan)
	if len(plan.KeyFamilies) != 2 || plan.SharedRelinPayload != 140 {
		t.Fatal("different P bases were incorrectly shared")
	}
}

func TestProfilePrefixMatchRequiresEveryPrime(t *testing.T) {
	a := ParamReport{N: 8192, Q: []string{"11", "13", "17"}, P: []string{"19"}}
	b := ParamReport{N: 8192, Q: []string{"11", "17"}, P: []string{"19"}}
	if compatibleProfileParameters(a, b) {
		t.Fatal("nonprefix deletion accepted")
	}
	b.Q = []string{"11", "13"}
	b.N = 16384
	if compatibleProfileParameters(a, b) {
		t.Fatal("ring dimensions ignored")
	}
}
