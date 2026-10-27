package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func publicTestProfile() *ProfileConfig {
	return &ProfileConfig{Schema: "ckks-profile-experiment-v1", ID: "public_contract", QuestionID: "public_contract", Repeat: 1, Seed: "2026100201", Precision: 1024, Depth: 1, Targets: []int{96}, GroupSizes: []int{8}, CertificationStatus: "numerical_only",
		Branches: []ProfileBranch{{ID: "direct", Groups: []int{0}, Parameters: ParamSpec{LogN: 6, LogQ: []int{60, 60, 60, 60}, LogP: []int{60}, DefaultScaleBits: 60}, ScaleBits: 160, RescaleCounts: []int{1}}}}
}

func TestProfileContractSeedIndependentNotParameterIndependent(t *testing.T) {
	c := publicTestProfile()
	a, e := PlanProfile(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	c.Repeat = 2
	c.Seed = "2026100202"
	b, e := PlanProfile(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	if a.ContractSHA256 != b.ContractSHA256 {
		t.Fatal("two repeats need same mathematical contract")
	}
	c.Branches[0].ScaleBits++
	changed, e := PlanProfile(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	if a.ContractSHA256 == changed.ContractSHA256 {
		t.Fatal("parameter change not bound")
	}
}

func TestProfileNoSecurityEvidenceNoKeysOrOutput(t *testing.T) {
	c := publicTestProfile()
	data, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	temp := t.TempDir()
	config := filepath.Join(temp, "config.json")
	out := filepath.Join(temp, "must_not_exist")
	if e = os.WriteFile(config, data, 0600); e != nil {
		t.Fatal(e)
	}
	if RunProfile(config, out) == nil {
		t.Fatal("formal runner accepted missing security")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("output created before security gate")
	}
}
