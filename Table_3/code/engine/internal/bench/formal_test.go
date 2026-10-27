package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFormalEvidenceRejectsChangedInputsAndFailedEstimates(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"frozen":"configuration"}`)
	attacks := map[string]any{}
	for _, a := range []string{"primal_usvp", "primal_bdd", "primal_hybrid_mitm", "primal_hybrid_bdd", "dual_hybrid_matzov"} {
		attacks[a] = map[string]any{"log2_rop":130.0,"finite":true}
	}
	security := map[string]any{"case":"candidate", "finished":true, "secret_model":"ND.SparseBinomial(eta=1,hw=128,n=N)", "cost_model":"RC.MATZOV", "attacks":attacks}
	write := func(name string, value any) []byte {
		t.Helper()
		b, e := json.Marshal(value); if e != nil { t.Fatal(e) }
		if e = os.WriteFile(filepath.Join(dir,name),b,0600); e != nil { t.Fatal(e) }
		return b
	}
	publish := func() {
		sb := write("security.json",security)
		write("manifest.json",map[string]any{"status":"FROZEN_FOR_TEN_REPEATS","repetitions":10,
			"tasks":[]any{map[string]any{"config_sha256":hashBytes(raw),"case":"example","security_case":"candidate"}},
			"security_evidence":map[string]any{"candidate":map[string]any{"path":"security.json","sha256":hashBytes(sb)}}})
	}
	publish()
	t.Setenv("TUPLE8_FORMAL_MANIFEST",filepath.Join(dir,"manifest.json"))
	if _,e:=formalEvidence(raw,"example"); e!=nil { t.Fatal(e) }
	if _,e:=formalEvidence(append(raw,' '),"example"); e==nil { t.Fatal("changed config accepted") }
	if _,e:=formalEvidence(raw,"other"); e==nil { t.Fatal("wrong case accepted") }
	attacks["primal_hybrid_mitm"] = map[string]any{"log2_rop":127.9,"finite":true}
	publish()
	if _,e:=formalEvidence(raw,"example"); e==nil { t.Fatal("below-threshold estimate accepted") }
	delete(attacks,"primal_hybrid_mitm")
	publish()
	if _,e:=formalEvidence(raw,"example"); e==nil { t.Fatal("missing estimate accepted") }
	if e:=os.WriteFile(filepath.Join(dir,"security.json"),[]byte("{}"),0600);e!=nil {t.Fatal(e)}
	if _,e:=formalEvidence(raw,"example"); e==nil { t.Fatal("changed evidence accepted") }
}
