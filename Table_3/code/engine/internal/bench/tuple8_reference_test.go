package bench

import (
 "math/big"
 "testing"
)

// This checks the actual dataset and oracle used by the new port, not HE.
func TestTuple8ReferenceContract(t *testing.T) {
 t.Setenv("TUPLE8_FORMAL_MANIFEST", "")
 s := &TupleSuite{ID:"test",GroupSize:8192,Targets:[2]int{32,80},Seed:"2026101701",Precision:1024,GOMAXPROCS:1}
 ds := NewDataset(tupleDataSuite(s))
 if len(ds.Values)!=16384 {t.Fatal("wrong slot count")}
 lo,hi:=big.NewRat(255,256),big.NewRat(1,1)
 for _,x:=range ds.Values {if x.Cmp(lo)<0 || x.Cmp(hi)>=0 {t.Fatal("input outside declared interval")}}
 tiny:= &Dataset{Values:[]*big.Rat{big.NewRat(255,256),big.NewRat(1,1)},References:map[string][]*big.Rat{}}
 got:=tiny.Reference("pow256",256)
 want:=new(big.Rat).SetFrac(new(big.Int).Exp(big.NewInt(255),big.NewInt(256),nil),new(big.Int).Lsh(big.NewInt(1),2048))
 if got[0].Cmp(want)!=0 || got[1].Cmp(hi)!=0 {t.Fatal("eight-square oracle mismatch")}
 if got[0].Cmp(big.NewRat(1,4))<=0 {t.Fatal("low-group zero-output degeneracy")}
 if RunTuple(s,nil,t.TempDir(),"")==nil {t.Fatal("HE must stay disabled before security validation")}
}
