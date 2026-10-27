package main

import (
	"runtime"
	"testing"
)

func TestPairedPrunedEncryptedFullsplit(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	c := config{LogN: 9, Logn: 8, R: 8, Trials: 2, TargetBits: 1, ScaleBits: 22, EMBits: 20, K: 17, MainBase: 9, EntryBase: 1, BoundaryBase: 5, Q0: 14155777, Qout: 5767169, TopP: 786433, MainP: 65537, UnitFile: "../../units-weak.json", Seed: 9281, Workers: 2, VerifySerial: true, Messages: 1, PruneOnly: true, Powers: "1", FusedPower: -1, Mod1Family: "continuous", Degree: 31, DoubleAngle: 3, CheckSquare: true}
	var r result
	if err := run(c, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Trials) != 2 {
		t.Fatal("missing trials")
	}
	for _, tr := range r.Trials {
		if tr.Error != "" || !tr.SerialCiphertextsEqual || tr.RefreshedBranches != 1 || tr.SerialOnlineSeconds <= 0 || tr.ParallelOnlineSeconds <= 0 {
			t.Fatalf("bad pair: %+v", tr)
		}
	}
}
