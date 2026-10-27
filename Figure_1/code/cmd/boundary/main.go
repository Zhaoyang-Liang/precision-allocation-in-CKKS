package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"ckks-precision-experiments/internal/boundary"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	mode := flag.String("mode", "", "params, keys or run")
	settings := flag.String("settings", "", "settings JSON")
	out := flag.String("out", "", "new output path")
	unit := flag.String("unit", "", "unit JSON")
	keys := flag.String("keys", "", "synthetic key family directory")
	input := flag.String("input", "grow", "grow or shrink")
	logN := flag.Int("logn", 15, "ring log2 dimension")
	messages := flag.Int("messages", 4096, "effective messages")
	flag.Parse()
	var e error
	switch *mode {
	case "roots":
		var s boundary.Settings
		e = boundary.ReadJSON(*settings, &s)
		if e == nil {
			os.Setenv("CKKS_BOUNDARY_ROOTS_CACHE", *out)
			os.Setenv("CKKS_BOUNDARY_GENERATE_ROOTS", "1")
			ckks.GetRootsBigComplex(2<<s.LogN, s.Precision)
			fmt.Println("public root constants cached:", boundary.HashFile(*out))
		}
	case "params":
		if _, e = os.Stat(*out); !os.IsNotExist(e) {
			fail(fmt.Errorf("output must not exist"))
		}
		var s boundary.Settings
		s, e = boundary.GenerateSettings(*logN, *messages)
		if e == nil {
			e = boundary.WriteJSON(*out, s)
		}
		if e == nil {
			e = boundary.WriteJSON(filepath.Join(filepath.Dir(*out), "security_plan.json"), boundary.SecurityPlan(s))
		}
	case "keys":
		e = boundary.GenerateKeys(*settings, *out)
	case "run":
		e = boundary.Run(*settings, *unit, *keys, *input, *out)
	default:
		e = fmt.Errorf("choose -mode params|keys|run")
	}
	if e != nil {
		fail(e)
	}
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
