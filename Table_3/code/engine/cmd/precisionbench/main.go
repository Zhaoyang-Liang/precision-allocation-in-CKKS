package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"ckks-precision-experiments/internal/bench"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "precisionbench:", err)
		os.Exit(1)
	}
}
func run() error {
	config := flag.String("config", "", "suite JSON (required)")
	mode := flag.String("mode", "plan", "plan: public parameters only; run: one actual HE execution per selected case")
	out := flag.String("out", "", "new output directory, required for run; never overwritten")
	cases := flag.String("cases", "", "optional comma-separated case IDs; original configuration order retained")
	flag.Parse()
	if *config == "" {
		return fmt.Errorf("-config is required")
	}
	s, b, e := bench.Load(*config)
	if e != nil {
		return e
	}
	switch *mode {
	case "plan":
		p, e := bench.Plan(s)
		if e != nil {
			return e
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	case "run":
		if *out == "" { return fmt.Errorf("-out is required for run") }
		return bench.RunFormal(s, b, *out, *cases)
    case "diagnostic":
		if *out == "" {
			return fmt.Errorf("-out is required for run")
		}
		return bench.Run(s, b, *out, *cases)
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}
