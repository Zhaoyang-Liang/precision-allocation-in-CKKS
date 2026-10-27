package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"ckks-precision-experiments/internal/bench"
)

func main() {
	mode := flag.String("mode", "plan", "plan (public), check (no keys), or run (requires security evidence)")
	config := flag.String("config", "", "new profile configuration")
	out := flag.String("out", "", "exclusive output JSON (plan) or run directory")
	flag.Parse()
	if *mode == "check" {
		result, e := bench.CheckProfileEvidence(*config)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if *mode == "run" {
		if e := bench.RunProfile(*config, *out); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if *mode != "plan" {
		fmt.Fprintln(os.Stderr, "mode must be plan, check, or run")
		os.Exit(2)
	}
	c, raw, e := bench.LoadProfile(*config)
	if e != nil {
		panic(e)
	}
	plan, e := bench.PlanProfile(c, raw)
	if e != nil {
		panic(e)
	}
	f, e := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if e = enc.Encode(plan); e != nil {
		panic(e)
	}
	fmt.Printf("public plan %s: %d branches; HE executions=0\n", c.ID, len(plan.Branches))
}
