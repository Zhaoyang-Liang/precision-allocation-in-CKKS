package main

import (
	"ckks-precision-experiments/internal/bench"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "Tuple suite")
	mode := flag.String("mode", "plan", "plan or run")
	out := flag.String("out", "", "new result directory")
	cases := flag.String("cases", "", "selected IDs")
	flag.Parse()
	s, b, e := bench.LoadTuple(*path)
	if e != nil {
		return e
	}
	switch *mode {
	case "plan":
		p, e := bench.TuplePlan(s)
		if e != nil {
			return e
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	case "diagnostic":
        if *out == "" { return fmt.Errorf("need output directory") }; return bench.RunTupleDiagnostic(s,b,*out,*cases)
	case "run":
		if *out == "" {
			return fmt.Errorf("need output directory")
		}
		return bench.RunTuple(s, b, *out, *cases)
	default:
		return fmt.Errorf("invalid mode")
	}
}
