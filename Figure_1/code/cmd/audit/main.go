package main

import (
	"ckks-precision-experiments/internal/boundary"
	"flag"
	"fmt"
	"os"
)

func main() {
	run := flag.String("run", "", "saved run")
	keys := flag.String("keys", "", "saved synthetic key family")
	out := flag.String("out", "", "new audit JSON")
	flag.Parse()
	if e := boundary.Audit(*run, *keys, *out); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
