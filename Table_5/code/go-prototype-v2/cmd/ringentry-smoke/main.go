package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"lowbootstrap"
)

func main() {
	var c lowbootstrap.RingEntrySmokeConfig
	flag.IntVar(&c.TopLogN, "logN", 8, "top ring log degree (use 15 on HPC)")
	flag.IntVar(&c.LeafLogN, "logn", 7, "leaf ring log degree (use 14 on HPC)")
	flag.IntVar(&c.QBits, "logq", 52, "entry q bit size")
	flag.IntVar(&c.PBits, "logp", 25, "single entry P prime bit size")
	flag.IntVar(&c.BaseTwo, "base", 14, "gadget base-two decomposition bits")
	flag.IntVar(&c.TopWeight, "top-h", 32, "top secret Hamming weight")
	flag.IntVar(&c.LeafWeight, "leaf-h", 32, "leaf secret Hamming weight")
	flag.Parse()
	report, err := lowbootstrap.RunRingEntrySmoke(c)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(report); e != nil {
		panic(e)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
