package main

import (
	"ckks-precision-experiments/internal/zeromean"
	"flag"
	"fmt"
	"os"
	"runtime"
)

func main() {
	runtime.GOMAXPROCS(1)
	settings := flag.String("settings", "", "settings JSON")
	unit := flag.String("unit", "", "exact unit JSON")
	input := flag.String("input", "grow", "grow or shrink")
	out := flag.String("out", "", "new compact result directory")
	flag.Parse()
	if e := zeromean.Run(*settings, *unit, "", *input, *out); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
