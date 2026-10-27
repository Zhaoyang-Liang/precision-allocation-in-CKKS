// Public arithmetic and serialization only: no secret keys or HE execution.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func rat(s rlwe.Scale) *big.Rat { r, _ := s.Value.Rat(nil); return r }
func relative(a, b *big.Rat) *big.Rat {
	return new(big.Rat).Quo(new(big.Rat).Abs(new(big.Rat).Sub(a, b)), new(big.Rat).Abs(b))
}
func bits(r *big.Rat) any {
	if r.Sign() == 0 {
		return nil
	}
	f := new(big.Float).SetPrec(128).SetRat(r)
	m := new(big.Float)
	e := f.MantExp(m)
	v, _ := m.Float64()
	return -float64(e) - math.Log2(v)
}
func main() {
	out := flag.String("out", "", "exclusive JSON output path")
	flag.Parse()
	if *out == "" {
		panic("-out is required")
	}
	s := rlwe.NewScale(new(big.Int).Lsh(big.NewInt(1), 192))
	exact := rat(s)
	rows := []map[string]any{}
	// The fixed integer divisor is just a public metadata stress test, not an
	// HE parameter or an asserted prime. Each node keeps the exact rational.
	divisor := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(51))
	for i := 1; i <= 4; i++ {
		exact.Mul(exact, exact)
		exact.Quo(exact, new(big.Rat).SetInt(divisor))
		s = s.Mul(s).Div(rlwe.NewScale(divisor))
		before := rat(s)
		w, err := s.MarshalBinary()
		if err != nil {
			panic(err)
		}
		if before.Sign() == 0 {
			panic(fmt.Sprintf("unexpected zero at layer %d: exact=%s scale=%s divisor=%s", i, exact.FloatString(2), s.Value.Text('g', 20), divisor.String()))
		}
		// v6.2.0 Scale.UnmarshalBinary has a value receiver; it does not populate
		// a zero Scale. The actual metadata reader uses pointer UnmarshalJSON.
		var read rlwe.Scale
		if err = read.UnmarshalJSON(w); err != nil {
			panic(err)
		}
		total := relative(rat(read), exact)
		rows = append(rows, map[string]any{"layer": i, "relative_arithmetic_error": relative(before, exact).RatString(),
			"relative_wire_change": relative(rat(read), before).RatString(), "relative_total_error": total.RatString(),
			"relative_accuracy_bits_display": bits(total), "serialized_bytes": len(w), "binary_size_match": len(w) == s.BinarySize(),
			"read_precision_bits": read.Value.Prec(), "error_le_2_minus_512": total.Cmp(new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 512))) <= 0})
		s = read
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(map[string]any{"scale_precision": rlwe.ScalePrecision, "HE_executions": 0, "generated_keys": 0, "rows": rows})
	if err != nil {
		panic(err)
	}
	fmt.Printf("scale_precision=%d; public layers=%d; output=%s\n", rlwe.ScalePrecision, len(rows), *out)
}
