package ckks

// Experiment-local persistence of public FFT constants. The original root
// construction is unchanged. GobEncode/GobDecode retain each big.Float exactly.
import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/big"
	"os"

	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type boundaryRootCache struct {
	N         int
	Precision uint
	Cosines   [][]byte
}

func loadBoundaryRoots(n int, prec uint) []*bignum.Complex {
	// The evaluator also creates its own low-precision encoder. Only the
	// explicitly selected high-precision observer uses this cache.
	if prec != 8192 {
		return nil
	}
	path := os.Getenv("CKKS_BOUNDARY_ROOTS_CACHE")
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) && os.Getenv("CKKS_BOUNDARY_GENERATE_ROOTS") == "1" {
		return nil
	}
	if err != nil {
		panic(fmt.Errorf("public roots cache: %w", err))
	}
	var c boundaryRootCache
	if err = gob.NewDecoder(bytes.NewReader(data)).Decode(&c); err != nil {
		panic(err)
	}
	if c.N != n || c.Precision != prec || len(c.Cosines) != n/4 {
		panic(fmt.Sprintf("public roots cache parameters differ: cached n=%d precision=%d count=%d; requested n=%d precision=%d", c.N, c.Precision, len(c.Cosines), n, prec))
	}
	q := n / 4
	roots := make([]*bignum.Complex, n+1)
	for i, raw := range c.Cosines {
		v := new(big.Float)
		if err = v.GobDecode(raw); err != nil {
			panic(err)
		}
		if v.Prec() != prec {
			panic("public roots cache float precision differs")
		}
		roots[i] = &bignum.Complex{v, nil}
	}
	roots[0][1] = bignum.NewFloat(0, prec)
	for i := 1; i < q; i++ {
		roots[q-i][1] = new(big.Float).Set(roots[i].Real())
	}
	roots[q] = &bignum.Complex{bignum.NewFloat(0, prec), bignum.NewFloat(1, prec)}
	for i := 1; i <= q; i++ {
		roots[i+q] = &bignum.Complex{new(big.Float).Neg(roots[q-i].Real()), new(big.Float).Set(roots[q-i].Imag())}
		roots[i+2*q] = &bignum.Complex{new(big.Float).Neg(roots[i].Real()), new(big.Float).Neg(roots[i].Imag())}
		roots[i+3*q] = &bignum.Complex{new(big.Float).Set(roots[q-i].Real()), new(big.Float).Neg(roots[q-i].Imag())}
	}
	roots[n] = roots[0]
	return roots
}

func saveBoundaryRoots(n int, prec uint, roots []*bignum.Complex) {
	if prec != 8192 {
		return
	}
	path := os.Getenv("CKKS_BOUNDARY_ROOTS_CACHE")
	if path == "" {
		return
	}
	if os.Getenv("CKKS_BOUNDARY_GENERATE_ROOTS") != "1" {
		panic("root generation was not explicitly enabled")
	}
	c := boundaryRootCache{N: n, Precision: prec, Cosines: make([][]byte, n/4)}
	for i := range c.Cosines {
		raw, err := roots[i].Real().GobEncode()
		if err != nil {
			panic(err)
		}
		c.Cosines[i] = raw
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(c); err != nil {
		panic(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	if _, err = f.Write(buf.Bytes()); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}
}
