package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
	"math"
	"math/big"
	"strconv"
)

func f64(s string) float64 {
	v, e := strconv.ParseFloat(s, 64)
	if e != nil {
		panic(e)
	}
	return v
}
func embed(c []string, n int) []*big.Int {
	a := make([]*big.Int, n)
	for i := range a {
		a[i] = new(big.Int)
	}
	for j, v := range c {
		x, ok := new(big.Int).SetString(v, 10)
		if !ok {
			panic("bad unit")
		}
		a[j*n/len(c)] = x
	}
	return a
}
func logProduct(xs []uint64) float64 {
	v := 0.0
	for _, x := range xs {
		v += math.Log2(float64(x))
	}
	return v
}
func scaleLog(s rlwe.Scale) float64 { v, _ := s.Value.Float64(); return math.Log2(v) }
func bitsError(e float64) float64 {
	if e == 0 {
		return 999
	}
	return -math.Log2(e)
}

func decode(p ckks.Parameters, sk *rlwe.SecretKey, c *rlwe.Ciphertext) ([]complex128, error) {
	pt := rlwe.NewDecryptor(p, sk).DecryptNew(c)
	v := make([]complex128, p.MaxSlots())
	err := ckks.NewEncoder(p, 128).Decode(pt, v)
	return v, err
}
func selectedLift(p ckks.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext) ([2]*big.Int, [2]int64, error) {
	var raw [2]*big.Int
	var carry [2]int64
	c, e := lb.CenteredCiphertextComponents(p, ct)
	if e != nil {
		return raw, carry, e
	}
	s, e := lb.CenteredCoefficients(p, sk.Value.Q, true, true)
	if e != nil {
		return raw, carry, e
	}
	pt := rlwe.NewDecryptor(p, sk).DecryptNew(ct)
	mu, e := lb.CenteredCoefficients(p, pt.Value, pt.IsNTT, pt.IsMontgomery)
	if e != nil {
		return raw, carry, e
	}
	q := new(big.Int).SetUint64(p.Q()[0])
	term := new(big.Int)
	for k, pos := range []int{0, p.N() / 2} {
		raw[k] = new(big.Int).Set(c[0][pos])
		for j, sj := range s {
			if sj.Sign() == 0 {
				continue
			}
			i := pos - j
			neg := i < 0
			if neg {
				i += p.N()
			}
			term.Mul(c[1][i], sj)
			if neg {
				raw[k].Sub(raw[k], term)
			} else {
				raw[k].Add(raw[k], term)
			}
		}
		delta := new(big.Int).Sub(raw[k], mu[pos])
		quot, rem := new(big.Int), new(big.Int)
		quot.QuoRem(delta, q, rem)
		if rem.Sign() != 0 || !quot.IsInt64() {
			return raw, carry, fmt.Errorf("nonintegral carry")
		}
		carry[k] = quot.Int64()
	}
	return raw, carry, nil
}
