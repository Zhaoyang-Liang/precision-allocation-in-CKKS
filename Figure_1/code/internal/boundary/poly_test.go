package boundary

import (
	"math/big"
	"math/rand"
	"testing"
)

func naiveSquare(a []*big.Int) []*big.Int {
	n := len(a)
	b := Ints(n)
	z := new(big.Int)
	for i, x := range a {
		for j, y := range a {
			z.Mul(x, y)
			k := i + j
			if k >= n {
				b[k-n].Sub(b[k-n], z)
			} else {
				b[k].Add(b[k], z)
			}
		}
	}
	return b
}

func TestExactSquareAgainstIntegerConvolution(t *testing.T) {
	random := rand.New(rand.NewSource(42))
	for _, bits := range []uint{2, 70, 310, 1000} {
		a := Ints(16)
		for i := range a {
			a[i].SetInt64(random.Int63n(1000) - 500)
			a[i].Lsh(a[i], bits)
		}
		got, _, err := ExactSquare(a)
		if err != nil {
			t.Fatal(err)
		}
		want := naiveSquare(a)
		if !Equals(got, want) {
			t.Fatalf("incorrect exact negacyclic product at bit shift %d", bits)
		}
	}
}

func TestCenteredWrapBoundary(t *testing.T) {
	q := big.NewInt(101)
	for _, v := range []int64{-152, -51, -50, 0, 50, 51, 152} {
		a := []*big.Int{big.NewInt(v)}
		c := Centered(a, q)
		wrap := new(big.Int).Abs(a[0]).Cmp(big.NewInt(50)) > 0
		if wrap == Equals(a, c) || !Congruent(a, c, q) {
			t.Fatalf("wrong centered boundary at %d", v)
		}
	}
}

func TestSparseSubringMultiplication(t *testing.T) {
	a := Ints(32)
	for i := range a {
		a[i].SetInt64(int64(i - 16))
	}
	u := []*big.Int{big.NewInt(2), big.NewInt(-7), big.NewInt(3), big.NewInt(9)}
	got := SparseMultiply(a, u)
	want := Ints(32)
	z := new(big.Int)
	for i, x := range a {
		for j, y := range u {
			k := i + 8*j
			z.Mul(x, y)
			if k >= 32 {
				want[k-32].Sub(want[k-32], z)
			} else {
				want[k].Add(want[k], z)
			}
		}
	}
	if !Equals(got, want) {
		t.Fatal("subring expansion is incorrect")
	}
}
