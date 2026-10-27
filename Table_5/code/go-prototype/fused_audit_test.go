package lowbootstrap

import (
	"math"
	"math/big"
	"math/cmplx"
	"strconv"
	"sync"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Independent audit of the public fused map, including real KS after source
// automorphisms and actual component rounding in the normalized trace. The
// known secret appears only in test-side measurement of the lifted phase.
func TestFusedRecoveryActualCiphertext(t *testing.T) {
	for _, R := range []int{2, 4, 8, 16} {
		t.Run(strconv.Itoa(R), func(t *testing.T) {
			high, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
				LogN: 7, LogQ: []int{43, 28, 28}, LogP: []int{53}, LogDefaultScale: 55,
				Xs: ring.Ternary{H: 32},
			})
			if err != nil {
				t.Fatal(err)
			}
			low, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
				LogN: 7, Q: high.Q()[:1], LogP: []int{25}, LogDefaultScale: 24,
				Xs: ring.Ternary{H: 16},
			})
			if err != nil {
				t.Fatal(err)
			}
			sparseLow := rlwe.NewKeyGenerator(low).GenSecretKeyNew()
			sparseHigh, err := RebaseSecretKey(low, high, sparseLow)
			if err != nil {
				t.Fatal(err)
			}
			kg := rlwe.NewKeyGenerator(high)
			dense := kg.GenSecretKeyNew()
			gks := kg.GenGaloisKeysNew(FusedGaloisElements(high, R), dense)
			unit := make([]*big.Int, high.N())
			unit[0], unit[high.N()/4], unit[3*high.N()/4] = big.NewInt(-1), big.NewInt(1), big.NewInt(-1)
			alpha := new(big.Float).SetPrec(192).SetInt64(64)
			scale := rlwe.NewScale(math.Exp2(55))
			fused, err := NewFusedRecovery(high, R, alpha, scale, unit, sparseHigh, dense, rlwe.NewMemEvaluationKeySet(nil, gks...), 741)
			if err != nil {
				t.Fatal(err)
			}
			message := make([]*big.Int, low.N())
			for j := range message {
				message[j] = big.NewInt(int64((j%11)-5) * 12345)
			}
			pt := rlwe.NewPlaintext(low, 0)
			pt.IsBatched = true
			pt.Scale, pt.LogDimensions.Cols = rlwe.NewScale(1<<24), low.LogN()-1
			p, err := PolynomialFromCoefficients(low, message, 0, true, false)
			if err != nil {
				t.Fatal(err)
			}
			pt.Value.Copy(p)
			ct, err := rlwe.NewEncryptor(low, sparseLow).EncryptNew(pt)
			if err != nil {
				t.Fatal(err)
			}
			components, err := CenteredCiphertextComponents(low, ct)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := CenteredCoefficients(low, sparseLow.Value.Q, true, true)
			if err != nil {
				t.Fatal(err)
			}
			lifted := func(k int) *big.Int {
				z, term := new(big.Int).Set(components[0][k]), new(big.Int)
				for j, s := range secret {
					if s.Sign() == 0 {
						continue
					}
					idx := k - j
					negative := idx < 0
					if negative {
						idx += low.N()
					}
					term.Mul(components[1][idx], s)
					if negative {
						z.Sub(z, term)
					} else {
						z.Add(z, term)
					}
				}
				return z
			}
			l0, _ := new(big.Float).SetInt(lifted(0)).Float64()
			li, _ := new(big.Float).SetInt(lifted(low.N() / 2)).Float64()
			realCT, imagCT, err := fused.Apply(low, ct)
			if err != nil {
				t.Fatal(err)
			}
			// Share the real evaluation keys while exercising independent mutable
			// scratch space and RNGs concurrently. Exact ciphertext equality is
			// stronger than comparing only decrypted error norms.
			copies := []*FusedRecovery{fused.ShallowCopy(741), fused.ShallowCopy(741), fused.ShallowCopy(741)}
			var wg sync.WaitGroup
			for _, clone := range copies {
				wg.Add(1)
				go func(f *FusedRecovery) {
					defer wg.Done()
					r, i, e := f.Apply(low, ct)
					if e != nil {
						t.Error(e)
						return
					}
					if !r.Equal(realCT) || !i.Equal(imagCT) {
						t.Error("concurrent fused copy differs from serial")
					}
					f.SetRoundingSeed(741)
					r2, i2, e := f.Apply(low, ct)
					if e != nil {
						t.Error(e)
						return
					}
					if !r2.Equal(r) || !i2.Equal(i) {
						t.Error("reset seed failed to reproduce ciphertext")
					}
				}(clone)
			}
			wg.Wait()
			dec, enc := rlwe.NewDecryptor(high, dense), ckks.NewEncoder(high)
			factor := 2 * 64 * float64(R) * (math.Sqrt(2) - 1) / math.Exp2(55)
			maxErr := 0.0
			for part, output := range []*rlwe.Ciphertext{realCT, imagCT} {
				values := make([]complex128, high.N()/2)
				if err := enc.Decode(dec.DecryptNew(output), values); err != nil {
					t.Fatal(err)
				}
				want := l0 * factor
				if part == 1 {
					want = li * factor
				}
				for j, v := range values {
					target := complex(0, 0)
					if j%R == 0 {
						target = complex(want, 0)
					}
					maxErr = math.Max(maxErr, cmplx.Abs(v-target))
				}
				if output.Level() != high.MaxLevel() || output.Scale.Cmp(scale) != 0 {
					t.Fatal("fused map changed output level or scale")
				}
			}
			if maxErr > 1e-10 {
				t.Fatalf("R=%d: max slot error=%g; mask sign, carry, or scale mismatch", R, maxErr)
			}
			t.Logf("R=%d: real public fused map n128, max data/guard slot error=%g", R, maxErr)
		})
	}
}
