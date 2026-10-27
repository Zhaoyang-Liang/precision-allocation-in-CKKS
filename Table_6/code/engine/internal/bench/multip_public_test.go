package bench

// Public arithmetic only: no secret generation, encryption, or HE evaluation.
import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math/big"
	"testing"
)

func mpProduct(ps []uint64) *big.Int {
	b := big.NewInt(1)
	for _, p := range ps {
		b.Mul(b, new(big.Int).SetUint64(p))
	}
	return b
}

// Integer CRT sum plus an independently reconstructed binary64 correction.
// Unlike a centered CRT oracle, this does not assume floating floor is exact.
func mpLift(res []uint64, ps []uint64, singleton bool) *big.Int {
	if singleton {
		d := new(big.Int).SetUint64(res[0])
		if res[0] >= ps[0]>>1 {
			d.Sub(d, new(big.Int).SetUint64(ps[0]))
		}
		return d
	}
	B := mpProduct(ps)
	half := new(big.Int).Rsh(new(big.Int).Set(B), 1)
	A := new(big.Int)
	sum := float64(0)
	for i, p := range ps {
		pp := new(big.Int).SetUint64(p)
		Mi := new(big.Int).Quo(new(big.Int).Set(B), pp)
		inv := new(big.Int).ModInverse(Mi, pp)
		y := new(big.Int).Add(new(big.Int).SetUint64(res[i]), half)
		y.Mul(y, inv)
		y.Mod(y, pp)
		A.Add(A, new(big.Int).Mul(y, Mi))
		sum += float64(y.Uint64()) / float64(p)
	}
	A.Sub(A, new(big.Int).Mul(new(big.Int).SetUint64(uint64(sum)), B))
	return A.Sub(A, half)
}

func mpParams(t *testing.T, m int) ckks.Parameters {
	t.Helper()
	pp := make([]int, m)
	for i := range pp {
		pp[i] = 48 + i%3
	}
	p, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 4, LogQ: []int{40, 39, 58, 58, 56, 58, 58, 56, 50, 51}, LogP: pp, LogDefaultScale: 76})
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestMultiPDecompositionUniformPublic(t *testing.T) {
	for m := 1; m <= 10; m++ {
		p := mpParams(t, m)
		ev := rlwe.NewEvaluator(p, nil)
		for level := 0; level < p.QCount(); level++ {
			rq := p.RingQ().AtLevel(level)
			rp := p.RingP()
			in := rq.NewPoly()
			for i, q := range p.Q()[:level+1] {
				for j := range in.Coeffs[i] {
					switch j % 6 {
					case 0:
						in.Coeffs[i][j] = 0
					case 1:
						in.Coeffs[i][j] = q / 2
					case 2:
						in.Coeffs[i][j] = q/2 - 1
					case 3:
						in.Coeffs[i][j] = q - 1
					default:
						in.Coeffs[i][j] = (uint64(j+1)*0x100000001b3 + uint64(i*17)) % q
					}
				}
			}
			nt := rq.NewPoly()
			rq.NTT(in, nt)
			for block := 0; block < (level+m)/m; block++ {
				outQ := rq.NewPoly()
				outP := rp.NewPoly()
				ev.DecomposeSingleNTT(level, m-1, m, block, nt, in, outQ, outP)
				rq.INTT(outQ, outQ)
				rp.INTT(outP, outP)
				start := block * m
				end := min(start+m, level+1)
				ps := p.Q()[start:end]
				for j := 0; j < p.N(); j++ {
					residues := make([]uint64, len(ps))
					for i := range ps {
						residues[i] = in.Coeffs[start+i][j]
					}
					d := mpLift(residues, ps, len(ps) == 1)
					for i, q := range p.Q()[:level+1] {
						want := new(big.Int).Mod(d, new(big.Int).SetUint64(q)).Uint64()
						if outQ.Coeffs[i][j]%q != want {
							t.Fatalf("m=%d level=%d block=%d Q[%d]", m, level, block, i)
						}
					}
					for i, q := range p.P() {
						want := new(big.Int).Mod(d, new(big.Int).SetUint64(q)).Uint64()
						if outP.Coeffs[i][j]%q != want {
							t.Fatalf("m=%d level=%d block=%d P[%d]", m, level, block, i)
						}
					}
				}
			}
		}
	}
}

func TestMultiPModDownLiftPublic(t *testing.T) {
	for m := 1; m <= 10; m++ {
		p := mpParams(t, m)
		rq := p.RingQ()
		rp := p.RingP()
		be := ring.NewBasisExtender(rq, rp)
		P := mpProduct(p.P())
		half := new(big.Int).Rsh(new(big.Int).Set(P), 1)
		qv := rq.NewPoly()
		pv := rp.NewPoly()
		zs := make([]*big.Int, p.N())
		for j := 0; j < p.N(); j++ {
			z := new(big.Int).Set(half)
			z.Add(z, big.NewInt(int64(j%7-3)))
			if j%2 == 1 {
				z.Neg(z)
			}
			z.Add(z, new(big.Int).Mul(P, big.NewInt(int64(j*17))))
			zs[j] = z
			for i, q := range p.Q() {
				qv.Coeffs[i][j] = new(big.Int).Mod(z, new(big.Int).SetUint64(q)).Uint64()
			}
			for i, q := range p.P() {
				pv.Coeffs[i][j] = new(big.Int).Mod(z, new(big.Int).SetUint64(q)).Uint64()
			}
		}
		out := rq.NewPoly()
		be.ModDownQPtoQ(p.MaxLevel(), m-1, qv, pv, out)
		qn := rq.NewPoly()
		pn := rp.NewPoly()
		rq.NTT(qv, qn)
		rp.NTT(pv, pn)
		outNTT := rq.NewPoly()
		be.ModDownQPtoQNTT(p.MaxLevel(), m-1, qn, pn, outNTT)
		rq.INTT(outNTT, outNTT)
		for j, z := range zs {
			residues := make([]uint64, m)
			for i := range residues {
				residues[i] = pv.Coeffs[i][j]
			}
			// ModDown uses floating reconstruction even with a singleton P.
			lift := mpLift(residues, p.P(), false)
			want, rem := new(big.Int).QuoRem(new(big.Int).Sub(z, lift), P, new(big.Int))
			if rem.Sign() != 0 {
				t.Fatal("nonintegral quotient")
			}
			for i, q := range p.Q() {
				w := new(big.Int).Mod(want, new(big.Int).SetUint64(q)).Uint64()
				if out.Coeffs[i][j]%q != w || outNTT.Coeffs[i][j]%q != w {
					t.Fatalf("ModDown m=%d j=%d q=%d", m, j, i)
				}
			}
		}
	}
}
