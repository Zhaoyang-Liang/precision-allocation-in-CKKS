package boundary

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func LoadCoefficients(path string, n int) []*big.Int {
	f, e := os.Open(path)
	must(e)
	defer f.Close()
	gz, e := gzip.NewReader(f)
	must(e)
	defer gz.Close()
	d := json.NewDecoder(gz)
	a := Ints(n)
	for i := 0; i < n; i++ {
		var row struct {
			Index   int    `json:"index"`
			Integer string `json:"integer"`
		}
		must(d.Decode(&row))
		if row.Index != i {
			panic("coefficient index mismatch")
		}
		if _, ok := a[i].SetString(row.Integer, 10); !ok {
			panic("invalid coefficient")
		}
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		panic("extra coefficient or corrupt gzip trailer")
	}
	return a
}
func loadCipher(path string, p ckks.Parameters) *rlwe.Ciphertext {
	f, e := os.Open(path)
	must(e)
	defer f.Close()
	gz, e := gzip.NewReader(f)
	must(e)
	defer gz.Close()
	b, e := io.ReadAll(gz)
	must(e)
	ct := ckks.NewCiphertext(p, 1, p.MaxLevel())
	must(ct.UnmarshalBinary(b))
	return ct
}
func checkHashes(dir string) {
	var m struct {
		Files map[string]string `json:"files"`
	}
	must(ReadJSON(filepath.Join(dir, "manifest.json"), &m))
	if len(m.Files) == 0 {
		panic("empty manifest")
	}
	for name, h := range m.Files {
		if filepath.Base(name) != name || HashFile(filepath.Join(dir, name)) != h {
			panic("manifest mismatch: " + name)
		}
	}
}

// Audit uses saved ciphertexts and integer witnesses, with no fresh encryption
// or HE evaluator calls. In particular, kappa is independently recovered from
// the saved next ciphertext and the rescale remainders.
func Audit(dir, keyDir, out string) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("raw audit failed: %v", x)
		}
	}()
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		return fmt.Errorf("audit output must be new")
	}
	start := time.Now()
	checkHashes(dir)
	checkHashes(keyDir)
	if HashFile(filepath.Join(dir, "key_manifest.json")) != HashFile(filepath.Join(keyDir, "manifest.json")) {
		panic("key family mismatch")
	}
	var s Settings
	var u Unit
	must(ReadJSON(filepath.Join(dir, "settings.json"), &s))
	must(ReadJSON(filepath.Join(dir, "unit.json"), &u))
	p, e := s.Params()
	must(e)
	sk := rlwe.NewSecretKey(p)
	must(readBinary(filepath.Join(keyDir, "secret.key"), sk))
	dec := rlwe.NewDecryptor(p, sk)
	unit := ParseInts(u.Coefficients)
	must(VerifySmallInverse(unit, ParseInts(u.Inverse)))
	dense := Ints(p.N())
	for i, v := range unit {
		dense[i*p.N()/len(unit)].Set(v)
	}
	unitMont := p.RingQ().NewPoly()
	p.RingQ().SetCoefficientsBigint(dense, unitMont)
	p.RingQ().NTT(unitMont, unitMont)
	p.RingQ().MForm(unitMont, unitMont)
	secret := Coefficients(p.RingQ(), sk.Value.Q, true, true)
	l1 := new(big.Int)
	for _, v := range secret {
		if new(big.Int).Abs(v).Cmp(big.NewInt(1)) > 0 {
			panic("nonternary secret")
		}
		l1.Add(l1, new(big.Int).Abs(v))
	}
	mu := LoadCoefficients(filepath.Join(dir, "encoded_mu.jsonl.gz"), p.N())
	noise := LoadCoefficients(filepath.Join(dir, "encryption_noise.jsonl.gz"), p.N())
	zero := ckks.NewCiphertext(p, 1, p.MaxLevel())
	must(readBinary(filepath.Join(keyDir, "zero.ct"), zero))
	if !Equals(noise, Coefficients(p.RingQ(), dec.DecryptNew(zero).Value, true, false)) || MaxAbs(noise).BitLen() > 40 {
		panic("fresh noise witness mismatch")
	}
	for i := range mu {
		mu[i].Add(mu[i], noise[i])
	}
	M := SparseMultiply(mu, unit)
	var result struct {
		Last     int    `json:"last_recoverable_depth"`
		First    int    `json:"first_failure_depth"`
		Terminal string `json:"terminal_reason"`
		Layers   []struct {
			Depth   int    `json:"depth"`
			Wrap    bool   `json:"wrap"`
			Max     string `json:"shadow_coefficient_max"`
			Allowed string `json:"allowed_coefficient_max"`
		} `json:"layers"`
	}
	must(ReadJSON(filepath.Join(dir, "result.json"), &result))
	last, first := -1, -1
	var prev *rlwe.Ciphertext
	for depth, row := range result.Layers {
		if row.Depth != depth {
			panic("nonconsecutive layers")
		}
		ct := loadCipher(filepath.Join(dir, fmt.Sprintf("layer_%02d.ct.gz", depth)), p)
		if ct.Degree() != 1 || ct.Level() != p.MaxLevel()-depth*s.RescaleCount {
			panic("ciphertext schedule mismatch")
		}
		r := p.RingQ().AtLevel(ct.Level())
		Q := Product(s.Q[:ct.Level()+1])
		half := new(big.Int).Rsh(new(big.Int).Set(Q), 1)
		if depth > 0 {
			beforeLevel := prev.Level()
			rb := p.RingQ().AtLevel(beforeLevel)
			qb := Product(s.Q[:beforeLevel+1])
			D := Product(s.Q[ct.Level()+1 : beforeLevel+1])
			prefix := filepath.Join(dir, fmt.Sprintf("step_%02d", depth))
			rho := [][]*big.Int{LoadCoefficients(prefix+"_rho0.jsonl.gz", p.N()), LoadCoefficients(prefix+"_rho1.jsonl.gz", p.N())}
			halfD := new(big.Int).Rsh(new(big.Int).Set(D), 1)
			old := ckks.NewCiphertext(p, 1, beforeLevel)
			rhoP := make([]ring.Poly, 2)
			for j := 0; j < 2; j++ {
				if MaxAbs(rho[j]).Cmp(halfD) > 0 {
					panic("noncentered rescale remainder")
				}
				next := Coefficients(r, ct.Value[j], true, false)
				for i := range next {
					next[i].Mul(next[i], D)
					next[i].Add(next[i], rho[j][i])
				}
				rb.SetCoefficientsBigint(next, old.Value[j])
				rb.NTT(old.Value[j], old.Value[j])
				rhoP[j] = rb.NewPoly()
				rb.SetCoefficientsBigint(rho[j], rhoP[j])
				rb.NTT(rhoP[j], rhoP[j])
			}
			phase := dec.DecryptNew(prev).Value
			mont := rb.NewPoly()
			before := rb.NewPoly()
			rb.MForm(phase, mont)
			rb.MulCoeffsMontgomery(phase, mont, before)
			rb.MulCoeffsMontgomery(before, unitMont, before)
			difference := dec.DecryptNew(old).Value
			rb.Sub(difference, before, difference)
			kappa := Coefficients(rb, difference, true, false)
			if MaxAbs(kappa).BitLen() > 64 || !Equals(kappa, LoadCoefficients(prefix+"_kappa.jsonl.gz", p.N())) {
				panic("relinearization witness inconsistent with saved ciphertexts")
			}
			rp := rb.NewPoly()
			rb.MulCoeffsMontgomery(rhoP[1], sk.Value.Q, rp)
			rb.Add(rp, rhoP[0], rp)
			R := Coefficients(rb, rp, true, false)
			bound := new(big.Int).Mul(halfD, new(big.Int).Add(l1, big.NewInt(1)))
			if new(big.Int).Lsh(new(big.Int).Set(bound), 1).Cmp(qb) >= 0 || MaxAbs(R).Cmp(bound) > 0 || !Equals(R, LoadCoefficients(prefix+"_rescale_numerator.jsonl.gz", p.N())) {
				panic("rescale witness mismatch")
			}
			next, _, e := ExactSquare(M)
			must(e)
			uk := SparseMultiply(kappa, unit)
			ur := SparseMultiply(R, unit)
			rem := new(big.Int)
			for i := range next {
				next[i].Add(next[i], uk[i])
				next[i].Sub(next[i], ur[i])
				next[i].QuoRem(next[i], D, rem)
				if rem.Sign() != 0 {
					panic("noninteger shadow quotient")
				}
			}
			M = next
		} else if !Congruent(mu, Coefficients(r, dec.DecryptNew(ct).Value, true, false), Q) {
			panic("initial ciphertext phase mismatch")
		}
		phase := dec.DecryptNew(ct).Value
		r.MulCoeffsMontgomery(phase, unitMont, phase)
		actual := Coefficients(r, phase, true, false)
		prefix := filepath.Join(dir, fmt.Sprintf("layer_%02d", depth))
		if !Equals(M, LoadCoefficients(prefix+"_shadow.jsonl.gz", p.N())) || !Equals(actual, LoadCoefficients(prefix+"_centered.jsonl.gz", p.N())) || !Equals(Centered(M, Q), actual) {
			panic("saved phase/shadow mismatch")
		}
		wrap := MaxAbs(M).Cmp(half) > 0
		if row.Wrap != wrap || row.Max != MaxAbs(M).String() || row.Allowed != half.String() {
			panic("classification mismatch")
		}
		if wrap {
			first = depth
			if depth != len(result.Layers)-1 {
				panic("continued after wrap")
			}
		} else {
			last = depth
		}
		prev = ct
	}
	terminal := "chain_exhausted"
	if first >= 0 {
		terminal = "restoration_wrap"
	} else if last != s.Depth {
		panic("ended before chain limit")
	}
	if first != result.First || last != result.Last || terminal != result.Terminal {
		panic("terminal mismatch")
	}
	exe, _ := os.Executable()
	host, _ := os.Hostname()
	return WriteJSON(out, map[string]any{"schema": "saved-raw-integer-audit-v1", "pass": true, "run_manifest_sha256": HashFile(filepath.Join(dir, "manifest.json")), "audit_binary_sha256": HashFile(exe), "host": host, "elapsed_seconds": time.Since(start).Seconds(), "layers_checked": len(result.Layers), "checks": []string{"all run and key file hashes", "unit inverse", "paired initial noise", "ciphertext re-decryption", "relinearization witness from saved next ciphertext and rescale remainders", "bounded rescale lift", "exact integer shadow recurrence", "centered modular identity and wrap decision", "terminal reason"}, "scope": "Independent reconstruction from saved ciphertexts; shares verified integer/NTT helpers with runner. Does not re-encrypt or repeat the HE run. Precision observer is not an acceptance criterion."})
}
