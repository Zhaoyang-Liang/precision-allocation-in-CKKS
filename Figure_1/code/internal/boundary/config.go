package boundary

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type Settings struct {
	Schema       string   `json:"schema"`
	LogN         int      `json:"log_n"`
	BaseBits     int      `json:"base_precision_budget_bits"`
	NoiseBits    int      `json:"baseline_numerator_noise_budget_bits"`
	ScaleBits    int      `json:"scale_bits"`
	Depth        int      `json:"depth"`
	RescaleCount int      `json:"rescale_count"`
	BottomCount  int      `json:"bottom_prime_count"`
	Messages     int      `json:"effective_messages"`
	Precision    uint     `json:"arithmetic_precision_bits"`
	Q            []uint64 `json:"Q"`
	P            []uint64 `json:"P"`
}

type Interval struct {
	Lower string `json:"lower"`
	Upper string `json:"upper"`
}
type Unit struct {
	Period       int        `json:"period"`
	Theta        int        `json:"requested_theta"`
	Coefficients []string   `json:"coefficients"`
	Inverse      []string   `json:"inverse_coefficients"`
	Embeddings   []Interval `json:"embedding_intervals"`
	ActualLogs   []float64  `json:"actual_log2_weights_display"`
	Hash         string     `json:"construction_sha256"`
}

func ReadJSON(path string, dst any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, dst)
}
func WriteJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func HashFile(path string) string {
	f, e := os.Open(path)
	must(e)
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	must(e)
	return hex.EncodeToString(h.Sum(nil))
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func NewFloat(p uint) *big.Float { return new(big.Float).SetPrec(p) }
func Product(q []uint64) *big.Int {
	x := big.NewInt(1)
	for _, v := range q {
		x.Mul(x, new(big.Int).SetUint64(v))
	}
	return x
}
func ScaleBits(bits int) rlwe.Scale {
	return rlwe.NewScale(new(big.Int).Lsh(big.NewInt(1), uint(bits)))
}

func (s Settings) Params() (ckks.Parameters, error) {
	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: s.LogN, Q: s.Q, P: s.P, LogDefaultScale: s.ScaleBits,
		Xs: ring.Ternary{P: 2.0 / 3.0}, Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}})
}

func GenerateSettings(logN, messages int) (Settings, error) {
	s := Settings{Schema: "ckks-allocation-boundary-v1", LogN: logN, BaseBits: 64, NoiseBits: 28, ScaleBits: 92, Depth: 7, RescaleCount: 2, BottomCount: 2, Messages: messages, Precision: 8192}
	logs := []int{48, 48, 48, 48}
	// The seventh rescale consumes two 48-bit primes; two remain afterwards.
	for i := 0; i < (s.Depth-1)*s.RescaleCount; i++ {
		logs = append(logs, 46)
	}
	p, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: logN, LogQ: logs, LogP: []int{56, 56}, LogDefaultScale: 92, Xs: ring.Ternary{P: 2.0 / 3.0}, Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}})
	if e != nil {
		return s, e
	}
	s.Q = p.Q()
	s.P = p.P()
	return s, nil
}

func SecurityPlan(s Settings) any {
	q, p := []string{}, []string{}
	for _, x := range s.Q {
		q = append(q, fmt.Sprint(x))
	}
	for _, x := range s.P {
		p = append(p, fmt.Sprint(x))
	}
	return map[string]any{"branches": []any{map[string]any{"id": "fixed_boundary_parameters", "parameters": map[string]any{"n": 1 << s.LogN, "Q": q, "P": p, "qp_exact": Product(append(append([]uint64{}, s.Q...), s.P...)).String()}}}}
}

func writeBinary(path string, v interface{ MarshalBinary() ([]byte, error) }) error {
	b, e := v.MarshalBinary()
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func readBinary(path string, v interface{ UnmarshalBinary([]byte) error }) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return v.UnmarshalBinary(b)
}
func gzipBinary(path string, v interface{ MarshalBinary() ([]byte, error) }) error {
	b, e := v.MarshalBinary()
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	w, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	_, e = w.Write(b)
	if e != nil {
		return e
	}
	if e = w.Close(); e != nil {
		return e
	}
	return f.Close()
}

func GenerateKeys(settingsPath, out string) error {
	var s Settings
	if e := ReadJSON(settingsPath, &s); e != nil {
		return e
	}
	p, e := s.Params()
	if e != nil {
		return e
	}
	if e = os.Mkdir(out, 0755); e != nil {
		return e
	}
	kg := rlwe.NewKeyGenerator(p)
	sk, pk := kg.GenKeyPairNew()
	rk := kg.GenRelinearizationKeyNew(sk)
	pt := ckks.NewPlaintext(p, p.MaxLevel())
	pt.Scale = ScaleBits(s.ScaleBits)
	ct, e := rlwe.NewEncryptor(p, pk).EncryptNew(pt)
	if e != nil {
		return e
	}
	for name, v := range map[string]interface{ MarshalBinary() ([]byte, error) }{"secret.key": sk, "public.key": pk, "relinearization.key": rk, "zero.ct": ct} {
		if e = writeBinary(filepath.Join(out, name), v); e != nil {
			return e
		}
	}
	hashes := map[string]string{}
	for _, name := range []string{"secret.key", "public.key", "relinearization.key", "zero.ct"} {
		hashes[name] = HashFile(filepath.Join(out, name))
	}
	return WriteJSON(filepath.Join(out, "manifest.json"), map[string]any{"schema": "paired-synthetic-experiment-key-family-v1", "settings_sha256": HashFile(settingsPath), "files": hashes, "purpose": "Fresh synthetic research keys and Enc(0). Within this replicate all configurations add their plaintext to the same Enc(0), pairing the encryption noise. Different replicate directories contain independent keys/noise. Secret key is intentionally retained for independent re-decryption of these synthetic experiment records."})
}
