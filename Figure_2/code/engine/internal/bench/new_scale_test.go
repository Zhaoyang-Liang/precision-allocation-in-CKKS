package bench

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestNewScaleWideExponentWire(t *testing.T) {
	p, err := (ParamSpec{LogN: 5, LogQ: []int{40, 39}, LogP: []int{41}, DefaultScaleBits: 30}).Build()
	if err != nil {
		t.Fatal(err)
	}
	// Public deterministic coefficients, no keys, encryption or HE evaluation.
	// Decimal exponent 99 -> 100 is the previously untested boundary.
	for _, exponent := range []int{-600, -340, 180, 332, 333, 378, 600} {
		ct := ckks.NewCiphertext(p, 1, p.MaxLevel())
		ct.Scale = scale(div(pow2(exponent), ri(17)))
		for k := range ct.Value {
			for l := range ct.Value[k].Coeffs {
				for j := range ct.Value[k].Coeffs[l] {
					ct.Value[k].Coeffs[l][j] = uint64(1 + k + l + j)
				}
			}
		}
		encoded, err := ct.Scale.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) != ct.Scale.BinarySize() {
			t.Fatalf("exponent %d: Scale size %d != actual %d", exponent, ct.Scale.BinarySize(), len(encoded))
		}
		_, read, _, err := wireCipher(p, ct)
		if err != nil {
			t.Fatalf("exponent %d: %v", exponent, err)
		}
		if scaleRat(read.Scale).Cmp(scaleRat(ct.Scale)) != 0 {
			t.Fatal("scale changed")
		}
		meta, err := ct.PlaintextMetaData.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		// Appended bytes must remain unread: JSON decoding must not consume
		// the following polynomial payload or rely on the receiver's scale.
		stream := bytes.NewBuffer(append(meta, []byte("following")...))
		var restored rlwe.PlaintextMetaData
		n, err := restored.ReadFrom(stream)
		if err != nil || int(n) != len(meta) || stream.String() != "following" {
			t.Fatalf("metadata framing: %d %v %q", n, err, stream.String())
		}
		if !restored.Equal(&ct.PlaintextMetaData) {
			t.Fatal("metadata changed")
		}
	}
}

func TestNewScaleHighPrecision(t *testing.T) {
	if rlwe.ScalePrecision < 768 {
		t.Fatal("new experiment requires high-precision metadata, including serialization")
	}
	v := new(big.Rat).SetFrac(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(65537))
	s := rlwe.NewScale(bf(v, 1024))
	for _, c := range []rlwe.Scale{s, s.Mul(rlwe.NewScale(3)).Div(rlwe.NewScale(3))} {
		w, e := c.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		var read rlwe.Scale
		if e = read.UnmarshalJSON(w); e != nil {
			t.Fatal(e)
		}
		if len(w) != c.BinarySize() {
			t.Fatal("metadata wire size mismatch")
		}
		delta := div(new(big.Rat).Abs(sub(scaleRat(read), v)), v)
		if delta.Cmp(pow2(-768)) > 0 {
			t.Fatal("insufficient relative precision after metadata roundtrip")
		}
	}
}

func TestNewScaleCiphertextRoundtrip(t *testing.T) {
	// Public zero ciphertext, no generated secret/public/evaluation keys.
	p, e := (ParamSpec{LogN: 5, LogQ: []int{40, 39}, LogP: []int{41}, DefaultScaleBits: 30}).Build()
	if e != nil {
		t.Fatal(e)
	}
	ct := ckks.NewCiphertext(p, 1, p.MaxLevel())
	ct.Scale = scale(div(pow2(180), ri(17)))
	for k := range ct.Value {
		for l := range ct.Value[k].Coeffs {
			for j := range ct.Value[k].Coeffs[l] {
				ct.Value[k].Coeffs[l][j] = uint64(1 + k + l + j)
			}
		}
	}
	cp := ct.CopyNew()
	if scaleRat(cp.Scale).Cmp(scaleRat(ct.Scale)) != 0 {
		t.Fatal("copy changed scale")
	}
	_, read, report, e := wireCipher(p, ct)
	if e != nil {
		t.Fatal(e)
	}
	if read.Scale.Value.Prec() != rlwe.ScalePrecision {
		t.Fatal("read scale precision lost")
	}
	if report.SerializedBytes <= report.PayloadBytes {
		t.Fatal("serialized metadata omitted from accounting")
	}
	if delta := div(new(big.Rat).Abs(sub(scaleRat(read.Scale), scaleRat(ct.Scale))), scaleRat(ct.Scale)); delta.Cmp(pow2(-768)) > 0 {
		t.Fatal("ciphertext wire roundtrip lost target precision")
	}
}
