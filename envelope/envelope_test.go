package envelope

import (
	"bytes"
	"errors"
	"testing"

	"github.com/nouchix/khepra-pqc/kem"
)

const label = "khepra/v3/test"

func newKey(t testing.TB) *kem.DecapsulationKey {
	t.Helper()
	dk, err := kem.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return dk
}

func mustSeal(t testing.TB, dk *kem.DecapsulationKey, pt []byte) []byte {
	t.Helper()
	sealed, err := Seal(dk.EncapsulationKey(), label, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

func TestRoundTrip(t *testing.T) {
	dk := newKey(t)
	for _, pt := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte("khepra"), 10000)} {
		sealed, err := Seal(dk.EncapsulationKey(), label, pt)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != Overhead+len(pt) {
			t.Fatalf("envelope is %d bytes, want %d", len(sealed), Overhead+len(pt))
		}
		got, err := Open(dk, label, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("plaintext mismatch")
		}
	}
}

func TestSealIsRandomized(t *testing.T) {
	dk := newKey(t)
	a := mustSeal(t, dk, []byte("same"))
	b := mustSeal(t, dk, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical")
	}
}

func TestWrongLabel(t *testing.T) {
	dk := newKey(t)
	sealed := mustSeal(t, dk, []byte("secret"))
	if _, err := Open(dk, "khepra/v3/other", sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestWrongRecipient(t *testing.T) {
	dk := newKey(t)
	sealed := mustSeal(t, dk, []byte("secret"))
	if _, err := Open(newKey(t), label, sealed); !errors.Is(err, ErrWrongRecipient) {
		t.Fatalf("got %v, want ErrWrongRecipient", err)
	}
}

// Flipping any byte of the envelope must make Open fail with the error that
// matches the field.
func TestTamperEveryField(t *testing.T) {
	dk := newKey(t)
	sealed := mustSeal(t, dk, []byte("tamper-evident payload"))
	cases := []struct {
		name string
		off  int
		want error
	}{
		{"magic", 0, ErrNotEnvelope},
		{"suite", offSuite + 1, ErrUnsupportedSuite},
		{"keyID", offKeyID, ErrWrongRecipient},
		{"kemCT", offKEMCT + 100, ErrDecrypt},
		{"nonce", offNonce, ErrDecrypt},
		{"ciphertext", offBody, ErrDecrypt},
		{"tag", len(sealed) - 1, ErrDecrypt},
	}
	for _, tc := range cases {
		mod := bytes.Clone(sealed)
		mod[tc.off] ^= 0x01
		if _, err := Open(dk, label, mod); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestTruncation(t *testing.T) {
	dk := newKey(t)
	sealed := mustSeal(t, dk, []byte("payload"))
	for _, n := range []int{0, 3, 4, offKEMCT, offBody, Overhead - 1, len(sealed) - 1} {
		if _, err := Open(dk, label, sealed[:n]); err == nil {
			t.Errorf("truncated to %d bytes: Open succeeded", n)
		}
	}
}

func TestLegacyDataIsNotAnEnvelope(t *testing.T) {
	dk := newKey(t)
	legacy := bytes.Repeat([]byte{0xAB}, 4000)
	if IsEnvelope(legacy) {
		t.Fatal("legacy blob detected as envelope")
	}
	if _, err := Open(dk, label, legacy); !errors.Is(err, ErrNotEnvelope) {
		t.Fatalf("got %v, want ErrNotEnvelope", err)
	}
}

func FuzzOpen(f *testing.F) {
	dk := newKey(f)
	sealed := mustSeal(f, dk, []byte("seed corpus"))
	f.Add(sealed)
	f.Add([]byte("KHQ3"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		pt, err := Open(dk, label, data)
		if err == nil && !bytes.Equal(data, sealed) {
			// Only an authentic envelope may open.
			resealed := bytes.Equal(pt, []byte("seed corpus"))
			if !resealed {
				t.Fatalf("Open accepted forged input of %d bytes", len(data))
			}
		}
	})
}
