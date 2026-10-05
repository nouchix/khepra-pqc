package sign

import (
	"bytes"
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type acvpDSA struct {
	KeyGen87 []keyGenVector `json:"keyGen87"`
	KeyGen65 []keyGenVector `json:"keyGen65"`
	SigVer87 []sigVerVector `json:"sigVer87"`
	SigVer65 []sigVerVector `json:"sigVer65"`
}

type keyGenVector struct {
	TcID int    `json:"tcId"`
	Seed string `json:"seed"`
	PK   string `json:"pk"`
}

type sigVerVector struct {
	TcID       int    `json:"tcId"`
	PK         string `json:"pk"`
	Message    string `json:"message"`
	Context    string `json:"context"`
	Signature  string `json:"signature"`
	TestPassed bool   `json:"testPassed"`
	Reason     string `json:"reason"`
}

func loadACVP(t *testing.T) acvpDSA {
	t.Helper()
	data, err := os.ReadFile("testdata/acvp_mldsa.json")
	if err != nil {
		t.Fatal(err)
	}
	var v acvpDSA
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test vector: %v", err)
	}
	return b
}

// FIPS 204 keyGen for ML-DSA-87: the seed must produce the expected public key.
func TestACVPKeyGen87(t *testing.T) {
	v := loadACVP(t)
	if len(v.KeyGen87) == 0 {
		t.Fatal("no ML-DSA-87 keyGen vectors")
	}
	for _, tc := range v.KeyGen87 {
		seed := mustHex(t, tc.Seed)
		sk, err := NewPrivateKey(seed)
		if err != nil {
			t.Fatalf("tcId %d: %v", tc.TcID, err)
		}
		if !bytes.Equal(sk.PublicKey().Bytes(), mustHex(t, tc.PK)) {
			t.Errorf("tcId %d: public key mismatch", tc.TcID)
		}
		if !bytes.Equal(sk.Bytes(), seed) {
			t.Errorf("tcId %d: Bytes() did not return the seed", tc.TcID)
		}
	}
}

// The verify-only ML-DSA-65 path decodes keys the same way the module does.
func TestACVPKeyGen65(t *testing.T) {
	v := loadACVP(t)
	for _, tc := range v.KeyGen65 {
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mustHex(t, tc.Seed))
		if err != nil {
			t.Fatalf("tcId %d: %v", tc.TcID, err)
		}
		if !bytes.Equal(sk.PublicKey().Bytes(), mustHex(t, tc.PK)) {
			t.Errorf("tcId %d: public key mismatch", tc.TcID)
		}
	}
}

// FIPS 204 sigVer (external interface, pure ML-DSA, arbitrary contexts).
func TestACVPSigVer87(t *testing.T) {
	v := loadACVP(t)
	if len(v.SigVer87) == 0 {
		t.Fatal("no ML-DSA-87 sigVer vectors")
	}
	for _, tc := range v.SigVer87 {
		pk, err := NewPublicKey(mustHex(t, tc.PK))
		if err != nil {
			t.Fatalf("tcId %d: %v", tc.TcID, err)
		}
		err = verify(pk.pk, string(mustHex(t, tc.Context)), mustHex(t, tc.Message), mustHex(t, tc.Signature))
		if got := err == nil; got != tc.TestPassed {
			t.Errorf("tcId %d (%s): verified=%v, want %v", tc.TcID, tc.Reason, got, tc.TestPassed)
		}
	}
}

func TestACVPSigVer65(t *testing.T) {
	v := loadACVP(t)
	if len(v.SigVer65) == 0 {
		t.Fatal("no ML-DSA-65 sigVer vectors")
	}
	for _, tc := range v.SigVer65 {
		err := VerifyMLDSA65(mustHex(t, tc.PK), string(mustHex(t, tc.Context)), mustHex(t, tc.Message), mustHex(t, tc.Signature))
		if got := err == nil; got != tc.TestPassed {
			t.Errorf("tcId %d (%s): verified=%v, want %v", tc.TcID, tc.Reason, got, tc.TestPassed)
		}
	}
}

func TestSignVerify(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("license payload")
	sig, err := sk.Sign(ContextLicense, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), SignatureSize)
	}
	pk, err := NewPublicKey(sk.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := pk.Verify(ContextLicense, msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := pk.Verify(ContextLicense, []byte("license payloaD"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("modified message: got %v", err)
	}
}

// A signature made for one purpose must not verify for another.
func TestContextSeparation(t *testing.T) {
	sk, _ := GenerateKey()
	msg := []byte("same bytes")
	sig, err := sk.Sign(ContextDAG, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sk.PublicKey().Verify(ContextLicense, msg, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("DAG signature verified as a license: %v", err)
	}
}

func TestLabelledContext(t *testing.T) {
	eban, err := ContextToken.WithLabel("Eban")
	if err != nil {
		t.Fatal(err)
	}
	if eban != "khepra/v3/token/Eban" {
		t.Fatalf("got %q", eban)
	}
	sk, _ := GenerateKey()
	sig, _ := sk.Sign(eban, []byte("t"))
	other, _ := ContextToken.WithLabel("Fawohodie")
	if err := sk.PublicKey().Verify(other, []byte("t"), sig); err == nil {
		t.Fatal("signature verified under a different symbol label")
	}
	for _, bad := range []string{"", "a/b", "with space", strings.Repeat("x", 300)} {
		if _, err := ContextToken.WithLabel(bad); err == nil {
			t.Errorf("label %q accepted", bad)
		}
	}
}

func TestRejectsUnregisteredContext(t *testing.T) {
	sk, _ := GenerateKey()
	for _, ctx := range []Context{"", "license", "khepra/v3/", "khepra/v2/license"} {
		if _, err := sk.Sign(ctx, []byte("m")); err == nil {
			t.Errorf("Sign accepted context %q", ctx)
		}
	}
}

func TestRejectsWrongSizes(t *testing.T) {
	if _, err := NewPrivateKey(make([]byte, SeedSize+1)); err == nil {
		t.Error("long seed accepted")
	}
	if _, err := NewPublicKey(make([]byte, mldsa.MLDSA65PublicKeySize)); err == nil {
		t.Error("ML-DSA-65-sized key accepted as ML-DSA-87")
	}
	sk, _ := GenerateKey()
	if err := sk.PublicKey().Verify(ContextDAG, []byte("m"), make([]byte, SignatureSize-1)); err == nil {
		t.Error("short signature accepted")
	}
}

func TestFingerprintIsStable(t *testing.T) {
	sk, _ := GenerateKey()
	pk, _ := NewPublicKey(sk.PublicKey().Bytes())
	if sk.PublicKey().Fingerprint() != pk.Fingerprint() || len(pk.Fingerprint()) != 32 {
		t.Fatalf("fingerprint unstable or wrong length: %q", pk.Fingerprint())
	}
}
