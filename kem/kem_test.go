package kem

import (
	"bytes"
	"crypto/fips140"
	"crypto/mlkem/mlkemtest"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type acvpKEM struct {
	KeyGen []struct {
		TcID int    `json:"tcId"`
		D    string `json:"d"`
		Z    string `json:"z"`
		EK   string `json:"ek"`
	} `json:"keyGen"`
	Encapsulation []struct {
		TcID int    `json:"tcId"`
		EK   string `json:"ek"`
		M    string `json:"m"`
		C    string `json:"c"`
		K    string `json:"k"`
	} `json:"encapsulation"`
	EncapsulationKeyCheck []struct {
		TcID       int    `json:"tcId"`
		EK         string `json:"ek"`
		TestPassed bool   `json:"testPassed"`
	} `json:"encapsulationKeyCheck"`
}

func loadACVP(t *testing.T) acvpKEM {
	t.Helper()
	data, err := os.ReadFile("testdata/acvp_mlkem1024.json")
	if err != nil {
		t.Fatal(err)
	}
	var v acvpKEM
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

// FIPS 203 keyGen: the seed d ‖ z must produce the expected encapsulation key.
func TestACVPKeyGen(t *testing.T) {
	v := loadACVP(t)
	if len(v.KeyGen) == 0 {
		t.Fatal("no keyGen vectors")
	}
	for _, tc := range v.KeyGen {
		seed := append(mustHex(t, tc.D), mustHex(t, tc.Z)...)
		dk, err := NewDecapsulationKey(seed)
		if err != nil {
			t.Fatalf("tcId %d: %v", tc.TcID, err)
		}
		if !bytes.Equal(dk.EncapsulationKey().Bytes(), mustHex(t, tc.EK)) {
			t.Errorf("tcId %d: encapsulation key mismatch", tc.TcID)
		}
		if !bytes.Equal(dk.Bytes(), seed) {
			t.Errorf("tcId %d: Bytes() did not return the seed", tc.TcID)
		}
	}
}

// FIPS 203 encapsulation with a fixed message m must produce the expected
// ciphertext and shared key.
func TestACVPEncapsulation(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("derandomized encapsulation is a test-only hook that fips140=only forbids")
	}
	v := loadACVP(t)
	if len(v.Encapsulation) == 0 {
		t.Fatal("no encapsulation vectors")
	}
	for _, tc := range v.Encapsulation {
		ek, err := NewEncapsulationKey(mustHex(t, tc.EK))
		if err != nil {
			t.Fatalf("tcId %d: %v", tc.TcID, err)
		}
		k, c, err := mlkemtest.Encapsulate1024(ek.ek, mustHex(t, tc.M))
		if err != nil {
			t.Fatalf("tcId %d: %v", tc.TcID, err)
		}
		if !bytes.Equal(c, mustHex(t, tc.C)) {
			t.Errorf("tcId %d: ciphertext mismatch", tc.TcID)
		}
		if !bytes.Equal(k, mustHex(t, tc.K)) {
			t.Errorf("tcId %d: shared key mismatch", tc.TcID)
		}
	}
}

// FIPS 203 §7.2 encapsulation key check: invalid keys must be rejected.
func TestACVPEncapsulationKeyCheck(t *testing.T) {
	v := loadACVP(t)
	if len(v.EncapsulationKeyCheck) == 0 {
		t.Fatal("no encapsulationKeyCheck vectors")
	}
	for _, tc := range v.EncapsulationKeyCheck {
		_, err := NewEncapsulationKey(mustHex(t, tc.EK))
		if got := err == nil; got != tc.TestPassed {
			t.Errorf("tcId %d: accepted=%v, want %v (err=%v)", tc.TcID, got, tc.TestPassed, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := NewEncapsulationKey(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ss, ct := ek.Encapsulate()
	if len(ct) != CiphertextSize || len(ss) != SharedKeySize {
		t.Fatalf("sizes: ct=%d ss=%d", len(ct), len(ss))
	}
	restored, err := NewDecapsulationKey(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ss) {
		t.Fatal("shared secrets differ")
	}
}

func TestGenerateKeyIsRandom(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two generated keys share a seed")
	}
}

func TestRejectsWrongSizes(t *testing.T) {
	if _, err := NewDecapsulationKey(make([]byte, SeedSize-1)); err == nil {
		t.Error("short seed accepted")
	}
	if _, err := NewEncapsulationKey(make([]byte, EncapsulationKeySize+1)); err == nil {
		t.Error("long encapsulation key accepted")
	}
	dk, _ := GenerateKey()
	if _, err := dk.Decapsulate(make([]byte, CiphertextSize-1)); err == nil {
		t.Error("short ciphertext accepted")
	}
}
