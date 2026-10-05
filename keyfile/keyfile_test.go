package keyfile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nouchix/khepra-pqc/kem"
	"github.com/nouchix/khepra-pqc/sign"
)

func TestKEMKeysRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dk, _ := kem.GenerateKey()
	priv := filepath.Join(dir, "kem.key")
	pub := filepath.Join(dir, "kem.pub")
	if err := WriteKEMPrivateKey(priv, dk); err != nil {
		t.Fatal(err)
	}
	if err := WriteKEMPublicKey(pub, dk.EncapsulationKey()); err != nil {
		t.Fatal(err)
	}
	gotDK, err := ReadKEMPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	gotEK, err := ReadKEMPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDK.Bytes(), dk.Bytes()) || !bytes.Equal(gotEK.Bytes(), dk.EncapsulationKey().Bytes()) {
		t.Fatal("round trip mismatch")
	}
}

func TestSigningKeysRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sk, _ := sign.GenerateKey()
	priv := filepath.Join(dir, "sign.key")
	pub := filepath.Join(dir, "sign.pub")
	if err := WriteSigningKey(priv, sk); err != nil {
		t.Fatal(err)
	}
	if err := WriteVerifyingKey(pub, sk.PublicKey()); err != nil {
		t.Fatal(err)
	}
	gotSK, err := ReadSigningKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	gotPK, err := ReadVerifyingKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSK.Bytes(), sk.Bytes()) || !bytes.Equal(gotPK.Bytes(), sk.PublicKey().Bytes()) {
		t.Fatal("round trip mismatch")
	}
	data, _ := os.ReadFile(pub)
	if !strings.Contains(string(data), TypeSignPublicKey) {
		t.Fatalf("public key file does not carry its PEM type:\n%s", data)
	}
}

func TestRejectsWrongBlockType(t *testing.T) {
	sk, _ := sign.GenerateKey()
	if _, err := DecodeKEMPublicKey(EncodeVerifyingKey(sk.PublicKey())); err == nil {
		t.Fatal("ML-DSA public key accepted as an ML-KEM public key")
	}
}

func TestPrivateKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sign.key")
	sk, _ := sign.GenerateKey()
	if err := WriteSigningKey(path, sk); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key written with mode %v", info.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSigningKey(path); err == nil {
		t.Fatal("world-readable private key accepted")
	}
}

func TestWriteLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	dk, _ := kem.GenerateKey()
	if err := WriteKEMPrivateKey(filepath.Join(dir, "kem.key"), dk); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries after write, want 1", len(entries))
	}
}
