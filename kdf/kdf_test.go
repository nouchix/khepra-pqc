package kdf

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha512"
	"testing"
)

func TestHKDFMatchesExtractExpand(t *testing.T) {
	secret := bytes.Repeat([]byte{0x0b}, 32)
	salt := []byte("salt")
	got, err := HKDFSHA384(secret, salt, "khepra/v3/test", 32)
	if err != nil {
		t.Fatal(err)
	}
	prk, _ := hkdf.Extract(sha512.New384, secret, salt)
	want, _ := hkdf.Expand(sha512.New384, prk, "khepra/v3/test", 32)
	if !bytes.Equal(got, want) {
		t.Fatal("HKDFSHA384 differs from Extract+Expand")
	}
}

func TestHKDFSeparatesPurposes(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	a, _ := HKDFSHA384(secret, nil, "purpose-a", 32)
	b, _ := HKDFSHA384(secret, nil, "purpose-b", 32)
	if bytes.Equal(a, b) {
		t.Fatal("different info produced the same key")
	}
	if _, err := HKDFSHA384(nil, nil, "x", 32); err == nil {
		t.Fatal("empty secret accepted")
	}
}

func TestPassphraseKey(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	a, err := PassphraseKey("correct horse battery staple", salt, 32)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := PassphraseKey("correct horse battery staple", salt, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("PBKDF2 is not deterministic for the same inputs")
	}
	other, _ := NewSalt()
	c, _ := PassphraseKey("correct horse battery staple", other, 32)
	if bytes.Equal(a, c) {
		t.Fatal("different salts produced the same key")
	}
	if _, err := PassphraseKey("", salt, 32); err == nil {
		t.Error("empty passphrase accepted")
	}
	if _, err := PassphraseKey("p", make([]byte, 8), 32); err == nil {
		t.Error("8-byte salt accepted")
	}
}
