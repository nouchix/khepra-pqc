// Copyright 2026 SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

// Package kem provides ML-KEM-1024 (FIPS 203) key encapsulation.
//
// It wraps the Go standard library's crypto/mlkem, which is part of the Go
// Cryptographic Module (FIPS 140-3). ML-KEM-1024 is the parameter set the
// CNSA 2.0 suite requires; no other parameter set is offered.
//
// Decapsulation keys are stored and exchanged in the 64-byte seed form
// (d ‖ z) defined by FIPS 203. Keys are generated only from the module's
// approved random bit generator; there is no way to derive one from a
// caller-chosen value other than a previously generated seed.
package kem

import (
	"crypto/mlkem"
	"fmt"
)

const (
	// EncapsulationKeySize is the size of an ML-KEM-1024 encapsulation key.
	EncapsulationKeySize = mlkem.EncapsulationKeySize1024
	// CiphertextSize is the size of an ML-KEM-1024 ciphertext.
	CiphertextSize = mlkem.CiphertextSize1024
	// SharedKeySize is the size of the shared secret.
	SharedKeySize = mlkem.SharedKeySize
	// SeedSize is the size of a decapsulation key in seed form.
	SeedSize = mlkem.SeedSize
)

// DecapsulationKey is an ML-KEM-1024 private key.
type DecapsulationKey struct {
	dk *mlkem.DecapsulationKey1024
}

// EncapsulationKey is an ML-KEM-1024 public key.
type EncapsulationKey struct {
	ek *mlkem.EncapsulationKey1024
}

// GenerateKey generates a new decapsulation key using the module's approved
// random bit generator.
func GenerateKey() (*DecapsulationKey, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("kem: generate ML-KEM-1024 key: %w", err)
	}
	return &DecapsulationKey{dk: dk}, nil
}

// NewDecapsulationKey restores a decapsulation key from its 64-byte seed, as
// returned by Bytes.
func NewDecapsulationKey(seed []byte) (*DecapsulationKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("kem: decapsulation key seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, fmt.Errorf("kem: decode decapsulation key: %w", err)
	}
	return &DecapsulationKey{dk: dk}, nil
}

// Bytes returns the decapsulation key in its 64-byte seed form. Treat it as
// secret key material.
func (k *DecapsulationKey) Bytes() []byte {
	return k.dk.Bytes()
}

// EncapsulationKey returns the public key that pairs with k.
func (k *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	return &EncapsulationKey{ek: k.dk.EncapsulationKey()}
}

// Decapsulate recovers the shared secret from a ciphertext. Per FIPS 203,
// a malformed but correctly sized ciphertext yields a pseudorandom secret
// rather than an error, so callers must authenticate whatever the secret
// protects (envelope does this with AES-256-GCM).
func (k *DecapsulationKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("kem: ciphertext must be %d bytes, got %d", CiphertextSize, len(ciphertext))
	}
	sharedKey, err := k.dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("kem: decapsulate: %w", err)
	}
	return sharedKey, nil
}

// NewEncapsulationKey parses an encapsulation key. It performs the FIPS 203
// encapsulation key check and rejects keys that fail it.
func NewEncapsulationKey(b []byte) (*EncapsulationKey, error) {
	if len(b) != EncapsulationKeySize {
		return nil, fmt.Errorf("kem: encapsulation key must be %d bytes, got %d", EncapsulationKeySize, len(b))
	}
	ek, err := mlkem.NewEncapsulationKey1024(b)
	if err != nil {
		return nil, fmt.Errorf("kem: decode encapsulation key: %w", err)
	}
	return &EncapsulationKey{ek: ek}, nil
}

// Bytes returns the encoded encapsulation key.
func (k *EncapsulationKey) Bytes() []byte {
	return k.ek.Bytes()
}

// Encapsulate generates a shared secret and the ciphertext that carries it to
// the holder of the matching decapsulation key.
func (k *EncapsulationKey) Encapsulate() (sharedKey, ciphertext []byte) {
	return k.ek.Encapsulate()
}
