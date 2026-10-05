// Copyright 2026 SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

// Package kdf provides the approved key derivation functions used across
// KHEPRA: HKDF-SHA-384 (SP 800-56C Rev 2) for keys derived from shared
// secrets, and PBKDF2-HMAC-SHA-384 (SP 800-132) for keys derived from
// passphrases. Both come from the Go Cryptographic Module.
package kdf

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
)

const (
	// PBKDF2Iterations is the iteration count for passphrase-derived keys.
	PBKDF2Iterations = 600_000
	// SaltSize is the size of salts produced by NewSalt.
	SaltSize = 32
	// minSaltSize is the SP 800-132 minimum salt length (128 bits).
	minSaltSize = 16
)

// HKDFSHA384 derives keyLength bytes from secret using HKDF-SHA-384
// (extract-then-expand, SP 800-56C Rev 2). info binds the key to its purpose
// and must differ between purposes.
func HKDFSHA384(secret, salt []byte, info string, keyLength int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("kdf: HKDF secret is empty")
	}
	key, err := hkdf.Key(sha512.New384, secret, salt, info, keyLength)
	if err != nil {
		return nil, fmt.Errorf("kdf: HKDF-SHA-384: %w", err)
	}
	return key, nil
}

// PassphraseKey derives keyLength bytes from a passphrase with
// PBKDF2-HMAC-SHA-384. Use a fresh salt from NewSalt for every key and store
// it alongside the protected data.
func PassphraseKey(passphrase string, salt []byte, keyLength int) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("kdf: passphrase is empty")
	}
	if len(salt) < minSaltSize {
		return nil, fmt.Errorf("kdf: salt must be at least %d bytes, got %d", minSaltSize, len(salt))
	}
	key, err := pbkdf2.Key(sha512.New384, passphrase, salt, PBKDF2Iterations, keyLength)
	if err != nil {
		return nil, fmt.Errorf("kdf: PBKDF2-HMAC-SHA-384: %w", err)
	}
	return key, nil
}

// NewSalt returns SaltSize random bytes from the module's approved random bit
// generator.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("kdf: generate salt: %w", err)
	}
	return salt, nil
}
