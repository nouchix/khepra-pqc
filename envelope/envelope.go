// Copyright 2026 SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

// Package envelope implements the KHEPRA v3 sealed envelope: ML-KEM-1024
// key encapsulation, HKDF-SHA-384 key derivation and AES-256-GCM, with the
// whole header authenticated.
//
// Wire format (all integers big-endian):
//
//	magic   "KHQ3"                      4 bytes
//	suite   uint16                      2 bytes  (SuiteMLKEM1024HKDFSHA384AES256GCM)
//	keyID   SHA-384(ek)[:16]            16 bytes
//	kemCT   ML-KEM-1024 ciphertext      1568 bytes
//	nonce                               12 bytes
//	ct‖tag  AES-256-GCM output          len(plaintext) + 16 bytes
//
// AES-256-GCM key = HKDF-SHA-384(ikm = shared secret, salt = keyID,
// info = magic ‖ suite ‖ kemCT ‖ label). The additional authenticated data is
// magic ‖ suite ‖ keyID ‖ kemCT, so truncating, swapping or replacing any
// header field makes Open fail.
//
// The label binds an envelope to its purpose (for example
// "khepra/v3/upstream-store"). Open must be given the same label.
package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/nouchix/khepra-pqc/kdf"
	"github.com/nouchix/khepra-pqc/kem"
)

// SuiteMLKEM1024HKDFSHA384AES256GCM is the only suite currently defined.
const SuiteMLKEM1024HKDFSHA384AES256GCM uint16 = 0x0101

const (
	magic     = "KHQ3"
	keyIDSize = 16
	nonceSize = 12
	tagSize   = 16
	aesKeyLen = 32

	offSuite = len(magic)
	offKeyID = offSuite + 2
	offKEMCT = offKeyID + keyIDSize
	offNonce = offKEMCT + kem.CiphertextSize
	offBody  = offNonce + nonceSize

	// Overhead is the number of bytes an envelope adds to its plaintext.
	Overhead = offBody + tagSize
)

var (
	// ErrNotEnvelope means the input does not start with the v3 magic. Data
	// sealed by an older format reaches this error.
	ErrNotEnvelope = errors.New("envelope: not a KHQ3 envelope")
	// ErrUnsupportedSuite means the envelope names a suite this version does
	// not implement.
	ErrUnsupportedSuite = errors.New("envelope: unsupported suite")
	// ErrWrongRecipient means the envelope was sealed to a different key.
	ErrWrongRecipient = errors.New("envelope: sealed to a different key")
	// ErrDecrypt means authentication failed: the envelope was modified,
	// truncated, or opened with the wrong label.
	ErrDecrypt = errors.New("envelope: authentication failed")
)

// KeyID returns the 16-byte identifier of an encapsulation key: the first 16
// bytes of SHA-384 over its encoding.
func KeyID(ek *kem.EncapsulationKey) []byte {
	sum := sha512.Sum384(ek.Bytes())
	return sum[:keyIDSize]
}

// IsEnvelope reports whether b starts with the v3 magic.
func IsEnvelope(b []byte) bool {
	return len(b) >= len(magic) && string(b[:len(magic)]) == magic
}

// Seal encrypts plaintext to the holder of the decapsulation key that pairs
// with ek.
func Seal(ek *kem.EncapsulationKey, label string, plaintext []byte) ([]byte, error) {
	sharedKey, kemCT := ek.Encapsulate()

	out := make([]byte, offBody, offBody+len(plaintext)+tagSize)
	copy(out, magic)
	binary.BigEndian.PutUint16(out[offSuite:], SuiteMLKEM1024HKDFSHA384AES256GCM)
	copy(out[offKeyID:], KeyID(ek))
	copy(out[offKEMCT:], kemCT)
	header := bytes.Clone(out[:offNonce])

	aead, err := newAEAD(sharedKey, header, label)
	if err != nil {
		return nil, err
	}
	// The module generates the 96-bit GCM nonce itself (SP 800-38D §8.2.2)
	// and prepends it to the ciphertext, which places it at offNonce.
	return aead.Seal(out[:offNonce], nil, plaintext, header), nil
}

// Open decrypts an envelope produced by Seal.
func Open(dk *kem.DecapsulationKey, label string, sealed []byte) ([]byte, error) {
	if !IsEnvelope(sealed) {
		return nil, ErrNotEnvelope
	}
	if len(sealed) < Overhead {
		return nil, fmt.Errorf("%w: envelope is %d bytes, shorter than the %d-byte minimum", ErrDecrypt, len(sealed), Overhead)
	}
	if suite := binary.BigEndian.Uint16(sealed[offSuite:]); suite != SuiteMLKEM1024HKDFSHA384AES256GCM {
		return nil, fmt.Errorf("%w: 0x%04x", ErrUnsupportedSuite, suite)
	}
	if !bytes.Equal(sealed[offKeyID:offKEMCT], KeyID(dk.EncapsulationKey())) {
		return nil, ErrWrongRecipient
	}

	sharedKey, err := dk.Decapsulate(sealed[offKEMCT:offNonce])
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	aead, err := newAEAD(sharedKey, sealed[:offNonce], label)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, sealed[offNonce:], sealed[:offNonce])
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// newAEAD derives the AES-256-GCM key for an envelope. header is
// magic ‖ suite ‖ keyID ‖ kemCT.
func newAEAD(sharedKey, header []byte, label string) (cipher.AEAD, error) {
	info := make([]byte, 0, len(magic)+2+kem.CiphertextSize+len(label))
	info = append(info, header[:offKeyID]...)         // magic ‖ suite
	info = append(info, header[offKEMCT:offNonce]...) // kemCT
	info = append(info, label...)
	key, err := kdf.HKDFSHA384(sharedKey, header[offKeyID:offKEMCT], string(info), aesKeyLen)
	if err != nil {
		return nil, fmt.Errorf("envelope: derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: GCM: %w", err)
	}
	return aead, nil
}
