// Copyright 2026 SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

// Package keyfile reads and writes khepra-pqc keys as PEM files.
//
// Private keys are stored in their FIPS 203 / FIPS 204 seed form. Files are
// written atomically; private key files are created with mode 0600 and, on
// systems with Unix permissions, refused on read if group or others can
// access them.
package keyfile

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/nouchix/khepra-pqc/kem"
	"github.com/nouchix/khepra-pqc/sign"
)

// PEM block types.
const (
	TypeKEMPrivateKey  = "KHEPRA ML-KEM-1024 PRIVATE KEY"
	TypeKEMPublicKey   = "KHEPRA ML-KEM-1024 PUBLIC KEY"
	TypeSignPrivateKey = "KHEPRA ML-DSA-87 PRIVATE KEY"
	TypeSignPublicKey  = "KHEPRA ML-DSA-87 PUBLIC KEY"
)

const (
	privateMode = 0o600
	publicMode  = 0o644
)

// WriteKEMPrivateKey writes a decapsulation key to path with mode 0600.
func WriteKEMPrivateKey(path string, k *kem.DecapsulationKey) error {
	return writeAtomic(path, encode(TypeKEMPrivateKey, k.Bytes()), privateMode)
}

// ReadKEMPrivateKey reads a decapsulation key written by WriteKEMPrivateKey.
func ReadKEMPrivateKey(path string) (*kem.DecapsulationKey, error) {
	der, err := readPrivate(path, TypeKEMPrivateKey)
	if err != nil {
		return nil, err
	}
	return kem.NewDecapsulationKey(der)
}

// WriteKEMPublicKey writes an encapsulation key to path.
func WriteKEMPublicKey(path string, k *kem.EncapsulationKey) error {
	return writeAtomic(path, EncodeKEMPublicKey(k), publicMode)
}

// ReadKEMPublicKey reads an encapsulation key written by WriteKEMPublicKey.
func ReadKEMPublicKey(path string) (*kem.EncapsulationKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	return DecodeKEMPublicKey(data)
}

// EncodeKEMPublicKey returns the PEM encoding of an encapsulation key.
func EncodeKEMPublicKey(k *kem.EncapsulationKey) []byte {
	return encode(TypeKEMPublicKey, k.Bytes())
}

// DecodeKEMPublicKey parses the PEM encoding of an encapsulation key.
func DecodeKEMPublicKey(data []byte) (*kem.EncapsulationKey, error) {
	der, err := decode(data, TypeKEMPublicKey)
	if err != nil {
		return nil, err
	}
	return kem.NewEncapsulationKey(der)
}

// WriteSigningKey writes a signing key to path with mode 0600.
func WriteSigningKey(path string, k *sign.PrivateKey) error {
	return writeAtomic(path, encode(TypeSignPrivateKey, k.Bytes()), privateMode)
}

// ReadSigningKey reads a signing key written by WriteSigningKey.
func ReadSigningKey(path string) (*sign.PrivateKey, error) {
	der, err := readPrivate(path, TypeSignPrivateKey)
	if err != nil {
		return nil, err
	}
	return sign.NewPrivateKey(der)
}

// WriteVerifyingKey writes a signature verification key to path.
func WriteVerifyingKey(path string, k *sign.PublicKey) error {
	return writeAtomic(path, EncodeVerifyingKey(k), publicMode)
}

// ReadVerifyingKey reads a verification key written by WriteVerifyingKey.
func ReadVerifyingKey(path string) (*sign.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	return DecodeVerifyingKey(data)
}

// EncodeVerifyingKey returns the PEM encoding of a verification key.
func EncodeVerifyingKey(k *sign.PublicKey) []byte {
	return encode(TypeSignPublicKey, k.Bytes())
}

// DecodeVerifyingKey parses the PEM encoding of a verification key.
func DecodeVerifyingKey(data []byte) (*sign.PublicKey, error) {
	der, err := decode(data, TypeSignPublicKey)
	if err != nil {
		return nil, err
	}
	return sign.NewPublicKey(der)
}

func encode(blockType string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: b})
}

func decode(data []byte, blockType string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("keyfile: no PEM block found")
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("keyfile: PEM block is %q, want %q", block.Type, blockType)
	}
	return block.Bytes, nil
}

func readPrivate(path, blockType string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keyfile: %s is accessible to group or others (mode %v); chmod 600 it", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	return decode(data, blockType)
}

// writeAtomic writes data to a temporary file beside path and renames it into
// place, so a crash never leaves a truncated key behind.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keyfile-*")
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := tmp.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return fmt.Errorf("keyfile: chmod: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("keyfile: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("keyfile: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keyfile: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("keyfile: rename: %w", err)
	}
	return nil
}
