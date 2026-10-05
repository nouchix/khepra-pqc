// Copyright 2026 SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

// Package sign provides ML-DSA-87 (FIPS 204) signatures.
//
// It wraps the Go standard library's crypto/mldsa, which is part of the Go
// Cryptographic Module (FIPS 140-3, module v1.26.0 and later). ML-DSA-87 is
// the parameter set the CNSA 2.0 suite requires.
//
// Every signature carries a FIPS 204 context string from the Context
// registry. A signature made for one purpose (a license, a DAG node, a
// token) therefore never verifies for another. Private keys are stored in
// the 32-byte seed form defined by FIPS 204.
package sign

import (
	"crypto/mldsa"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// PublicKeySize is the size of an ML-DSA-87 public key.
	PublicKeySize = mldsa.MLDSA87PublicKeySize
	// SignatureSize is the size of an ML-DSA-87 signature.
	SignatureSize = mldsa.MLDSA87SignatureSize
	// SeedSize is the size of a private key in seed form.
	SeedSize = mldsa.PrivateKeySize
)

// Context is a FIPS 204 context string. Use one of the registered values,
// optionally narrowed with WithLabel.
type Context string

// Registered contexts. Add new purposes here rather than inventing strings at
// call sites, so that no two purposes can share a context by accident.
const (
	ContextLicense   Context = "khepra/v3/license"
	ContextAPIKey    Context = "khepra/v3/apikey"
	ContextDAG       Context = "khepra/v3/dag"
	ContextAttest    Context = "khepra/v3/attest"
	ContextToken     Context = "khepra/v3/token"
	ContextTelemetry Context = "khepra/v3/telemetry"
	ContextRelease   Context = "khepra/v3/release"
	ContextManifest  Context = "khepra/v3/manifest"
	ContextEnvelope  Context = "khepra/v3/envelope"
	ContextKEMCert   Context = "khepra/v3/kemcert"
	// ContextAdinkra is used by the adinkra package's general-purpose Sign
	// API. Prefer a purpose-specific context in new code.
	ContextAdinkra Context = "khepra/v3/adinkra"
)

const contextPrefix = "khepra/v3/"

// maxContextSize is the FIPS 204 limit on context strings.
const maxContextSize = 255

// ErrInvalidSignature is returned when a signature does not verify.
var ErrInvalidSignature = errors.New("sign: signature verification failed")

// WithLabel narrows c with a label, for example an Adinkra symbol:
// ContextToken.WithLabel("Eban") is "khepra/v3/token/Eban". The label must
// be printable ASCII without '/'.
func (c Context) WithLabel(label string) (Context, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	if label == "" {
		return "", errors.New("sign: context label is empty")
	}
	for _, r := range label {
		if r < 0x21 || r > 0x7e || r == '/' {
			return "", fmt.Errorf("sign: context label %q must be printable ASCII without '/'", label)
		}
	}
	out := Context(string(c) + "/" + label)
	if err := out.validate(); err != nil {
		return "", err
	}
	return out, nil
}

func (c Context) validate() error {
	if !strings.HasPrefix(string(c), contextPrefix) || len(c) == len(contextPrefix) {
		return fmt.Errorf("sign: context %q is not a registered khepra/v3 context", string(c))
	}
	if len(c) > maxContextSize {
		return fmt.Errorf("sign: context is %d bytes; FIPS 204 allows at most %d", len(c), maxContextSize)
	}
	return nil
}

// PrivateKey is an ML-DSA-87 private key.
type PrivateKey struct {
	sk *mldsa.PrivateKey
}

// PublicKey is an ML-DSA-87 public key.
type PublicKey struct {
	pk *mldsa.PublicKey
}

// GenerateKey generates a new private key using the module's approved random
// bit generator.
func GenerateKey() (*PrivateKey, error) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, fmt.Errorf("sign: generate ML-DSA-87 key: %w", err)
	}
	return &PrivateKey{sk: sk}, nil
}

// NewPrivateKey restores a private key from its 32-byte seed, as returned by
// Bytes.
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("sign: private key seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		return nil, fmt.Errorf("sign: decode private key: %w", err)
	}
	return &PrivateKey{sk: sk}, nil
}

// Bytes returns the private key in its 32-byte seed form. Treat it as secret
// key material.
func (k *PrivateKey) Bytes() []byte {
	return k.sk.Bytes()
}

// PublicKey returns the public key that pairs with k.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{pk: k.sk.PublicKey()}
}

// Sign signs message under ctx. Signatures are hedged: the module mixes fresh
// randomness into every signature, as FIPS 204 recommends.
func (k *PrivateKey) Sign(ctx Context, message []byte) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	sig, err := k.sk.Sign(nil, message, &mldsa.Options{Context: string(ctx)})
	if err != nil {
		return nil, fmt.Errorf("sign: ML-DSA-87 sign: %w", err)
	}
	return sig, nil
}

// NewPublicKey parses an ML-DSA-87 public key.
func NewPublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("sign: ML-DSA-87 public key must be %d bytes, got %d", PublicKeySize, len(b))
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), b)
	if err != nil {
		return nil, fmt.Errorf("sign: decode public key: %w", err)
	}
	return &PublicKey{pk: pk}, nil
}

// Bytes returns the encoded public key.
func (k *PublicKey) Bytes() []byte {
	return k.pk.Bytes()
}

// Fingerprint returns a stable identifier for the key: the first 16 bytes of
// SHA-384 over the encoded public key, in hex.
func (k *PublicKey) Fingerprint() string {
	sum := sha512.Sum384(k.pk.Bytes())
	return hex.EncodeToString(sum[:16])
}

// Verify checks a signature made by Sign under the same ctx.
func (k *PublicKey) Verify(ctx Context, message, signature []byte) error {
	if err := ctx.validate(); err != nil {
		return err
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("%w: ML-DSA-87 signature must be %d bytes, got %d", ErrInvalidSignature, SignatureSize, len(signature))
	}
	return verify(k.pk, string(ctx), message, signature)
}

// VerifyMLDSA65 verifies a historical ML-DSA-65 signature, such as a DAG node
// signed before the move to ML-DSA-87. It is verify-only: this package never
// creates ML-DSA-65 signatures. context is the FIPS 204 context the signer
// used; signatures made with Cloudflare CIRCL's mldsa65 and a nil context
// verify with "".
func VerifyMLDSA65(publicKey []byte, context string, message, signature []byte) error {
	if len(publicKey) != mldsa.MLDSA65PublicKeySize {
		return fmt.Errorf("sign: ML-DSA-65 public key must be %d bytes, got %d", mldsa.MLDSA65PublicKeySize, len(publicKey))
	}
	if len(signature) != mldsa.MLDSA65SignatureSize {
		return fmt.Errorf("%w: ML-DSA-65 signature must be %d bytes, got %d", ErrInvalidSignature, mldsa.MLDSA65SignatureSize, len(signature))
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicKey)
	if err != nil {
		return fmt.Errorf("sign: decode ML-DSA-65 public key: %w", err)
	}
	return verify(pk, context, message, signature)
}

func verify(pk *mldsa.PublicKey, context string, message, signature []byte) error {
	if len(context) > maxContextSize {
		return fmt.Errorf("sign: context is %d bytes; FIPS 204 allows at most %d", len(context), maxContextSize)
	}
	if err := mldsa.Verify(pk, message, signature, &mldsa.Options{Context: context}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}
