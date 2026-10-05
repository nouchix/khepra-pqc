// Copyright 2026 SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

// Package fips reports and enforces FIPS 140-3 mode for binaries that use
// khepra-pqc. The cryptography itself comes from the Go Cryptographic Module
// (crypto/mlkem, crypto/mldsa, crypto/aes, crypto/hkdf); this package only
// checks that the module is running in approved mode when a deployment
// requires it.
package fips

import (
	"crypto/fips140"
	"errors"
	"fmt"
	"os"
)

// RequiredEnv names the environment variable that makes FIPS 140-3 mode
// mandatory. FIPS container images set it to "1".
const RequiredEnv = "KHEPRA_FIPS_REQUIRED"

// ErrNotEnabled is returned by Enforce when FIPS mode is required but the
// process is not running the Go Cryptographic Module in FIPS mode.
var ErrNotEnabled = errors.New("fips: FIPS 140-3 mode is required but not enabled " +
	"(build with GOFIPS140=inprocess, which selects module v1.26.0, and run with GODEBUG=fips140=on)")

// Required reports whether this process must run in FIPS 140-3 mode.
func Required() bool {
	switch os.Getenv(RequiredEnv) {
	case "1", "true", "TRUE", "on":
		return true
	}
	return false
}

// Enforce returns ErrNotEnabled when FIPS mode is required but not enabled.
// Call it at the top of main and exit on error.
func Enforce() error {
	if Required() && !fips140.Enabled() {
		return ErrNotEnabled
	}
	return nil
}

// Status describes the cryptographic module state for startup logs.
func Status() string {
	if !fips140.Enabled() {
		return "FIPS 140-3 mode: off"
	}
	mode := "on"
	if fips140.Enforced() {
		mode = "only (non-approved algorithms disabled)"
	}
	return fmt.Sprintf("FIPS 140-3 mode: %s; Go Cryptographic Module %s", mode, fips140.Version())
}
