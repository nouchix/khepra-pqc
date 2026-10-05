# khepra-pqc

NIST-standard post-quantum cryptography for KHEPRA, built on the Go
Cryptographic Module.

| Function | Algorithm | Standard | Implementation |
|---|---|---|---|
| Key encapsulation | ML-KEM-1024 | FIPS 203 | `crypto/mlkem` |
| Signatures | ML-DSA-87 | FIPS 204 | `crypto/mldsa` |
| Historical signature verification | ML-DSA-65 (verify only) | FIPS 204 | `crypto/mldsa` |
| Key derivation | HKDF-SHA-384 | SP 800-56C Rev 2 | `crypto/hkdf` |
| Passphrase keys | PBKDF2-HMAC-SHA-384 | SP 800-132 | `crypto/pbkdf2` |
| Symmetric encryption | AES-256-GCM, module-generated nonces | SP 800-38D | `crypto/aes`, `crypto/cipher` |

ML-KEM-1024 and ML-DSA-87 are the parameter sets the NSA CNSA 2.0 suite
requires. This module offers no other parameter sets for new keys.

## FIPS 140-3 status

All cryptography comes from the Go Cryptographic Module. ML-DSA requires
module v1.26.0, which is **in process** for FIPS 140-3 validation (CMVP
Modules In Process). Module v1.0.0 is validated but does not include ML-DSA.
Do not describe a build as "FIPS 140-3 validated" until the v1.26.0
certificate is issued; check the CMVP listing before publishing any claim.

Build and run in FIPS mode:

```sh
GOFIPS140=inprocess go build ./...            # selects module v1.26.0
GODEBUG=fips140=on   ./binary                  # approved mode
GODEBUG=fips140=only ./binary                  # non-approved algorithms disabled
```

The test suite passes in default, `fips140=on` and `fips140=only` modes.

Binaries should call `fips.Enforce()` at startup and exit on error; it fails
when `KHEPRA_FIPS_REQUIRED=1` is set and the module is not in FIPS mode.

## Packages

- `kem` — ML-KEM-1024. Decapsulation keys are stored as the 64-byte FIPS 203
  seed.
- `sign` — ML-DSA-87 with a mandatory FIPS 204 context from a fixed registry
  (`khepra/v3/license`, `khepra/v3/dag`, ...). `Context.WithLabel` narrows a
  context, for example to an Adinkra symbol. Private keys are stored as the
  32-byte seed.
- `envelope` — the KHQ3 sealed envelope: ML-KEM-1024, HKDF-SHA-384 and
  AES-256-GCM with the whole header authenticated. Data that does not start
  with the `KHQ3` magic returns `ErrNotEnvelope`, so callers can route legacy
  formats to a one-off migration tool.
- `kdf` — HKDF-SHA-384 and PBKDF2-HMAC-SHA-384.
- `keyfile` — PEM key files, written atomically; private keys use mode 0600.
- `fips` — FIPS mode reporting and enforcement.
- `cmd/pqc-importban` — CI check that fails on imports of pre-standard Kyber
  and Dilithium, CIRCL's unvalidated ML-KEM and ML-DSA, BLAKE2b, Argon2, and
  `math/rand` in cryptographic packages.

## Tests

Known-answer tests use NIST ACVP-Server vectors (`gen-val/json-files`, vsId 42),
filtered to the parameter sets in use:

- ML-KEM-1024 key generation, encapsulation and encapsulation-key checks.
- ML-DSA-87 and ML-DSA-65 key generation and signature verification
  (external interface, pure ML-DSA, with contexts).

Decapsulation and signature generation vectors use expanded private keys,
which the seed-only standard library API does not load; the module's own CAVP
testing covers those internals. `envelope` also has a fuzz target:

```sh
go test ./envelope -run '^$' -fuzz FuzzOpen -fuzztime 60s
```

## License

See [LICENSE](LICENSE). Copyright SOUHIMBOU DOH KONE LLC, exclusively licensed
to SecRed Knowledge Inc.
