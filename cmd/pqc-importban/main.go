// Copyright 2026 SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

// Command pqc-importban fails when a module's packages import cryptography
// that has no place in a FIPS 203/204 build: pre-standard Kyber and Dilithium,
// CIRCL's unvalidated ML-KEM and ML-DSA, BLAKE2b and Argon2 (not approved for
// key derivation or integrity), and math/rand in cryptographic packages.
//
// Run it from a module root, typically in CI:
//
//	go run github.com/nouchix/khepra-pqc/cmd/pqc-importban ./...
//
// Files behind the legacy_r3 build tag are not loaded, so a decrypt-only
// migration shim can live there without failing the check. Temporary
// exemptions for whole packages can be passed with -allow.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// rule describes one banned import.
type rule struct {
	prefix string
	reason string
	// cryptoOnly limits the rule to packages matched by -crypto-pkgs.
	cryptoOnly bool
}

var rules = []rule{
	{prefix: "github.com/cloudflare/circl/kem/kyber", reason: "pre-standard CRYSTALS-Kyber; use github.com/nouchix/khepra-pqc/kem (FIPS 203 ML-KEM-1024)"},
	{prefix: "github.com/cloudflare/circl/sign/dilithium", reason: "pre-standard CRYSTALS-Dilithium; use github.com/nouchix/khepra-pqc/sign (FIPS 204 ML-DSA-87)"},
	{prefix: "github.com/cloudflare/circl/kem/mlkem", reason: "not a validated module; use github.com/nouchix/khepra-pqc/kem (crypto/mlkem)"},
	{prefix: "github.com/cloudflare/circl/sign/mldsa", reason: "not a validated module; use github.com/nouchix/khepra-pqc/sign (crypto/mldsa)"},
	{prefix: "golang.org/x/crypto/blake2b", reason: "BLAKE2b is not approved for key derivation or integrity; use SHA-384 or HKDF-SHA-384"},
	{prefix: "golang.org/x/crypto/argon2", reason: "Argon2 is not approved for key derivation; use github.com/nouchix/khepra-pqc/kdf (PBKDF2)"},
	{prefix: "math/rand", reason: "math/rand is not a cryptographic random source; use crypto/rand", cryptoOnly: true},
}

type goPackage struct {
	ImportPath string
	Imports    []string
	Error      *struct{ Err string }
}

type violation struct {
	pkg, imp, reason string
}

func main() {
	allow := flag.String("allow", "", "comma-separated package paths exempted from the check (temporary, document why)")
	cryptoPkgs := flag.String("crypto-pkgs", `(adinkra|crypto|license|kms|keytwin|pqc|envelope|acp|attest|drbc|kem|sign)`,
		"regexp selecting cryptographic packages, where math/rand is also banned")
	flag.Parse()

	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	cryptoRe, err := regexp.Compile(*cryptoPkgs)
	if err != nil {
		fatal(fmt.Errorf("-crypto-pkgs: %w", err))
	}
	allowed := map[string]bool{}
	for _, p := range strings.Split(*allow, ",") {
		if p = strings.TrimSpace(p); p != "" {
			allowed[p] = true
		}
	}

	pkgs, err := listPackages(patterns)
	if err != nil {
		fatal(err)
	}
	found := check(pkgs, allowed, cryptoRe)
	if len(found) == 0 {
		fmt.Printf("pqc-importban: %d packages checked, no banned imports\n", len(pkgs))
		return
	}
	for _, v := range found {
		fmt.Fprintf(os.Stderr, "%s imports %s: %s\n", v.pkg, v.imp, v.reason)
	}
	fmt.Fprintf(os.Stderr, "pqc-importban: %d banned imports\n", len(found))
	os.Exit(1)
}

func check(pkgs []goPackage, allowed map[string]bool, cryptoRe *regexp.Regexp) []violation {
	var out []violation
	for _, p := range pkgs {
		if allowed[p.ImportPath] {
			continue
		}
		for _, imp := range p.Imports {
			for _, r := range rules {
				if !matchesPrefix(imp, r.prefix) {
					continue
				}
				if r.cryptoOnly && !cryptoRe.MatchString(p.ImportPath) {
					continue
				}
				out = append(out, violation{pkg: p.ImportPath, imp: imp, reason: r.reason})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].pkg != out[j].pkg {
			return out[i].pkg < out[j].pkg
		}
		return out[i].imp < out[j].imp
	})
	return out
}

// matchesPrefix reports whether imp is prefix or a package under it.
func matchesPrefix(imp, prefix string) bool {
	return imp == prefix || strings.HasPrefix(imp, prefix+"/")
}

// listPackages runs `go list -json` and decodes the stream of packages.
// Test-only imports are not included: the ban applies to shipped code.
func listPackages(patterns []string) ([]goPackage, error) {
	args := append([]string{"list", "-e", "-json=ImportPath,Imports,Error"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	var pkgs []goPackage
	dec := json.NewDecoder(stdout)
	for {
		var p goPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		pkgs = append(pkgs, p)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	return pkgs, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "pqc-importban:", err)
	os.Exit(2)
}
