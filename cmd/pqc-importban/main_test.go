package main

import (
	"regexp"
	"testing"
)

func TestCheck(t *testing.T) {
	cryptoRe := regexp.MustCompile(`(adinkra|crypto|license)`)
	pkgs := []goPackage{
		{ImportPath: "example.com/app/pkg/adinkra", Imports: []string{
			"github.com/cloudflare/circl/kem/kyber/kyber1024",
			"github.com/cloudflare/circl/sign/dilithium/mode3",
			"math/rand",
			"crypto/mlkem",
		}},
		{ImportPath: "example.com/app/pkg/ui", Imports: []string{"math/rand", "fmt"}},
		{ImportPath: "example.com/app/pkg/license", Imports: []string{"golang.org/x/crypto/argon2", "github.com/cloudflare/circl/sign/mldsa/mldsa65"}},
		{ImportPath: "example.com/app/pkg/exempt", Imports: []string{"golang.org/x/crypto/blake2b"}},
		{ImportPath: "example.com/app/pkg/lookalike", Imports: []string{"github.com/cloudflare/circl/kem/kyberish"}},
	}
	got := check(pkgs, map[string]bool{"example.com/app/pkg/exempt": true}, cryptoRe)

	want := map[string]bool{
		"example.com/app/pkg/adinkra github.com/cloudflare/circl/kem/kyber/kyber1024":  true,
		"example.com/app/pkg/adinkra github.com/cloudflare/circl/sign/dilithium/mode3": true,
		"example.com/app/pkg/adinkra math/rand":                                        true,
		"example.com/app/pkg/license golang.org/x/crypto/argon2":                       true,
		"example.com/app/pkg/license github.com/cloudflare/circl/sign/mldsa/mldsa65":   true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d violations, want %d: %+v", len(got), len(want), got)
	}
	for _, v := range got {
		if !want[v.pkg+" "+v.imp] {
			t.Errorf("unexpected violation %s -> %s", v.pkg, v.imp)
		}
	}
}

func TestMatchesPrefix(t *testing.T) {
	if !matchesPrefix("math/rand/v2", "math/rand") {
		t.Error("math/rand/v2 should match math/rand")
	}
	if matchesPrefix("math/random", "math/rand") {
		t.Error("math/random must not match math/rand")
	}
}
