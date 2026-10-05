package fips

import (
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
)

func TestEnforce(t *testing.T) {
	t.Setenv(RequiredEnv, "")
	if err := Enforce(); err != nil {
		t.Fatalf("not required: %v", err)
	}

	t.Setenv(RequiredEnv, "1")
	err := Enforce()
	if fips140.Enabled() {
		if err != nil {
			t.Fatalf("FIPS mode is on, Enforce failed: %v", err)
		}
	} else if !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("FIPS mode is off and required: got %v, want ErrNotEnabled", err)
	}
}

func TestStatus(t *testing.T) {
	s := Status()
	if fips140.Enabled() {
		if !strings.Contains(s, fips140.Version()) {
			t.Fatalf("status %q does not name the module version", s)
		}
	} else if s != "FIPS 140-3 mode: off" {
		t.Fatalf("unexpected status %q", s)
	}
}
