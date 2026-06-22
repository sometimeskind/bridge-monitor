package totp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestFromSeedFile(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	p := filepath.Join(t.TempDir(), "seed")
	// Seed written with surrounding whitespace and an internal space, as Proton
	// displays it, to exercise the cleanup.
	if err := os.WriteFile(p, []byte("  JBSWY3DP EHPK3PXP \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := FromSeedFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want, err := totp.GenerateCode(seed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("FromSeedFile = %q, want %q", got, want)
	}
}

func TestFromSeedFileEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromSeedFile(p); err == nil {
		t.Error("expected error for empty seed")
	}
}
