package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadTrims(t *testing.T) {
	got, err := Read(write(t, "  value\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "value" {
		t.Errorf("Read = %q, want value", got)
	}
}

func TestIMAPChanged(t *testing.T) {
	sealed := write(t, "secretpw\n")

	changed, _, err := IMAPChanged([]byte("secretpw"), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("expected unchanged for matching password (modulo newline)")
	}

	changed, _, err = IMAPChanged([]byte("different"), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected changed for differing password")
	}
}
