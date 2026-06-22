package bridge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grpcServerConfig.json")
	os.WriteFile(p, []byte(`{"port":0,"cert":"PEM","token":"tok","fileSocketPath":"/tmp/s.sock"}`), 0o600)

	cfg, err := LoadServerConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "tok" || cfg.FileSocketPath != "/tmp/s.sock" || cfg.Cert != "PEM" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoadServerConfigMissingToken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grpcServerConfig.json")
	os.WriteFile(p, []byte(`{"cert":"PEM"}`), 0o600)

	if _, err := LoadServerConfig(p); err == nil {
		t.Error("expected error for missing token")
	}
}

func TestLoadServerConfigMissingFile(t *testing.T) {
	if _, err := LoadServerConfig(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected error for missing file")
	}
}
