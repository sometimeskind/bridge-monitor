package bridge

import (
	"encoding/json"
	"fmt"
	"os"
)

// ServerConfig mirrors the grpcServerConfig.json that Proton Bridge writes to
// its settings directory. Field names match the bridge's own struct
// (ProtonMail/proton-bridge internal/service/config.go).
type ServerConfig struct {
	Port           int    `json:"port"`
	Cert           string `json:"cert"`
	Token          string `json:"token"`
	FileSocketPath string `json:"fileSocketPath"`
}

// LoadServerConfig reads and parses grpcServerConfig.json. Bridge regenerates
// this file (new socket path and token) every time it restarts, so callers
// should load it fresh before each connection rather than caching it.
func LoadServerConfig(path string) (*ServerConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open grpc server config %q: %w", path, err)
	}
	defer f.Close()

	var cfg ServerConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode grpc server config %q: %w", path, err)
	}
	if cfg.Token == "" || cfg.Cert == "" {
		return nil, fmt.Errorf("grpc server config %q missing token or cert", path)
	}
	return &cfg, nil
}
