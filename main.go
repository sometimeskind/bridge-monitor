// Command bridge-monitor is a Proton Bridge sidecar: it exports Prometheus
// metrics and serves a re-auth web UI, both driving the bridge gRPC API.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sometimeskind/bridge-monitor/internal/serve"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	defaultEmailFile    = "/secrets/bridge-login-credentials/email"
	defaultTOTPSeedFile = "/secrets/bridge-login-credentials/totp-seed"
	defaultIMAPPassFile = "/secrets/bridge-imap-password/password"
)

func main() {
	grpcConfig := flag.String("grpc-config", defaultGRPCConfig(), "path to bridge grpcServerConfig.json")
	emailFile := flag.String("email-file", defaultEmailFile, "path to the login email secret")
	totpSeed := flag.String("totp-seed", defaultTOTPSeedFile, "path to the TOTP seed secret")
	imapPass := flag.String("imap-password-file", defaultIMAPPassFile, "path to the sealed IMAP password")
	metricsAddr := flag.String("metrics-addr", ":9100", "metrics listen address")
	webAddr := flag.String("web-addr", ":8080", "web UI listen address")
	pollInterval := flag.Duration("poll-interval", 30*time.Second, "metrics poll interval")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := serve.Run(ctx, serve.Options{
		GRPCConfigPath:   *grpcConfig,
		EmailFile:        *emailFile,
		TOTPSeedFile:     *totpSeed,
		IMAPPasswordFile: *imapPass,
		MetricsAddr:      *metricsAddr,
		WebAddr:          *webAddr,
		PollInterval:     *pollInterval,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bridge-monitor: %v\n", err)
		os.Exit(1)
	}
}

// defaultGRPCConfig returns the bridge's grpcServerConfig.json under the user
// config dir (honouring XDG_CONFIG_HOME / HOME). Overridable with --grpc-config.
func defaultGRPCConfig() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "/root/.config"
	}
	return filepath.Join(dir, "protonmail", "bridge-v3", "grpcServerConfig.json")
}
