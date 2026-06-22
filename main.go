// Command bridge-monitor is a Proton Bridge sidecar: it exports Prometheus
// metrics and serves a re-auth web UI (serve), and provides a CLI re-auth
// fallback (login), both driving the bridge gRPC API.
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

const (
	defaultEmailFile    = "/secrets/bridge-login-credentials/email"
	defaultTOTPSeedFile = "/secrets/bridge-login-credentials/totp-seed"
	defaultIMAPPassFile = "/secrets/bridge-imap-password/password"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "login":
		runLogin(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `bridge-monitor — Proton Bridge sidecar

Usage:
  bridge-monitor serve [flags]   run metrics (:9100) and re-auth web UI (:8080)
  bridge-monitor login [flags]   re-auth from the terminal (prompts for password)

Run "bridge-monitor <subcommand> -h" for flags.
`)
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

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	grpcConfig := fs.String("grpc-config", defaultGRPCConfig(), "path to bridge grpcServerConfig.json")
	emailFile := fs.String("email-file", defaultEmailFile, "path to the login email secret")
	totpSeed := fs.String("totp-seed", defaultTOTPSeedFile, "path to the TOTP seed secret")
	imapPass := fs.String("imap-password-file", defaultIMAPPassFile, "path to the sealed IMAP password")
	metricsAddr := fs.String("metrics-addr", ":9100", "metrics listen address")
	webAddr := fs.String("web-addr", ":8080", "web UI listen address")
	pollInterval := fs.Duration("poll-interval", 30*time.Second, "metrics poll interval")
	_ = fs.Parse(args)

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
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}
