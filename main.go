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
	defaultIMAPPassFile = "/secrets/bridge-imap-password/password"
)

func main() {
	grpcConfig := flag.String("grpc-config", defaultGRPCConfig(), "path to bridge grpcServerConfig.json")
	grpcHost := flag.String("grpc-host", "", "bridge gRPC host or host:port for cross-pod TCP connection (default: use unix socket from grpc config)")
	imapHost := flag.String("imap-host", "", "IMAP host:port for cross-pod probe (default: use port from MailServerSettings on 127.0.0.1)")
	imapOnly := flag.Bool("imap-only", false, "disable all gRPC; derive health from IMAP probe only (requires --imap-host)")
	emailFile := flag.String("email-file", defaultEmailFile, "path to the login email secret")
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

	if *imapOnly && *imapHost == "" {
		fmt.Fprintln(os.Stderr, "bridge-monitor: --imap-host is required when --imap-only is set")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := serve.Run(ctx, serve.Options{
		GRPCConfigPath:   *grpcConfig,
		GRPCHost:         *grpcHost,
		IMAPHost:         *imapHost,
		IMAPOnly:         *imapOnly,
		EmailFile:        *emailFile,
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
