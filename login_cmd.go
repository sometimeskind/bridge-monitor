package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/sometimeskind/bridge-monitor/internal/reauth"
	"github.com/sometimeskind/bridge-monitor/internal/secrets"
	"github.com/sometimeskind/bridge-monitor/internal/totp"
)

// runLogin is the CLI re-auth fallback invoked by mail-reauth.sh via kubectl exec.
// It reads the email and TOTP seed from secret files, prompts for the password
// (no echo), drives the gRPC login flow, prints the IMAP password and whether it
// changed, and exits 0 on success.
func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	grpcConfig := fs.String("grpc-config", defaultGRPCConfig(), "path to bridge grpcServerConfig.json")
	emailFile := fs.String("email-file", defaultEmailFile, "path to the login email secret")
	totpSeed := fs.String("totp-seed", defaultTOTPSeedFile, "path to the TOTP seed secret")
	imapPass := fs.String("imap-password-file", defaultIMAPPassFile, "path to the sealed IMAP password")
	_ = fs.Parse(args)

	email, err := secrets.Read(*emailFile)
	if err != nil {
		fatal(err)
	}

	fmt.Fprintf(os.Stderr, "Password for %s: ", email)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal(fmt.Errorf("read password: %w", err))
	}
	if len(password) == 0 {
		fatal(fmt.Errorf("password is required"))
	}

	code, err := totp.FromSeedFile(*totpSeed)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := reauth.Run(ctx, reauth.Config{
		GRPCConfigPath:   *grpcConfig,
		IMAPPasswordFile: *imapPass,
	}, email, password, code)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("Login succeeded for %s\n", email)
	fmt.Printf("IMAP password: %s\n", out.IMAPPassword)
	switch {
	case out.CompareError != nil:
		fmt.Printf("IMAP password change: UNKNOWN (%v)\n", out.CompareError)
	case out.Changed:
		fmt.Println("IMAP password CHANGED — re-seal it in the homelab repo.")
	default:
		fmt.Println("IMAP password unchanged.")
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "login: %v\n", err)
	os.Exit(1)
}
