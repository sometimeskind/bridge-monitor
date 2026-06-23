// Package reauth orchestrates a full bridge re-authentication: connect, drive
// the gRPC login flow, and compare the resulting IMAP password with the sealed
// value. It is shared by the web UI (POST /auth) and the login CLI.
package reauth

import (
	"context"
	"fmt"
	"time"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/secrets"
)

// imapVerifyAttempts/imapVerifyInterval bound the post-login IMAP
// verification: the login event stream confirms credentials were accepted,
// not that the daemon is actually IMAP-ready yet, so a short retry rides out
// that settle delay without making a real failure wait long.
const imapVerifyAttempts = 3

// imapVerifyInterval is a var so tests can shorten it.
var imapVerifyInterval = 2 * time.Second

// Config locates the bridge gRPC config and the sealed IMAP password.
type Config struct {
	GRPCConfigPath   string
	IMAPPasswordFile string
}

// Outcome describes a successful re-auth.
type Outcome struct {
	Result       *bridge.LoginResult
	IMAPPassword string
	Changed      bool
	// CompareError is set when login succeeded but the IMAP password could not
	// be compared against the sealed file. The login itself is still valid.
	CompareError error
}

// Run performs the re-auth. A non-nil error means login failed; a *bridge.LoginError
// carries a clean, user-facing message.
func Run(ctx context.Context, cfg Config, email string, password []byte, totpCode string) (*Outcome, error) {
	c, err := bridge.Connect(cfg.GRPCConfigPath)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	res, err := c.Login(ctx, email, password, totpCode)
	if err != nil {
		return nil, err
	}

	// Verify-before-success: the login event stream only confirms the
	// password/2FA were accepted, not that the session actually works
	// afterward (a de-authed refresh token leaves the bridge daemon reporting
	// CONNECTED locally). An authenticated IMAP LOGIN against the bridge's own
	// listener is the only signal that distinguishes the two.
	port, useSSL, err := c.MailServerSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("post-login IMAP verification: %w", err)
	}
	if err := verifyIMAPLogin(ctx, port, useSSL, email, res.IMAPPassword); err != nil {
		return nil, fmt.Errorf("post-login IMAP verification failed: %w", err)
	}

	out := &Outcome{Result: res, IMAPPassword: string(res.IMAPPassword)}
	changed, _, cerr := secrets.IMAPChanged(res.IMAPPassword, cfg.IMAPPasswordFile)
	if cerr != nil {
		out.CompareError = cerr
	} else {
		out.Changed = changed
	}
	return out, nil
}

// verifyIMAPLogin probes up to imapVerifyAttempts times, imapVerifyInterval
// apart, returning nil as soon as one succeeds. No sleep follows the final
// failed attempt.
func verifyIMAPLogin(ctx context.Context, port int, useSSL bool, email string, password []byte) error {
	var lastErr error
	for attempt := 0; attempt < imapVerifyAttempts; attempt++ {
		lastErr = bridge.ProbeIMAPLogin(ctx, port, useSSL, email, password)
		if lastErr == nil {
			return nil
		}
		if attempt < imapVerifyAttempts-1 {
			select {
			case <-ctx.Done():
				return lastErr
			case <-time.After(imapVerifyInterval):
			}
		}
	}
	return lastErr
}
