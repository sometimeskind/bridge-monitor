// Package reauth orchestrates a full bridge re-authentication: connect, drive
// the gRPC login flow, and compare the resulting IMAP password with the sealed
// value. It is shared by the web UI (POST /auth) and the login CLI.
package reauth

import (
	"context"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/secrets"
)

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

	out := &Outcome{Result: res, IMAPPassword: string(res.IMAPPassword)}
	changed, _, cerr := secrets.IMAPChanged(res.IMAPPassword, cfg.IMAPPasswordFile)
	if cerr != nil {
		out.CompareError = cerr
	} else {
		out.Changed = changed
	}
	return out, nil
}
