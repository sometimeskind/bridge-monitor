// Package totp generates time-based one-time codes from a seed file.
package totp

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// FromSeedFile reads a base32 TOTP seed from path and returns the current code.
// Surrounding whitespace and any spaces within the seed (as Proton displays it)
// are stripped before decoding.
func FromSeedFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read TOTP seed %q: %w", path, err)
	}
	seed := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(string(raw)), " ", ""))
	if seed == "" {
		return "", fmt.Errorf("TOTP seed %q is empty", path)
	}
	code, err := totp.GenerateCode(seed, time.Now())
	if err != nil {
		return "", fmt.Errorf("generate TOTP code: %w", err)
	}
	return code, nil
}
