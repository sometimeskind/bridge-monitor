// Package secrets reads operator-supplied secret files mounted into the pod.
package secrets

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// Read returns the contents of a secret file with surrounding whitespace
// trimmed (mounted secrets commonly carry a trailing newline).
func Read(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret %q: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// IMAPChanged reports whether the IMAP password the bridge returned after login
// differs from the sealed value in sealedFile. Both sides are trimmed so a
// trailing newline in the sealed file does not register as a change.
func IMAPChanged(current []byte, sealedFile string) (changed bool, sealed string, err error) {
	sealed, err = Read(sealedFile)
	if err != nil {
		return false, "", err
	}
	return string(bytes.TrimSpace(current)) != sealed, sealed, nil
}
