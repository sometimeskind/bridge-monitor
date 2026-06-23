package reauth

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sometimeskind/bridge-monitor/internal/bridgetest"
)

func testCtx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func writeFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestRunSucceedsWhenIMAPLoginPasses(t *testing.T) {
	imapVerifyInterval = time.Millisecond
	const email = "me@example.com"
	const password = "hunter2"
	const imapPass = "imap-secret"

	port := bridgetest.StartFakeIMAPServer(t, email, imapPass, false)
	cfg := bridgetest.StartFakeBridge(t, bridgetest.Scenario{
		WantPassword: password,
		IMAPPassword: []byte(imapPass),
		ImapPort:     port,
	})

	out, err := Run(testCtx(t), Config{
		GRPCConfigPath:   cfg,
		IMAPPasswordFile: writeFile(t, imapPass),
	}, email, []byte(password), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.IMAPPassword != imapPass {
		t.Errorf("IMAPPassword = %q, want %q", out.IMAPPassword, imapPass)
	}
}

// TestRunFailsWhenIMAPLoginNeverRecovers verifies that Run returns an error
// when the post-login IMAP probe exhausts all attempts, and that the probe
// was attempted exactly imapVerifyAttempts times.
func TestRunFailsWhenIMAPLoginNeverRecovers(t *testing.T) {
	imapVerifyInterval = time.Millisecond
	const email = "me@example.com"
	const password = "hunter2"
	const imapPass = "imap-secret"
	const bogusPass = "wrong-imap-password"

	// Fake IMAP server that expects bogusPass (so the real imapPass is always
	// rejected), and counts how many times LOGIN was attempted.
	port, loginCount := startCountingIMAPServer(t)

	cfg := bridgetest.StartFakeBridge(t, bridgetest.Scenario{
		WantPassword: password,
		IMAPPassword: []byte(imapPass),
		ImapPort:     port,
	})

	_, err := Run(testCtx(t), Config{
		GRPCConfigPath:   cfg,
		IMAPPasswordFile: writeFile(t, bogusPass),
	}, email, []byte(password), "")
	if err == nil {
		t.Fatal("Run: want error when IMAP probe never recovers, got nil")
	}
	if !strings.Contains(err.Error(), "post-login IMAP verification failed") {
		t.Errorf("Run: error %q does not mention verification failure", err)
	}

	if got := int(loginCount.Load()); got != imapVerifyAttempts {
		t.Errorf("IMAP LOGIN attempted %d times, want %d", got, imapVerifyAttempts)
	}
}

// startCountingIMAPServer starts a fake IMAP server that rejects every login
// and counts attempts via loginCount.
func startCountingIMAPServer(t *testing.T) (port int, loginCount *atomic.Int32) {
	t.Helper()
	loginCount = &atomic.Int32{}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })

	loginRe := regexp.MustCompile(`^(\S+) LOGIN`)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte("* OK fake imap ready\r\n"))
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if m := loginRe.FindStringSubmatch(line); m != nil {
						loginCount.Add(1)
						_, _ = conn.Write([]byte(m[1] + " NO [AUTHENTICATIONFAILED] no such user\r\n"))
						continue
					}
					fields := strings.Fields(line)
					if len(fields) == 2 && strings.EqualFold(fields[1], "LOGOUT") {
						_, _ = conn.Write([]byte("* BYE\r\n" + fields[0] + " OK LOGOUT\r\n"))
						return
					}
				}
			}()
		}
	}()

	return lis.Addr().(*net.TCPAddr).Port, loginCount
}
