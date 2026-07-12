package serve

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sometimeskind/bridge-monitor/internal/bridgetest"
	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

// When the bridge config is unreachable, the poll must report bridge_grpc_up=0
// rather than crashing.
func TestPollMarksDownOnBadConfig(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg, false)

	m.poll(context.Background(), "/nonexistent/grpcServerConfig.json", "", "", "/nonexistent/email", "/nonexistent/imap-password", false)

	if got := testutil.ToFloat64(m.grpcUp); got != 0 {
		t.Errorf("bridge_grpc_up = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.accountConnected); got != 0 {
		t.Errorf("bridge_account_connected = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.imapLoginOK); got != 0 {
		t.Errorf("bridge_imap_login_ok = %v, want 0", got)
	}
}

// A healthy poll (gRPC up, IMAP login succeeds) must report
// bridge_imap_login_ok=1.
func TestPollIMAPLoginOK(t *testing.T) {
	const email = "me@example.com"
	const imapPassword = "imap-secret"

	port := bridgetest.StartFakeIMAPServer(t, email, imapPassword, false)
	cfg := bridgetest.StartFakeBridge(t, bridgetest.Scenario{
		Users:    []*pb.User{{Id: "u1", Username: email, Addresses: []string{email}, State: pb.UserState_CONNECTED}},
		ImapPort: port,
	})

	emailFile := writeSecretFile(t, email)
	imapPasswordFile := writeSecretFile(t, imapPassword)

	reg := prometheus.NewRegistry()
	m := newMetrics(reg, false)
	m.poll(context.Background(), cfg, "", "", emailFile, imapPasswordFile, false)

	if got := testutil.ToFloat64(m.imapLoginOK); got != 1 {
		t.Errorf("bridge_imap_login_ok = %v, want 1", got)
	}
}

func writeSecretFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return path
}
