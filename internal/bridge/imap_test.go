package bridge_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/bridgetest"
)

func probeCtx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestProbeIMAPLoginSuccess(t *testing.T) {
	port := bridgetest.StartFakeIMAPServer(t, "me@example.com", "imap-secret", false)

	if err := bridge.ProbeIMAPLogin(probeCtx(t), port, false, "me@example.com", []byte("imap-secret")); err != nil {
		t.Fatalf("ProbeIMAPLogin: %v", err)
	}
}

func TestProbeIMAPLoginWrongCredentials(t *testing.T) {
	port := bridgetest.StartFakeIMAPServer(t, "me@example.com", "imap-secret", false)

	err := bridge.ProbeIMAPLogin(probeCtx(t), port, false, "me@example.com", []byte("wrong"))
	if err == nil {
		t.Fatal("ProbeIMAPLogin: want error for wrong credentials, got nil")
	}
}

func TestProbeIMAPLoginConnectionRefused(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	lis.Close() // nothing listens on this port now

	err = bridge.ProbeIMAPLogin(probeCtx(t), port, false, "me@example.com", []byte("imap-secret"))
	if err == nil {
		t.Fatal("ProbeIMAPLogin: want error for connection refused, got nil")
	}
}

func TestProbeIMAPLoginTLS(t *testing.T) {
	port := bridgetest.StartFakeIMAPServer(t, "me@example.com", "imap-secret", true)

	if err := bridge.ProbeIMAPLogin(probeCtx(t), port, true, "me@example.com", []byte("imap-secret")); err != nil {
		t.Fatalf("ProbeIMAPLogin: %v", err)
	}
}

func TestMailServerSettings(t *testing.T) {
	cfg := bridgetest.StartFakeBridge(t, bridgetest.Scenario{
		ImapPort:   1234,
		ImapUseSSL: true,
	})
	c := connect(t, cfg)

	port, useSSL, err := c.MailServerSettings(probeCtx(t))
	if err != nil {
		t.Fatalf("MailServerSettings: %v", err)
	}
	if port != 1234 || !useSSL {
		t.Errorf("MailServerSettings = (%d, %v), want (1234, true)", port, useSSL)
	}
}
