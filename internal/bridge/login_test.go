package bridge_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

func connect(t *testing.T, configPath string) *bridge.Client {
	t.Helper()
	c, err := bridge.Connect(configPath)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestLoginWithTFA(t *testing.T) {
	cfg := startFakeBridge(t, scenario{
		users: []*pb.User{{Id: "u1", Username: "me@example.com",
			Addresses: []string{"me@example.com"}, State: pb.UserState_CONNECTED}},
		wantPassword: "hunter2",
		wantTOTP:     "123456",
		imapPassword: []byte("imap-secret"),
	})
	c := connect(t, cfg)

	res, err := c.Login(ctx(t), "me@example.com", []byte("hunter2"), "123456")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got := string(res.IMAPPassword); got != "imap-secret" {
		t.Errorf("IMAP password = %q, want imap-secret", got)
	}
	if res.UserID != "user-me@example.com" {
		t.Errorf("UserID = %q", res.UserID)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	cfg := startFakeBridge(t, scenario{wantPassword: "correct", wantTOTP: "123456"})
	c := connect(t, cfg)

	_, err := c.Login(ctx(t), "me@example.com", []byte("wrong"), "123456")
	var le *bridge.LoginError
	if !errors.As(err, &le) || le.Type != pb.LoginErrorType_USERNAME_PASSWORD_ERROR {
		t.Fatalf("want USERNAME_PASSWORD_ERROR, got %v", err)
	}
}

func TestLoginWrongTOTP(t *testing.T) {
	cfg := startFakeBridge(t, scenario{wantPassword: "hunter2", wantTOTP: "999999"})
	c := connect(t, cfg)

	_, err := c.Login(ctx(t), "me@example.com", []byte("hunter2"), "000000")
	var le *bridge.LoginError
	if !errors.As(err, &le) || le.Type != pb.LoginErrorType_TFA_ERROR {
		t.Fatalf("want TFA_ERROR, got %v", err)
	}
}

func TestLoginNoTFA(t *testing.T) {
	cfg := startFakeBridge(t, scenario{wantPassword: "hunter2", imapPassword: []byte("imap-x")})
	c := connect(t, cfg)

	res, err := c.Login(ctx(t), "me@example.com", []byte("hunter2"), "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if string(res.IMAPPassword) != "imap-x" {
		t.Errorf("IMAP password = %q", res.IMAPPassword)
	}
}

func TestLoginAlreadyLoggedIn(t *testing.T) {
	cfg := startFakeBridge(t, scenario{
		wantPassword: "hunter2",
		imapPassword: []byte("imap-y"),
		loginEmits: func(f *fakeBridge, username string) {
			f.finishLoginAs(username)
			f.emit(&pb.LoginEvent{Event: &pb.LoginEvent_AlreadyLoggedIn{
				AlreadyLoggedIn: &pb.LoginFinishedEvent{UserID: "user-" + username}}})
		},
	})
	c := connect(t, cfg)

	res, err := c.Login(ctx(t), "me@example.com", []byte("hunter2"), "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if string(res.IMAPPassword) != "imap-y" {
		t.Errorf("IMAP password = %q", res.IMAPPassword)
	}
}

func TestLoginTwoPasswordUnsupported(t *testing.T) {
	cfg := startFakeBridge(t, scenario{
		wantPassword: "hunter2",
		loginEmits: func(f *fakeBridge, username string) {
			f.emit(&pb.LoginEvent{Event: &pb.LoginEvent_TwoPasswordRequested{
				TwoPasswordRequested: &pb.LoginTwoPasswordsRequestedEvent{Username: username}}})
		},
	})
	c := connect(t, cfg)

	_, err := c.Login(ctx(t), "me@example.com", []byte("hunter2"), "")
	var le *bridge.LoginError
	if !errors.As(err, &le) {
		t.Fatalf("want LoginError for two-password mode, got %v", err)
	}
}

func TestLoginLogsOutConnectedUser(t *testing.T) {
	fakeCfg := scenario{
		users: []*pb.User{{Id: "u1", Username: "me@example.com",
			Addresses: []string{"me@example.com"}, State: pb.UserState_CONNECTED}},
		wantPassword: "hunter2",
		imapPassword: []byte("imap-z"),
	}
	cfg := startFakeBridge(t, fakeCfg)
	c := connect(t, cfg)

	if _, err := c.Login(ctx(t), "me@example.com", []byte("hunter2"), ""); err != nil {
		t.Fatalf("login: %v", err)
	}
}
