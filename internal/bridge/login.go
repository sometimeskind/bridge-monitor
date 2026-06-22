package bridge

import (
	"context"
	"encoding/base64"
	"fmt"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

// LoginResult is the outcome of a successful re-auth.
type LoginResult struct {
	UserID       string
	Username     string
	Addresses    []string
	IMAPPassword []byte
}

// LoginError is an expected, user-facing login failure (wrong password, wrong
// 2FA, etc.). Callers should show its message rather than a stack trace.
type LoginError struct {
	Type    pb.LoginErrorType
	Message string
}

func (e *LoginError) Error() string {
	msg := loginErrorText(e.Type)
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", msg, e.Message)
	}
	return msg
}

func loginErrorText(t pb.LoginErrorType) string {
	switch t {
	case pb.LoginErrorType_USERNAME_PASSWORD_ERROR:
		return "incorrect username or password"
	case pb.LoginErrorType_FREE_USER:
		return "account is not a paid plan"
	case pb.LoginErrorType_CONNECTION_ERROR:
		return "could not connect to Proton"
	case pb.LoginErrorType_TFA_ERROR:
		return "incorrect or expired 2FA code"
	case pb.LoginErrorType_TFA_ABORT:
		return "2FA was aborted"
	case pb.LoginErrorType_HV_ERROR:
		return "human verification required (not supported here)"
	default:
		return "login failed"
	}
}

// base64Field encodes a secret the way the bridge gRPC server expects: the bytes
// password field of LoginRequest holds the std-base64 encoding of the raw value,
// which the server base64-decodes (see proton-bridge service_methods.go).
func base64Field(raw []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(raw))
}

// Login drives the full re-auth flow against the running bridge:
//
//	GetUserList -> LogoutUser (if logged in) -> RunEventStream -> Login
//	  -> [tfaRequested -> Login2FA] -> finished/alreadyLoggedIn
//
// then reads back the user to capture the new IMAP password. The supplied ctx
// should carry a timeout so a missing event cannot hang the caller. Single
// account, single-password mode: two-password/HV/FIDO prompts are treated as
// unsupported errors.
func (c *Client) Login(ctx context.Context, login string, password []byte, totp string) (*LoginResult, error) {
	// Clear any live session so Login reconnects instead of erroring with
	// "already logged in". A signed-out user is left as-is (LoginUser reconnects
	// it without a resync).
	users, err := c.GetUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	if existing := FindUser(users, login); existing != nil && existing.GetState() != pb.UserState_SIGNED_OUT {
		if _, err := c.Bridge.LogoutUser(ctx, wrapperspb.String(existing.GetId())); err != nil {
			return nil, fmt.Errorf("logout existing user: %w", err)
		}
	}

	// Subscribe to the event stream BEFORE calling Login, otherwise the
	// tfaRequested event can fire before we are listening.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.Bridge.RunEventStream(streamCtx, &pb.EventStreamRequest{ClientPlatform: "bridge-monitor"})
	if err != nil {
		return nil, fmt.Errorf("open event stream: %w", err)
	}
	defer func() { _, _ = c.Bridge.StopEventStream(context.WithoutCancel(ctx), &emptypb.Empty{}) }()

	if _, err := c.Bridge.Login(ctx, &pb.LoginRequest{
		Username: login,
		Password: base64Field(password),
	}); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	userID, err := c.awaitLogin(ctx, stream, login, totp)
	if err != nil {
		// Abort any half-finished login so it does not poison the next attempt.
		_, _ = c.Bridge.LoginAbort(context.WithoutCancel(ctx), &pb.LoginAbortRequest{Username: login})
		return nil, err
	}

	return c.imapResult(ctx, userID, login)
}

// awaitLogin consumes login events until the flow finishes or fails. It returns
// the logged-in user's ID on success.
func (c *Client) awaitLogin(ctx context.Context, stream pb.Bridge_RunEventStreamClient, login, totp string) (string, error) {
	tfaSent := false
	for {
		event, err := stream.Recv()
		if err != nil {
			return "", fmt.Errorf("event stream: %w", err)
		}
		le := event.GetLogin()
		if le == nil {
			continue // unrelated event (app/user/etc.)
		}

		switch {
		case le.GetError() != nil:
			return "", &LoginError{Type: le.GetError().GetType(), Message: le.GetError().GetMessage()}

		case le.GetTfaRequested() != nil:
			if tfaSent {
				continue
			}
			tfaSent = true
			if _, err := c.Bridge.Login2FA(ctx, &pb.LoginRequest{
				Username: login,
				Password: base64Field([]byte(totp)),
			}); err != nil {
				return "", fmt.Errorf("submit 2FA: %w", err)
			}

		case le.GetFinished() != nil:
			return le.GetFinished().GetUserID(), nil

		case le.GetAlreadyLoggedIn() != nil:
			return le.GetAlreadyLoggedIn().GetUserID(), nil

		case le.GetTwoPasswordRequested() != nil:
			return "", &LoginError{Message: "account uses two-password mode, which is not supported"}

		case le.GetHvRequested() != nil:
			return "", &LoginError{Type: pb.LoginErrorType_HV_ERROR}

		case le.GetFidoRequested() != nil, le.GetTfaOrFidoRequested() != nil:
			return "", &LoginError{Message: "security-key (FIDO) login is not supported"}
		}
	}
}

// imapResult reads back the logged-in user to capture the IMAP password.
func (c *Client) imapResult(ctx context.Context, userID, login string) (*LoginResult, error) {
	user, err := c.Bridge.GetUser(ctx, wrapperspb.String(userID))
	if err != nil {
		// Fall back to the list if GetUser is unavailable for some reason.
		users, lerr := c.GetUsers(ctx)
		if lerr != nil {
			return nil, fmt.Errorf("read user after login: %w", err)
		}
		if user = FindUser(users, login); user == nil {
			return nil, fmt.Errorf("logged-in user %q not found after login", login)
		}
	}

	return &LoginResult{
		UserID:       user.GetId(),
		Username:     user.GetUsername(),
		Addresses:    user.GetAddresses(),
		IMAPPassword: user.GetPassword(),
	}, nil
}
