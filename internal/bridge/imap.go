package bridge

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"
)

// MailServerSettings returns the bridge's current IMAP listener port and
// whether it expects a direct TLS connection (vs. plaintext/STARTTLS). The
// bridge regenerates these on every restart, so callers should fetch them
// fresh rather than caching.
func (c *Client) MailServerSettings(ctx context.Context) (port int, useSSL bool, err error) {
	resp, err := c.Bridge.MailServerSettings(ctx, &emptypb.Empty{})
	if err != nil {
		return 0, false, fmt.Errorf("mail server settings: %w", err)
	}
	return int(resp.GetImapPort()), resp.GetUseSSLForImap(), nil
}

// ProbeIMAPLogin opens an authenticated IMAP session against addr (host:port)
// and immediately logs out. It is the only signal that distinguishes a
// de-authed session (Code=10013) from a healthy one: the bridge daemon does
// not transition such a user out of CONNECTED locally, but IMAP LOGIN fails
// with "no such user". Deliberately LOGIN -> LOGOUT only; SELECT/FETCH would
// trigger a real mailbox sync against Proton.
func ProbeIMAPLogin(ctx context.Context, addr string, useSSL bool, username string, password []byte) error {
	var conn net.Conn
	var err error
	if useSSL {
		// InsecureSkipVerify: trust in the bridge was already established via
		// the token-authenticated gRPC call that handed us this port. TLS
		// here is transport only, not identity.
		dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial imap %s: %w", addr, err)
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		return fmt.Errorf("read imap greeting: %w", err)
	}

	cmd := fmt.Sprintf("a1 LOGIN %s %s\r\n", quoteIMAPString(username), quoteIMAPString(string(password)))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return fmt.Errorf("send imap login: %w", err)
	}
	resp, err := readTaggedResponse(r, "a1")
	if err != nil {
		return fmt.Errorf("read imap login response: %w", err)
	}
	if !isOK(resp) {
		return fmt.Errorf("imap login failed: %s", resp)
	}

	if _, err := conn.Write([]byte("a2 LOGOUT\r\n")); err != nil {
		return fmt.Errorf("send imap logout: %w", err)
	}
	if _, err := readTaggedResponse(r, "a2"); err != nil {
		return fmt.Errorf("read imap logout response: %w", err)
	}
	return nil
}

// readTaggedResponse reads lines until one starts with the given command tag,
// discarding untagged ("* ...") responses along the way.
func readTaggedResponse(r *bufio.Reader, tag string) (string, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return line, nil
		}
	}
}

func isOK(taggedLine string) bool {
	fields := strings.Fields(taggedLine)
	return len(fields) >= 2 && strings.EqualFold(fields[1], "OK")
}

// quoteIMAPString renders s as an IMAP quoted-string. Sufficient for secrets
// read as a single trimmed line (never containing CR/LF); only backslash and
// double-quote need escaping.
func quoteIMAPString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
