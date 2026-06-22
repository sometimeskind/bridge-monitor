package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

// serverTokenMetadataKey is the gRPC metadata key the bridge's auth interceptor
// checks on every call (ProtonMail/proton-bridge internal/frontend/grpc).
const serverTokenMetadataKey = "server-token"

// tlsServerName is the CN/SAN baked into the bridge's self-signed certificate.
// We dial a unix socket, so there's no real hostname; this must match the cert
// for verification to pass (internal/certs/tls.go).
const tlsServerName = "127.0.0.1"

// tokenCreds attaches the bridge server token to every unary and stream call.
type tokenCreds struct {
	token string
}

func (t tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{serverTokenMetadataKey: t.token}, nil
}

// RequireTransportSecurity is true because the bridge serves gRPC over TLS even
// on the local unix socket.
func (t tokenCreds) RequireTransportSecurity() bool { return true }

// Client is a connection to the bridge gRPC API. It owns a single grpc.ClientConn
// and must be closed by the caller. Because the bridge rotates its socket and
// token on restart, callers should open a fresh Client per logical operation.
type Client struct {
	conn   *grpc.ClientConn
	Bridge pb.BridgeClient
}

// Connect reads the given grpcServerConfig.json and dials the bridge over its
// unix socket (TLS, with the server token pinned). The returned Client is ready
// to use; lazily connected like all grpc.NewClient connections.
func Connect(configPath string) (*Client, error) {
	cfg, err := LoadServerConfig(configPath)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.Cert)) {
		return nil, fmt.Errorf("grpc server config cert is not valid PEM")
	}
	transport := credentials.NewTLS(&tls.Config{
		ServerName: tlsServerName,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})

	target := dialTarget(cfg)
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(transport),
		grpc.WithPerRPCCredentials(tokenCreds{token: cfg.Token}),
		grpc.WithAuthority(tlsServerName),
	)
	if err != nil {
		return nil, fmt.Errorf("dial bridge gRPC %q: %w", target, err)
	}

	return &Client{conn: conn, Bridge: pb.NewBridgeClient(conn)}, nil
}

// dialTarget builds the grpc target. On Linux the bridge listens on a unix
// socket; the TCP port is a fallback for other platforms.
func dialTarget(cfg *ServerConfig) string {
	if cfg.FileSocketPath != "" {
		return "unix://" + cfg.FileSocketPath
	}
	return fmt.Sprintf("127.0.0.1:%d", cfg.Port)
}

// Close releases the underlying connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
