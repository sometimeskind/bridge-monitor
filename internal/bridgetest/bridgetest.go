// Package bridgetest provides a fake bridge gRPC server for tests in
// internal/bridge and internal/reauth. It implements just enough of
// pb.BridgeServer to drive the login flow and report mail server settings.
package bridgetest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

// Scenario configures the fake bridge's behaviour for one test.
type Scenario struct {
	Users        []*pb.User // returned by GetUserList before login
	WantPassword string     // raw password the fake accepts
	WantTOTP     string     // raw TOTP the fake accepts (empty => no 2FA prompt)
	IMAPPassword []byte     // User.password reported after a successful login
	LoginEmits   func(f *FakeBridge, username string)

	// ImapPort/ImapUseSSL are returned by MailServerSettings. Tests that probe
	// IMAP health must set ImapPort to a listening fake IMAP server's port.
	ImapPort   int
	ImapUseSSL bool
}

// FakeBridge implements pb.BridgeServer for the login/connection tests.
type FakeBridge struct {
	pb.UnimplementedBridgeServer
	sc     Scenario
	events chan *pb.StreamEvent

	mu             sync.Mutex
	loggedOut      []string
	finishedUserID string
	finishedAddrs  []string
	finishedName   string
}

func (f *FakeBridge) GetUserList(context.Context, *emptypb.Empty) (*pb.UserListResponse, error) {
	return &pb.UserListResponse{Users: f.sc.Users}, nil
}

func (f *FakeBridge) GetUser(_ context.Context, id *wrapperspb.StringValue) (*pb.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.User{
		Id:        id.GetValue(),
		Username:  f.finishedName,
		Addresses: f.finishedAddrs,
		Password:  f.sc.IMAPPassword,
		State:     pb.UserState_CONNECTED,
	}, nil
}

func (f *FakeBridge) LogoutUser(_ context.Context, id *wrapperspb.StringValue) (*emptypb.Empty, error) {
	f.mu.Lock()
	f.loggedOut = append(f.loggedOut, id.GetValue())
	f.mu.Unlock()
	return &emptypb.Empty{}, nil
}

func (f *FakeBridge) Login(_ context.Context, req *pb.LoginRequest) (*emptypb.Empty, error) {
	raw, _ := base64.StdEncoding.DecodeString(string(req.GetPassword()))
	if string(raw) != f.sc.WantPassword {
		f.Emit(&pb.LoginEvent{Event: &pb.LoginEvent_Error{Error: &pb.LoginErrorEvent{Type: pb.LoginErrorType_USERNAME_PASSWORD_ERROR}}})
		return &emptypb.Empty{}, nil
	}
	if f.sc.LoginEmits != nil {
		f.sc.LoginEmits(f, req.GetUsername())
		return &emptypb.Empty{}, nil
	}
	if f.sc.WantTOTP != "" {
		f.Emit(&pb.LoginEvent{Event: &pb.LoginEvent_TfaRequested{TfaRequested: &pb.LoginTfaRequestedEvent{Username: req.GetUsername()}}})
		return &emptypb.Empty{}, nil
	}
	f.finishLogin(req.GetUsername())
	return &emptypb.Empty{}, nil
}

func (f *FakeBridge) Login2FA(_ context.Context, req *pb.LoginRequest) (*emptypb.Empty, error) {
	raw, _ := base64.StdEncoding.DecodeString(string(req.GetPassword()))
	if string(raw) != f.sc.WantTOTP {
		f.Emit(&pb.LoginEvent{Event: &pb.LoginEvent_Error{Error: &pb.LoginErrorEvent{Type: pb.LoginErrorType_TFA_ERROR}}})
		return &emptypb.Empty{}, nil
	}
	f.finishLogin(req.GetUsername())
	return &emptypb.Empty{}, nil
}

// FinishLoginAs records the logged-in user (so GetUser returns it) without
// emitting a Finished event.
func (f *FakeBridge) FinishLoginAs(username string) {
	f.mu.Lock()
	f.finishedUserID = "user-" + username
	f.finishedName = username
	f.finishedAddrs = []string{username}
	f.mu.Unlock()
}

func (f *FakeBridge) finishLogin(username string) {
	f.FinishLoginAs(username)
	f.Emit(&pb.LoginEvent{Event: &pb.LoginEvent_Finished{Finished: &pb.LoginFinishedEvent{UserID: "user-" + username}}})
}

func (f *FakeBridge) RunEventStream(_ *pb.EventStreamRequest, stream grpc.ServerStreamingServer[pb.StreamEvent]) error {
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-f.events:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (f *FakeBridge) StopEventStream(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (f *FakeBridge) LoginAbort(context.Context, *pb.LoginAbortRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (f *FakeBridge) MailServerSettings(context.Context, *emptypb.Empty) (*pb.ImapSmtpSettings, error) {
	return &pb.ImapSmtpSettings{ImapPort: int32(f.sc.ImapPort), UseSSLForImap: f.sc.ImapUseSSL}, nil
}

// Emit wraps a login event in a StreamEvent and queues it for the active stream.
func (f *FakeBridge) Emit(le *pb.LoginEvent) {
	f.events <- &pb.StreamEvent{Event: &pb.StreamEvent_Login{Login: le}}
}

const fakeToken = "test-token"

// StartFakeBridge launches the fake over a TLS unix socket and writes a
// grpcServerConfig.json pointing at it. It returns the config path.
func StartFakeBridge(t *testing.T, sc Scenario) string {
	t.Helper()

	certPEM, keyPEM := GenCert(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}

	sock := filepath.Join(t.TempDir(), "bridge.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
		grpc.UnaryInterceptor(unaryTokenCheck),
		grpc.StreamInterceptor(streamTokenCheck),
	)
	pb.RegisterBridgeServer(srv, &FakeBridge{sc: sc, events: make(chan *pb.StreamEvent, 16)})

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	cfg := struct {
		Port           int    `json:"port"`
		Cert           string `json:"cert"`
		Token          string `json:"token"`
		FileSocketPath string `json:"fileSocketPath"`
	}{Cert: string(certPEM), Token: fakeToken, FileSocketPath: sock}

	configPath := filepath.Join(t.TempDir(), "grpcServerConfig.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

func unaryTokenCheck(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if err := checkToken(ctx); err != nil {
		return nil, err
	}
	return h(ctx, req)
}

func streamTokenCheck(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if err := checkToken(ss.Context()); err != nil {
		return err
	}
	return h(srv, ss)
}

func checkToken(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if vals := md.Get("server-token"); len(vals) != 1 || vals[0] != fakeToken {
		return status.Error(codes.Unauthenticated, "bad server token")
	}
	return nil
}

// StartFakeIMAPServer starts a minimal IMAP server handling only LOGIN and
// LOGOUT (no SELECT/FETCH), used to exercise bridge.ProbeIMAPLogin without a
// real bridge. Returns the listening port.
func StartFakeIMAPServer(t *testing.T, wantUser, wantPass string, useTLS bool) int {
	t.Helper()

	var lis net.Listener
	var err error
	if useTLS {
		certPEM, keyPEM := GenCert(t)
		cert, cerr := tls.X509KeyPair(certPEM, keyPEM)
		if cerr != nil {
			t.Fatalf("key pair: %v", cerr)
		}
		lis, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	} else {
		lis, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go serveFakeIMAPConn(conn, wantUser, wantPass)
		}
	}()

	return lis.Addr().(*net.TCPAddr).Port
}

var imapLoginRe = regexp.MustCompile(`^(\S+) LOGIN "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"$`)

func unquoteIMAP(s string) string {
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

func serveFakeIMAPConn(conn net.Conn, wantUser, wantPass string) {
	defer conn.Close()
	_, _ = conn.Write([]byte("* OK fake imap ready\r\n"))

	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if m := imapLoginRe.FindStringSubmatch(line); m != nil {
			tag, user, pass := m[1], unquoteIMAP(m[2]), unquoteIMAP(m[3])
			if user == wantUser && pass == wantPass {
				_, _ = conn.Write([]byte(tag + " OK LOGIN completed\r\n"))
			} else {
				_, _ = conn.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] no such user\r\n"))
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[1], "LOGOUT") {
			_, _ = conn.Write([]byte("* BYE logging out\r\n" + fields[0] + " OK LOGOUT completed\r\n"))
			return
		}
	}
}

// GenCert generates a self-signed ECDSA cert/key pair for 127.0.0.1, usable
// for both the fake gRPC server and a fake IMAP TLS listener.
func GenCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
