package bridge_test

import (
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

// scenario configures the fake bridge's behaviour for one test.
type scenario struct {
	users        []*pb.User // returned by GetUserList before login
	wantPassword string     // raw password the fake accepts
	wantTOTP     string     // raw TOTP the fake accepts (empty => no 2FA prompt)
	imapPassword []byte     // User.password reported after a successful login
	loginEmits   func(s *fakeBridge, username string)
}

// fakeBridge implements pb.BridgeServer for the login/connection tests.
type fakeBridge struct {
	pb.UnimplementedBridgeServer
	sc     scenario
	events chan *pb.StreamEvent

	mu             sync.Mutex
	loggedOut      []string
	finishedUserID string
	finishedAddrs  []string
	finishedName   string
}

func (f *fakeBridge) GetUserList(context.Context, *emptypb.Empty) (*pb.UserListResponse, error) {
	return &pb.UserListResponse{Users: f.sc.users}, nil
}

func (f *fakeBridge) GetUser(_ context.Context, id *wrapperspb.StringValue) (*pb.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.User{
		Id:        id.GetValue(),
		Username:  f.finishedName,
		Addresses: f.finishedAddrs,
		Password:  f.sc.imapPassword,
		State:     pb.UserState_CONNECTED,
	}, nil
}

func (f *fakeBridge) LogoutUser(_ context.Context, id *wrapperspb.StringValue) (*emptypb.Empty, error) {
	f.mu.Lock()
	f.loggedOut = append(f.loggedOut, id.GetValue())
	f.mu.Unlock()
	return &emptypb.Empty{}, nil
}

func (f *fakeBridge) Login(_ context.Context, req *pb.LoginRequest) (*emptypb.Empty, error) {
	raw, _ := base64.StdEncoding.DecodeString(string(req.GetPassword()))
	if string(raw) != f.sc.wantPassword {
		f.emit(&pb.LoginEvent{Event: &pb.LoginEvent_Error{Error: &pb.LoginErrorEvent{Type: pb.LoginErrorType_USERNAME_PASSWORD_ERROR}}})
		return &emptypb.Empty{}, nil
	}
	if f.sc.loginEmits != nil {
		f.sc.loginEmits(f, req.GetUsername())
		return &emptypb.Empty{}, nil
	}
	if f.sc.wantTOTP != "" {
		f.emit(&pb.LoginEvent{Event: &pb.LoginEvent_TfaRequested{TfaRequested: &pb.LoginTfaRequestedEvent{Username: req.GetUsername()}}})
		return &emptypb.Empty{}, nil
	}
	f.finishLogin(req.GetUsername())
	return &emptypb.Empty{}, nil
}

func (f *fakeBridge) Login2FA(_ context.Context, req *pb.LoginRequest) (*emptypb.Empty, error) {
	raw, _ := base64.StdEncoding.DecodeString(string(req.GetPassword()))
	if string(raw) != f.sc.wantTOTP {
		f.emit(&pb.LoginEvent{Event: &pb.LoginEvent_Error{Error: &pb.LoginErrorEvent{Type: pb.LoginErrorType_TFA_ERROR}}})
		return &emptypb.Empty{}, nil
	}
	f.finishLogin(req.GetUsername())
	return &emptypb.Empty{}, nil
}

// finishLoginAs records the logged-in user (so GetUser returns it) without
// emitting a Finished event.
func (f *fakeBridge) finishLoginAs(username string) {
	f.mu.Lock()
	f.finishedUserID = "user-" + username
	f.finishedName = username
	f.finishedAddrs = []string{username}
	f.mu.Unlock()
}

func (f *fakeBridge) finishLogin(username string) {
	f.finishLoginAs(username)
	f.emit(&pb.LoginEvent{Event: &pb.LoginEvent_Finished{Finished: &pb.LoginFinishedEvent{UserID: "user-" + username}}})
}

func (f *fakeBridge) RunEventStream(_ *pb.EventStreamRequest, stream grpc.ServerStreamingServer[pb.StreamEvent]) error {
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

func (f *fakeBridge) StopEventStream(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (f *fakeBridge) LoginAbort(context.Context, *pb.LoginAbortRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// emit wraps a login event in a StreamEvent and queues it for the active stream.
func (f *fakeBridge) emit(le *pb.LoginEvent) {
	f.events <- &pb.StreamEvent{Event: &pb.StreamEvent_Login{Login: le}}
}

const fakeToken = "test-token"

// startFakeBridge launches the fake over a TLS unix socket and writes a
// grpcServerConfig.json pointing at it. It returns the config path.
func startFakeBridge(t *testing.T, sc scenario) string {
	t.Helper()

	certPEM, keyPEM := genCert(t)
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
	pb.RegisterBridgeServer(srv, &fakeBridge{sc: sc, events: make(chan *pb.StreamEvent, 16)})

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

func genCert(t *testing.T) (certPEM, keyPEM []byte) {
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
