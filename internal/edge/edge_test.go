//go:build linux

package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/config"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/registry"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/status"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func TestRandomID(t *testing.T) {
	first, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 24 || strings.Trim(first, "0123456789abcdef") != "" {
		t.Fatalf("got invalid session identifier %q", first)
	}
	if first == second {
		t.Fatal("expected unique session identifiers")
	}
}

func TestDynamicRegistryRefreshAndUnknownDNS(t *testing.T) {
	ctx := context.Background()
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	request := registry.PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "production", ProjectAlias: "shop", EnvironmentAlias: "production", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32)}
	if _, _, err := store.CreatePending(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Approve(ctx, registry.Approval{RequestID: request.ID, ProviderID: "provider", JTI: "jti", JTIExpiresAt: time.Now().Add(time.Minute), LeaseClass: "persistent", LeaseDuration: time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16")}); err != nil {
		t.Fatal(err)
	}
	state := status.New("test")
	cfg := config.Edge{VirtualNetwork: netip.MustParsePrefix("fd40::/16"), MaxTCPFlows: 10, MaxUDPFlows: 10, UDPIdleTimeout: time.Second}
	server, err := NewWithStore(ctx, cfg, store, slog.Default(), state)
	if err != nil || len(server.routes) != 1 || server.routes[0].target.VirtualPrefix != netip.MustParsePrefix("fd40::/16") {
		t.Fatalf("NewWithStore() routes=%v err=%v", server.routes, err)
	}
	if state.Snapshot().ConfiguredConnectors != 1 {
		t.Fatalf("dynamic status = %#v", state.Snapshot())
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	query := new(dns.Msg)
	query.SetQuestion("api.unknown.preview.railway.internal.", dns.TypeAAAA)
	payload, _ := query.Pack()
	server.forwardDNS(ctx, listener, client.LocalAddr().(*net.UDPAddr), payload)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 2048)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(buffer[:n]); err != nil || response.Rcode != dns.RcodeNameError {
		t.Fatalf("DNS response = %#v, %v", response, err)
	}
	query.SetQuestion("api.shop.production.railway.internal.", dns.TypeAAAA)
	payload, _ = query.Pack()
	server.forwardDNS(ctx, listener, client.LocalAddr().(*net.UDPAddr), payload)
	n, err = client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Unpack(buffer[:n]); err != nil || response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("inactive connector DNS response = %#v, %v", response, err)
	}
	server.forwardDNS(ctx, listener, client.LocalAddr().(*net.UDPAddr), []byte("invalid"))
	if address, err := listenerInterfaceAddress("127.0.0.1:53"); err != nil || address.Port != 53 {
		t.Fatalf("listenerInterfaceAddress() = %v, %v", address, err)
	}
	if _, err := listenerInterfaceAddress("missing-interface:53"); err == nil {
		t.Fatal("listenerInterfaceAddress() accepted a missing interface")
	}
	policy := reconciledPolicy{policy: &edgeFakePolicy{}, server: server}
	if err := policy.Replace(ctx, []netip.Prefix{netip.MustParsePrefix("fd40::/16")}); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, "project", "environment", time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshDynamic(ctx); err != nil {
		t.Fatal(err)
	}
	if len(server.registry) != 0 || len(server.routes) != 0 {
		t.Fatalf("refreshDynamic() retained inactive entries: registry=%d routes=%d", len(server.registry), len(server.routes))
	}
}

type edgeFakePolicy struct{ routes []netip.Prefix }

func (*edgeFakePolicy) Apply(context.Context) error { return nil }

func (p *edgeFakePolicy) Replace(_ context.Context, routes []netip.Prefix) error {
	p.routes = append([]netip.Prefix(nil), routes...)
	return nil
}

func (*edgeFakePolicy) Close(context.Context) error { return nil }

func TestAcceptDNS(t *testing.T) {
	server := testServer(1)
	listener := testUDPListener(t)
	client, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.acceptDNS(ctx, listener) }()
	query := new(dns.Msg)
	query.SetQuestion("api.outside.example.", dns.TypeAAAA)
	payload, _ := query.Pack()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 2048)
	if _, err := client.Read(buffer); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectionClosed(t *testing.T) {
	client, server, cleanup := testQUICPair(t)
	defer cleanup()
	if connectionClosed(server) {
		t.Fatal("expected an open connection")
	}
	if err := client.CloseWithError(0, "test complete"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("the server connection did not close")
	}
	if !connectionClosed(server) {
		t.Fatal("expected a closed connection")
	}
}

func TestAuthenticateDynamicConnector(t *testing.T) {
	ctx := context.Background()
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	identityKey := make([]byte, ed25519.PublicKeySize)
	identityKey[0] = 1
	keyID := registry.Fingerprint(identityKey)
	request := registry.PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "production", ProjectAlias: "shop", EnvironmentAlias: "production", IdentityKey: identityKey, TransportKey: make([]byte, ed25519.PublicKeySize), Proof: make([]byte, 32)}
	if _, _, err := store.CreatePending(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Approve(ctx, registry.Approval{RequestID: request.ID, ProviderID: "provider", JTI: "jti", JTIExpiresAt: time.Now().Add(time.Minute), LeaseClass: "persistent", LeaseDuration: time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16")}); err != nil {
		t.Fatal(err)
	}
	client, connection, cleanup := testQUICPairWithIdentity(t, protocol.ALPNV3, "/connector/project/environment/"+keyID)
	defer cleanup()
	cfg := config.Edge{VirtualNetwork: netip.MustParsePrefix("fd40::/16"), AllowedRoutes: []netip.Prefix{netip.MustParsePrefix("fd12::/16")}, MaxTCPFlows: 4, MaxUDPFlows: 4, UDPIdleTimeout: time.Second}
	server, err := NewWithStore(ctx, cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)), status.New("test"))
	if err != nil {
		t.Fatal(err)
	}
	done := startAuthentication(server, connection)
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := protocol.ConnectorHelloV3{ProtocolVersion: protocol.ProtocolVersionV3, ProjectID: "project", EnvironmentID: "environment", IdentityKeyID: keyID, SoftwareVersion: "test", StartedUnixNano: time.Now().UnixNano(), Routes: []string{"fd12::/16"}}
	if err := protocol.WriteFrame(stream, hello); err != nil {
		t.Fatal(err)
	}
	var accepted protocol.ConnectorAccepted
	if err := protocol.ReadFrame(stream, &accepted); err != nil || accepted.VirtualPrefix != "fd40::/16" {
		t.Fatalf("dynamic acceptance = %#v, %v", accepted, err)
	}
	if err := client.CloseWithError(0, "test complete"); err != nil {
		t.Fatal(err)
	}
	waitForAuthentication(t, done)
	registration, err := store.Registration(ctx, "project", "environment")
	if err != nil || registration.State != "ready" {
		t.Fatalf("dynamic registration = %#v, %v", registration, err)
	}
}

type fakePolicy struct {
	applyErr error
	closed   bool
}

func (p *fakePolicy) Apply(context.Context) error                   { return p.applyErr }
func (p *fakePolicy) Replace(context.Context, []netip.Prefix) error { return p.applyErr }
func (p *fakePolicy) Close(context.Context) error                   { p.closed = true; return nil }

func TestRunReportsNetworkStartupFailures(t *testing.T) {
	originalWait := waitForNetwork
	originalCreate := createPolicy
	t.Cleanup(func() {
		waitForNetwork = originalWait
		createPolicy = originalCreate
	})
	server := testServer(1)

	waitForNetwork = func(context.Context) error { return errors.New("wait failed") }
	if err := server.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "wait for tailscale0") {
		t.Fatalf("Run() error = %v, want a network readiness error", err)
	}

	waitForNetwork = func(context.Context) error { return nil }
	createPolicy = func([]netip.Prefix, string, string) (networkPolicy, error) {
		return nil, errors.New("create failed")
	}
	if err := server.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "create failed") {
		t.Fatalf("Run() error = %v, want a policy creation error", err)
	}

	policy := &fakePolicy{applyErr: errors.New("apply failed")}
	createPolicy = func([]netip.Prefix, string, string) (networkPolicy, error) { return policy, nil }
	if err := server.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("Run() error = %v, want a policy application error", err)
	}

	policy = &fakePolicy{}
	createPolicy = func([]netip.Prefix, string, string) (networkPolicy, error) { return policy, nil }
	if err := server.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "configure TLS") {
		t.Fatalf("Run() error = %v, want a TLS configuration error", err)
	}
	if !policy.closed {
		t.Fatal("Run() did not close the network policy after a later startup failure")
	}
}

func TestRunReportsListenerStartupFailures(t *testing.T) {
	originalWait := waitForNetwork
	originalCreate := createPolicy
	originalQUIC := listenQUIC
	originalTCP := listenTCP
	originalUDP := listenUDP
	t.Cleanup(func() {
		waitForNetwork = originalWait
		createPolicy = originalCreate
		listenQUIC = originalQUIC
		listenTCP = originalTCP
		listenUDP = originalUDP
	})
	waitForNetwork = func(context.Context) error { return nil }
	createPolicy = func([]netip.Prefix, string, string) (networkPolicy, error) { return &fakePolicy{}, nil }

	newServer := func() *Server {
		server := testServer(1)
		server.config.Common = testCommon(t)
		server.config.QUICListenAddr = "127.0.0.1:0"
		server.config.TCPListenAddr = "127.0.0.1:0"
		server.config.UDPListenAddr = "127.0.0.1:0"
		return server
	}

	server := newServer()
	server.config.QUICListenAddr = "invalid"
	if err := server.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "listen for QUIC") {
		t.Fatalf("Run() error = %v, want a QUIC listener error", err)
	}

	listenTCP = func(string) (net.Listener, error) { return nil, errors.New("TCP listen failed") }
	if err := newServer().Run(context.Background()); err == nil || !strings.Contains(err.Error(), "listen for transparent TCP") {
		t.Fatalf("Run() error = %v, want a TCP listener error", err)
	}

	listenTCP = func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	listenUDP = func(string) (*net.UDPConn, error) { return nil, errors.New("UDP listen failed") }
	if err := newServer().Run(context.Background()); err == nil || !strings.Contains(err.Error(), "listen for transparent UDP") {
		t.Fatalf("Run() error = %v, want a UDP listener error", err)
	}
}

func TestRunDynamicServicesUntilCancellation(t *testing.T) {
	originalWait := waitForNetwork
	originalCreate := createPolicy
	originalTCP := listenTCP
	originalUDP := listenUDP
	t.Cleanup(func() {
		waitForNetwork = originalWait
		createPolicy = originalCreate
		listenTCP = originalTCP
		listenUDP = originalUDP
	})
	waitForNetwork = func(context.Context) error { return nil }
	listenTCP = func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	listenUDP = func(string) (*net.UDPConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	policy := &fakePolicy{}
	createPolicy = func([]netip.Prefix, string, string) (networkPolicy, error) { return policy, nil }
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(context.Background(), netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Edge{Common: testCommon(t), VirtualNetwork: netip.MustParsePrefix("fd40::/16"), QUICListenAddr: "127.0.0.1:0", TCPListenAddr: "127.0.0.1:0", UDPListenAddr: "127.0.0.1:0", DNSListenAddr: "127.0.0.1:0", MaxTCPFlows: 4, MaxUDPFlows: 4, UDPIdleTimeout: time.Second, ReconcileInterval: time.Millisecond, SlotQuarantine: time.Hour}
	server, err := NewWithStore(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)), status.New("test"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := server.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !policy.closed {
		t.Fatal("Run() did not close the dynamic network policy")
	}
}

type errorListener struct{}

func (errorListener) Accept() (net.Conn, error) { return nil, errors.New("listener failed") }
func (errorListener) Close() error              { return nil }
func (errorListener) Addr() net.Addr            { return stringAddress("127.0.0.1:0") }

func TestRunPropagatesActiveListenerFailures(t *testing.T) {
	originalWait := waitForNetwork
	originalCreate := createPolicy
	originalQUIC := listenQUIC
	originalTCP := listenTCP
	originalUDP := listenUDP
	t.Cleanup(func() {
		waitForNetwork = originalWait
		createPolicy = originalCreate
		listenQUIC = originalQUIC
		listenTCP = originalTCP
		listenUDP = originalUDP
	})
	waitForNetwork = func(context.Context) error { return nil }
	createPolicy = func([]netip.Prefix, string, string) (networkPolicy, error) { return &fakePolicy{}, nil }
	newServer := func() *Server {
		server := testServer(1)
		server.config.Common = testCommon(t)
		server.config.QUICListenAddr = "127.0.0.1:0"
		server.config.TCPListenAddr = "127.0.0.1:0"
		server.config.UDPListenAddr = "127.0.0.1:0"
		return server
	}

	t.Run("TCP", func(t *testing.T) {
		listenTCP = func(string) (net.Listener, error) { return errorListener{}, nil }
		listenUDP = func(string) (*net.UDPConn, error) {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}
		if err := newServer().Run(context.Background()); err == nil || !strings.Contains(err.Error(), "accept TCP") {
			t.Fatalf("Run() error = %v, want an active TCP listener error", err)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		listenTCP = func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
		listenUDP = func(string) (*net.UDPConn, error) {
			connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			_ = connection.Close()
			return connection, nil
		}
		if err := newServer().Run(context.Background()); err == nil || !strings.Contains(err.Error(), "receive UDP") {
			t.Fatalf("Run() error = %v, want an active UDP listener error", err)
		}
	})

	t.Run("QUIC", func(t *testing.T) {
		listenTCP = func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
		listenUDP = func(string) (*net.UDPConn, error) {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}
		listenQUIC = func(address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Listener, error) {
			listener, err := originalQUIC(address, tlsConfig, quicConfig)
			if err == nil {
				_ = listener.Close()
			}
			return listener, err
		}
		if err := newServer().Run(context.Background()); err == nil || !strings.Contains(err.Error(), "accept connector") {
			t.Fatalf("Run() error = %v, want an active QUIC listener error", err)
		}
	})
}

func TestRunMonitorsTailscale(t *testing.T) {
	originalStart := startTailscale
	originalWait := waitForNetwork
	originalCreate := createPolicy
	originalTCP := listenTCP
	originalUDP := listenUDP
	t.Cleanup(func() {
		startTailscale = originalStart
		waitForNetwork = originalWait
		createPolicy = originalCreate
		listenTCP = originalTCP
		listenUDP = originalUDP
	})
	server := testServer(1)
	server.config.ManageTailscale = true
	startTailscale = func(context.Context, *slog.Logger) (*managedProcess, error) {
		return nil, errors.New("start failed")
	}
	if err := server.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "start Tailscale") {
		t.Fatalf("Run() error = %v, want a Tailscale start error", err)
	}

	stopped := make(chan error, 1)
	stopped <- nil
	startTailscale = func(context.Context, *slog.Logger) (*managedProcess, error) {
		return &managedProcess{done: stopped, kill: func() error { return nil }}, nil
	}
	waitForNetwork = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := server.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "before it became ready") {
		t.Fatalf("Run() error = %v, want an early Tailscale exit", err)
	}

	waitForNetwork = func(context.Context) error { return nil }
	createPolicy = func([]netip.Prefix, string, string) (networkPolicy, error) { return &fakePolicy{}, nil }
	listenTCP = func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	listenUDP = func(string) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	stopped = make(chan error, 1)
	startTailscale = func(context.Context, *slog.Logger) (*managedProcess, error) {
		return &managedProcess{done: stopped, kill: func() error { return nil }}, nil
	}
	server = testServer(1)
	server.config.Common = testCommon(t)
	server.config.ManageTailscale = true
	server.config.QUICListenAddr = "127.0.0.1:0"
	server.config.TCPListenAddr = "127.0.0.1:0"
	server.config.UDPListenAddr = "127.0.0.1:0"
	result := make(chan error, 1)
	go func() { result <- server.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	stopped <- errors.New("containerboot failed")
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "Tailscale stopped") || strings.Contains(err.Error(), "before it became ready") {
			t.Fatalf("Run() error = %v, want an active Tailscale exit", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after Tailscale exited")
	}
}

type addressedConnection struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *addressedConnection) LocalAddr() net.Addr  { return c.local }
func (c *addressedConnection) RemoteAddr() net.Addr { return c.remote }

type stringAddress string

func (a stringAddress) Network() string { return "test" }
func (a stringAddress) String() string  { return string(a) }

func TestHandleTCPRejectsInvalidAndUnavailableDestinations(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		prepare     func(*Server)
	}{
		{name: "invalid destination", destination: "invalid"},
		{name: "route denied", destination: "192.0.2.1:80"},
		{name: "session unavailable", destination: "10.0.0.1:80"},
		{name: "session draining", destination: "10.0.0.1:80", prepare: func(server *Server) {
			active := &session{routes: server.config.AllowedRoutes}
			active.draining.Store(true)
			server.session.Store(active)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := testServer(1)
			if test.prepare != nil {
				test.prepare(server)
			}
			client, peer := net.Pipe()
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			server.handleTCP(context.Background(), &addressedConnection{Conn: client, local: stringAddress(test.destination), remote: stringAddress("192.0.2.2:1234")})
		})
	}
}

func TestHandleTCPReturnsConnectorRejection(t *testing.T) {
	clientQUIC, edgeQUIC, cleanup := testQUICPair(t)
	defer cleanup()
	server := testServer(1)
	server.session.Store(&session{id: "test", connection: edgeQUIC, routes: server.config.AllowedRoutes})
	connectorDone := make(chan error, 1)
	go func() {
		stream, err := clientQUIC.AcceptStream(context.Background())
		if err != nil {
			connectorDone <- err
			return
		}
		var request protocol.OpenTCP
		if err := protocol.ReadFrame(stream, &request); err != nil {
			connectorDone <- err
			return
		}
		connectorDone <- protocol.WriteFrame(stream, protocol.OpenTCPResult{Code: "DESTINATION_UNREACHABLE"})
	}()
	client, peer := net.Pipe()
	defer peer.Close()
	server.handleTCP(context.Background(), &addressedConnection{Conn: client, local: stringAddress("10.0.0.1:80"), remote: stringAddress("192.0.2.2:1234")})
	if err := <-connectorDone; err != nil {
		t.Fatal(err)
	}
}

func TestHandleTCPHandlesStreamFailures(t *testing.T) {
	t.Run("open stream", func(t *testing.T) {
		clientQUIC, edgeQUIC, cleanup := testQUICPair(t)
		defer cleanup()
		_ = clientQUIC.CloseWithError(0, "closed")
		<-edgeQUIC.Context().Done()
		server := testServer(1)
		server.session.Store(&session{id: "test", connection: edgeQUIC, routes: server.config.AllowedRoutes})
		client, peer := net.Pipe()
		defer peer.Close()
		server.handleTCP(context.Background(), &addressedConnection{Conn: client, local: stringAddress("10.0.0.1:80"), remote: stringAddress("192.0.2.2:1234")})
	})

	t.Run("read result", func(t *testing.T) {
		clientQUIC, edgeQUIC, cleanup := testQUICPair(t)
		defer cleanup()
		server := testServer(1)
		server.session.Store(&session{id: "test", connection: edgeQUIC, routes: server.config.AllowedRoutes})
		connectorDone := make(chan struct{})
		go func() {
			defer close(connectorDone)
			stream, err := clientQUIC.AcceptStream(context.Background())
			if err != nil {
				return
			}
			var request protocol.OpenTCP
			_ = protocol.ReadFrame(stream, &request)
			stream.CancelRead(1)
			stream.CancelWrite(1)
		}()
		client, peer := net.Pipe()
		defer peer.Close()
		server.handleTCP(context.Background(), &addressedConnection{Conn: client, local: stringAddress("10.0.0.1:80"), remote: stringAddress("192.0.2.2:1234")})
		<-connectorDone
	})
}

func TestProcessStoppedError(t *testing.T) {
	if err := processStoppedError("stopped", nil); err == nil || err.Error() != "stopped" {
		t.Fatalf("processStoppedError() = %v", err)
	}
	cause := errors.New("failed")
	if err := processStoppedError("stopped", cause); !errors.Is(err, cause) {
		t.Fatalf("processStoppedError() = %v, want wrapped cause", err)
	}
}

func TestAuthenticateRejectsInvalidHello(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name  string
		hello protocol.ConnectorHello
	}{
		{
			name: "protocol version",
			hello: protocol.ConnectorHello{
				ProtocolVersion: "1.0",
				ConnectorID:     "railway-production",
				Environment:     "production",
				StartedUnixNano: now.UnixNano(),
				Routes:          []string{"10.1.0.0/16"},
			},
		},
		{
			name: "connector identity",
			hello: protocol.ConnectorHello{
				ProtocolVersion: protocol.ProtocolVersion,
				ConnectorID:     "other",
				Environment:     "production",
				StartedUnixNano: now.UnixNano(),
				Routes:          []string{"10.1.0.0/16"},
			},
		},
		{
			name: "zero start time",
			hello: protocol.ConnectorHello{
				ProtocolVersion: protocol.ProtocolVersion,
				ConnectorID:     "railway-production",
				Environment:     "production",
				Routes:          []string{"10.1.0.0/16"},
			},
		},
		{
			name: "future start time",
			hello: protocol.ConnectorHello{
				ProtocolVersion: protocol.ProtocolVersion,
				ConnectorID:     "railway-production",
				Environment:     "production",
				StartedUnixNano: now.Add(6 * time.Minute).UnixNano(),
				Routes:          []string{"10.1.0.0/16"},
			},
		},
		{
			name: "malformed route",
			hello: protocol.ConnectorHello{
				ProtocolVersion: protocol.ProtocolVersion,
				ConnectorID:     "railway-production",
				Environment:     "production",
				StartedUnixNano: now.UnixNano(),
				Routes:          []string{"invalid"},
			},
		},
		{
			name: "empty route intersection",
			hello: protocol.ConnectorHello{
				ProtocolVersion: protocol.ProtocolVersion,
				ConnectorID:     "railway-production",
				Environment:     "production",
				StartedUnixNano: now.UnixNano(),
				Routes:          []string{"192.0.2.0/24"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := testServer(1)
			client, connection, cleanup := testQUICPair(t)
			defer cleanup()
			done := startAuthentication(server, connection)
			writeHello(t, client, test.hello)
			waitForApplicationError(t, client, 3)
			waitForAuthentication(t, done)
		})
	}
}

func TestAuthenticateRejectsMissingAndMalformedControl(t *testing.T) {
	t.Run("missing stream", func(t *testing.T) {
		server := testServer(1)
		client, connection, cleanup := testQUICPair(t)
		defer cleanup()
		done := startAuthentication(server, connection)
		_ = client.CloseWithError(0, "missing control")
		waitForAuthentication(t, done)
	})
	t.Run("malformed frame", func(t *testing.T) {
		server := testServer(1)
		client, connection, cleanup := testQUICPair(t)
		defer cleanup()
		done := startAuthentication(server, connection)
		stream, err := client.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte{0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		waitForApplicationError(t, client, 2)
		waitForAuthentication(t, done)
	})
}

func TestAuthenticateAcceptsNarrowerRoute(t *testing.T) {
	server := testServer(1)
	client, connection, cleanup := testQUICPair(t)
	defer cleanup()
	done := startAuthentication(server, connection)
	stream := writeHello(t, client, protocol.ConnectorHello{
		ProtocolVersion: protocol.ProtocolVersion,
		ConnectorID:     "railway-production",
		Environment:     "production",
		StartedUnixNano: time.Now().UnixNano(),
		Routes:          []string{"10.20.0.0/16"},
	})
	if err := stream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var accepted protocol.ConnectorAccepted
	if err := protocol.ReadFrame(stream, &accepted); err != nil {
		t.Fatal(err)
	}
	if len(accepted.Routes) != 1 || accepted.Routes[0] != "10.20.0.0/16" {
		t.Fatalf("got accepted routes %v", accepted.Routes)
	}
	if accepted.SessionID == "" {
		t.Fatal("expected a session identifier")
	}
	if accepted.MaxTCPFlows != 1 {
		t.Fatalf("got TCP flow limit %d", accepted.MaxTCPFlows)
	}
	deadline := time.Now().Add(time.Second)
	active := server.session.Load()
	for active == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		active = server.session.Load()
	}
	if active == nil || active.id != accepted.SessionID {
		t.Fatal("the server did not store the accepted session")
	}
	if err := client.CloseWithError(0, "test complete"); err != nil {
		t.Fatal(err)
	}
	waitForAuthentication(t, done)
}

func TestAuthenticateRejectsOlderSession(t *testing.T) {
	server := testServer(1)
	oldClient, currentConnection, oldCleanup := testQUICPair(t)
	defer oldCleanup()
	started := time.Now().UnixNano()
	server.session.Store(&session{id: "current", started: started, connection: currentConnection})

	client, connection, cleanup := testQUICPair(t)
	defer cleanup()
	done := startAuthentication(server, connection)
	writeHello(t, client, protocol.ConnectorHello{
		ProtocolVersion: protocol.ProtocolVersion,
		ConnectorID:     "railway-production",
		Environment:     "production",
		StartedUnixNano: started - 1,
		Routes:          []string{"10.20.0.0/16"},
	})
	waitForApplicationError(t, client, 5)
	waitForAuthentication(t, done)
	if server.session.Load().id != "current" {
		t.Fatal("the older session replaced the current session")
	}
	_ = oldClient.CloseWithError(0, "test complete")
}

func TestEdgeUDPFlowRejectsCapacity(t *testing.T) {
	server := testServer(1)
	server.udpByID[1] = &edgeUDPFlow{id: 1}
	_, err := server.edgeUDPFlow(
		&session{id: "test"},
		"flow",
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234},
		netip.MustParseAddrPort("192.0.2.2:53"),
	)
	if err == nil || err.Error() != "the UDP flow limit is full" {
		t.Fatalf("got error %v", err)
	}
}

func TestEdgeUDPFlowCreationReuseExpiryAndFailure(t *testing.T) {
	original := openUDPResponse
	t.Cleanup(func() { openUDPResponse = original })
	openUDPResponse = func(netip.AddrPort) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	server := testServer(2)
	server.config.UDPIdleTimeout = 10 * time.Millisecond
	active := &session{id: "test"}
	source := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	destination := netip.MustParseAddrPort("192.0.2.2:53")
	flow, err := server.edgeUDPFlow(active, "flow", source, destination)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := server.edgeUDPFlow(active, "flow", source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if reused != flow {
		t.Fatal("edgeUDPFlow() did not reuse the active flow")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.udpMu.Lock()
		remaining := len(server.udpByID)
		server.udpMu.Unlock()
		if remaining == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	server.udpMu.Lock()
	remaining := len(server.udpByID)
	server.udpMu.Unlock()
	if remaining != 0 {
		t.Fatal("the inactive edge UDP flow did not expire")
	}

	openUDPResponse = func(netip.AddrPort) (*net.UDPConn, error) { return nil, errors.New("open failed") }
	if _, err := server.edgeUDPFlow(active, "failed", source, destination); err == nil {
		t.Fatal("edgeUDPFlow() ignored a response-socket failure")
	}
}

func TestCloseUDPSessionReleasesOnlyOwnedFlows(t *testing.T) {
	server := testServer(2)
	firstSession := &session{id: "first"}
	secondSession := &session{id: "second"}
	firstReply, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	secondReply, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	second := &edgeUDPFlow{id: 2, key: "second", session: secondSession, reply: secondReply}
	server.udpByID[1] = &edgeUDPFlow{id: 1, key: "first", session: firstSession, reply: firstReply}
	server.udpByID[2] = second
	server.udpByKey["first"] = server.udpByID[1]
	server.udpByKey["second"] = second
	server.status.UDPFlowStarted()
	server.status.UDPFlowStarted()

	server.closeUDPSession(firstSession)
	if len(server.udpByID) != 1 || len(server.udpByKey) != 1 || server.udpByID[2] != second || server.udpByKey["second"] != second {
		t.Fatal("closeUDPSession() changed a flow from another session")
	}
	if err := firstReply.SetReadDeadline(time.Now()); err == nil {
		t.Fatal("closeUDPSession() left the owned response socket open")
	}
	if err := secondReply.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("closeUDPSession() closed another session's response socket: %v", err)
	}
	server.closeUDPSession(secondSession)
}

func TestCloseUDPFlowsReleasesAllResponseSockets(t *testing.T) {
	server := testServer(2)
	first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server.udpByID[1] = &edgeUDPFlow{id: 1, reply: first}
	server.udpByID[2] = &edgeUDPFlow{id: 2, reply: second}
	server.udpByKey["first"] = server.udpByID[1]
	server.udpByKey["second"] = server.udpByID[2]
	server.status.UDPFlowStarted()
	server.status.UDPFlowStarted()

	server.closeUDPFlows()
	if len(server.udpByID) != 0 || len(server.udpByKey) != 0 {
		t.Fatal("closeUDPFlows() kept flow state")
	}
	for _, connection := range []*net.UDPConn{first, second} {
		if err := connection.SetReadDeadline(time.Now()); err == nil {
			t.Fatal("closeUDPFlows() left a response socket open")
		}
	}
}

func TestDNSFlowsUseDedicatedLimit(t *testing.T) {
	server := testServer(2)
	reply, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close()
	server.dnsFlowMax = 1
	active := &session{id: "connector"}
	source := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	destination := netip.MustParseAddrPort("[fd40::10]:53")
	if _, err := server.edgeUDPFlowWithReply(active, "first", source, destination, destination, reply, true); err != nil {
		t.Fatal(err)
	}
	if _, err := server.edgeUDPFlowWithReply(active, "second", source, destination, destination, reply, true); err == nil {
		t.Fatal("edgeUDPFlowWithReply() exceeded the DNS flow limit")
	}
	server.closeUDPSession(active)
	if server.dnsFlows != 0 {
		t.Fatalf("closeUDPSession() left %d DNS flows", server.dnsFlows)
	}
}

func TestReceiveUDPValidatesExactEndpoints(t *testing.T) {
	client, connection, cleanup := testQUICPair(t)
	defer cleanup()

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	reply, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close()

	server := testServer(1)
	destination := netip.MustParseAddrPort("192.0.2.10:53")
	source := receiver.LocalAddr().(*net.UDPAddr)
	active := &session{id: "current", connection: connection}
	server.udpByID[7] = &edgeUDPFlow{id: 7, session: active, source: source, destination: destination, reply: reply, lastUsed: time.Now()}
	done := make(chan struct{})
	go func() {
		server.receiveUDP(active)
		close(done)
	}()

	sendResponse := func(sourceAddress, destinationAddress netip.AddrPort, payload string) {
		t.Helper()
		packet, err := protocol.EncodeUDP(protocol.UDPDatagram{
			FlowID:      7,
			Response:    true,
			Source:      sourceAddress,
			Destination: destinationAddress,
			Payload:     []byte(payload),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.SendDatagram(packet); err != nil {
			t.Fatal(err)
		}
	}

	if err := client.SendDatagram([]byte("malformed")); err != nil {
		t.Fatal(err)
	}
	request, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: 7, Source: destination, Destination: source.AddrPort()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendDatagram(request); err != nil {
		t.Fatal(err)
	}
	unknown, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: 8, Response: true, Source: destination, Destination: source.AddrPort()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendDatagram(unknown); err != nil {
		t.Fatal(err)
	}
	server.udpMu.Lock()
	server.udpByID[7].session = &session{id: "foreign"}
	server.udpMu.Unlock()
	sendResponse(destination, source.AddrPort(), "wrong session")
	sendResponse(netip.MustParseAddrPort("192.0.2.11:53"), source.AddrPort(), "wrong source")
	sendResponse(destination, netip.MustParseAddrPort("127.0.0.1:1"), "wrong destination")
	if err := receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, _, err := receiver.ReadFromUDP(buffer); err == nil {
		t.Fatal("expected endpoint mismatches to be dropped")
	}

	server.udpMu.Lock()
	server.udpByID[7].session = active
	server.udpMu.Unlock()
	sendResponse(destination, source.AddrPort(), "accepted")
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := receiver.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "accepted" {
		t.Fatalf("got payload %q", got)
	}

	_ = client.CloseWithError(0, "test complete")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the UDP receiver did not stop")
	}
}

func TestAcceptTCPCancellationAndFailure(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = listener.Close()
		if err := testServer(1).acceptTCP(ctx, listener); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("listener failure", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_ = listener.Close()
		if err := testServer(1).acceptTCP(context.Background(), listener); err == nil {
			t.Fatal("expected a listener failure")
		}
	})
}

func TestAcceptTCPRejectsTrafficAtCapacity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(1)
	server.limit <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.acceptTCP(ctx, listener) }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("the edge kept a TCP connection above the flow limit")
	}
	_ = connection.Close()
	cancel()
	_ = listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAcceptUDPCancellationAndFailure(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		listener := testUDPListener(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = listener.Close()
		if err := testServer(1).acceptUDP(ctx, listener); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("listener failure", func(t *testing.T) {
		listener := testUDPListener(t)
		_ = listener.Close()
		if err := testServer(1).acceptUDP(context.Background(), listener); err == nil {
			t.Fatal("expected a listener failure")
		}
	})
}

func TestAcceptUDPDropsPacketsWithoutAnOriginalDestination(t *testing.T) {
	listener := testUDPListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- testServer(1).acceptUDP(ctx, listener) }()
	connection, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	time.Sleep(10 * time.Millisecond)
	cancel()
	_ = listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAcceptConnectorsCancellationAndFailure(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		listener := testQUICListener(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = listener.Close()
		if err := testServer(1).acceptConnectors(ctx, listener); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("listener failure", func(t *testing.T) {
		listener := testQUICListener(t)
		_ = listener.Close()
		if err := testServer(1).acceptConnectors(context.Background(), listener); err == nil {
			t.Fatal("expected a listener failure")
		}
	})
}

func testUDPListener(t *testing.T) *net.UDPConn {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func testServer(maxUDPFlows int64) *Server {
	return New(
		config.Edge{
			Common: config.Common{
				ConnectorID: "railway-production",
				Environment: "production",
			},
			AllowedRoutes:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			MaxTCPFlows:    1,
			MaxUDPFlows:    maxUDPFlows,
			UDPIdleTimeout: time.Second,
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		status.New("test"),
	)
}

func startAuthentication(server *Server, connection *quic.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		server.authenticate(context.Background(), connection)
		close(done)
	}()
	return done
}

func writeHello(t *testing.T, client *quic.Conn, hello protocol.ConnectorHello) *quic.Stream {
	t.Helper()
	stream, err := client.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(stream, hello); err != nil {
		t.Fatal(err)
	}
	return stream
}

func waitForApplicationError(t *testing.T, client *quic.Conn, code quic.ApplicationErrorCode) {
	t.Helper()
	select {
	case <-client.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("the edge did not reject the connector")
	}
	var applicationError *quic.ApplicationError
	if !errors.As(context.Cause(client.Context()), &applicationError) {
		t.Fatalf("got connection error %v", context.Cause(client.Context()))
	}
	if applicationError.ErrorCode != code {
		t.Fatalf("got application error code %d, want %d", applicationError.ErrorCode, code)
	}
}

func waitForAuthentication(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("authentication did not stop")
	}
}

func testQUICPair(t *testing.T) (*quic.Conn, *quic.Conn, func()) {
	return testQUICPairWithIdentity(t, protocol.ALPN, "/connector/railway-production")
}

func testQUICPairWithIdentity(t *testing.T, alpn, identityPath string) (*quic.Conn, *quic.Conn, func()) {
	t.Helper()
	certificate := testTLSCertificate(t)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequestClientCert, NextProtos: []string{alpn}}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *quic.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(context.Background())
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- connection
	}()
	clientTLS := &tls.Config{Certificates: []tls.Certificate{testTLSCertificateForIdentity(t, identityPath)}, InsecureSkipVerify: true, NextProtos: []string{alpn}}
	client, err := quic.DialAddr(context.Background(), listener.Addr().String(), clientTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server *quic.Conn
	select {
	case server = <-accepted:
	case err := <-acceptError:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("the QUIC listener did not accept the connection")
	}
	cleanup := func() {
		_ = client.CloseWithError(0, "test complete")
		_ = server.CloseWithError(0, "test complete")
		_ = listener.Close()
	}
	return client, server, cleanup
}

func testQUICListener(t *testing.T) *quic.Listener {
	t.Helper()
	certificate := testTLSCertificate(t)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequestClientCert, NextProtos: []string{protocol.ALPN}}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func testTLSCertificate(t *testing.T) tls.Certificate {
	return testTLSCertificateForIdentity(t, "/connector/railway-production")
}

func testTLSCertificateForIdentity(t *testing.T, identityPath string) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "spiffe", Host: "tailbridge.local", Path: identityPath}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func testCommon(t *testing.T) config.Common {
	t.Helper()
	certificate := testTLSCertificate(t)
	privateDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	return config.Common{
		ConnectorID: "railway-production",
		Environment: "production",
		CABundle:    certificatePEM,
		Certificate: certificatePEM,
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	}
}
