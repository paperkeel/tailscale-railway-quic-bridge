package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/registry"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/transport"
	"github.com/quic-go/quic-go"
)

func TestEnrollmentProofBindsIdentity(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	request := protocol.RegistrationRequest{ProjectID: "project", EnvironmentID: "environment", IdentityKey: public, TransportKey: public}
	proof := Proof([]byte("nonce"), request)
	if len(proof) != 32 || subtle.ConstantTimeCompare(proof, Proof([]byte("wrong"), request)) == 1 {
		t.Fatal("Proof() did not bind the enrollment nonce")
	}
	signature := ed25519.Sign(private, RenewalMessage(request))
	if !ed25519.Verify(public, RenewalMessage(request), signature) {
		t.Fatal("renewal signature did not verify")
	}
	request.EnvironmentID = "other"
	if ed25519.Verify(public, RenewalMessage(request), signature) {
		t.Fatal("renewal signature did not bind the environment")
	}
}

func TestLocalIdentityAndRegistrationServer(t *testing.T) {
	directory := t.TempDir()
	cfg := config.Connector{IdentityDir: directory, ProjectID: "project", EnvironmentID: "environment"}
	identity, err := loadOrCreate(cfg)
	if err != nil || len(publicKey(identity.IdentityKeyPEM)) != ed25519.PublicKeySize {
		t.Fatalf("loadOrCreate() = %#v, %v", identity, err)
	}
	loaded, err := loadOrCreate(cfg)
	if err != nil || string(loaded.IdentityKeyPEM) != string(identity.IdentityKeyPEM) {
		t.Fatalf("second loadOrCreate() = %#v, %v", loaded, err)
	}
	if err := save(filepath.Join(directory, "copy.json"), loaded); err != nil {
		t.Fatal(err)
	}

	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(context.Background(), netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	certificate, key := testIntermediate(t)
	edgeCfg := config.Edge{IntermediateCertificate: certificate, IntermediatePrivateKey: key, PreviewLease: 24 * time.Hour, PersistentLease: 30 * 24 * time.Hour}
	server, err := NewServer(edgeCfg, store, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.RegistrationRequest{Kind: "enroll", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "preview", ProjectAlias: "shop", EnvironmentAlias: "preview", IdentityKey: publicKey(identity.IdentityKeyPEM), TransportKey: publicKey(identity.TransportKeyPEM)}
	request.Proof = Proof([]byte("nonce"), request)
	response := server.process(context.Background(), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000}, request)
	if response.State != "pending" || response.RequestID == "" {
		t.Fatalf("registration response = %#v", response)
	}
	request.RequestID = response.RequestID
	if polled := server.process(context.Background(), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2000}, request); polled.State != "pending" {
		t.Fatalf("poll response = %#v", polled)
	}
	if _, _, err := store.Approve(context.Background(), registry.Approval{RequestID: response.RequestID, ProviderID: "provider", JTI: "jti", JTIExpiresAt: time.Now().Add(time.Minute), LeaseClass: "preview", LeaseDuration: 24 * time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16")}); err != nil {
		t.Fatal(err)
	}
	server.config.RegistrationFrozen = true
	renewal := protocol.RegistrationRequest{Kind: "renew", ProjectID: "project", EnvironmentID: "environment", IdentityKey: publicKey(identity.IdentityKeyPEM), TransportKey: publicKey(identity.TransportKeyPEM)}
	identityPrivate, err := privateKey(identity.IdentityKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	renewal.Proof = ed25519.Sign(identityPrivate, RenewalMessage(renewal))
	if renewed := server.process(context.Background(), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 3000}, renewal); renewed.State != "approved" || len(renewed.CertificatePEM) == 0 {
		t.Fatalf("renewal response = %#v", renewed)
	}
	request.RequestID = ""
	if frozen := server.process(context.Background(), &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1000}, request); frozen.State != "frozen" {
		t.Fatalf("frozen response = %#v", frozen)
	}
	if sourceHost(&net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 1}) != "192.0.2.3" || !server.allow("new-source") {
		t.Fatal("registration source helpers failed")
	}
}

func TestEnsureCompletesRegistrationExchange(t *testing.T) {
	common := registrationEdgeCredentials(t, "edge")
	tlsConfig, err := transport.RegistrationServerTLS(common)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, transport.QUICConfig(4))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverError := make(chan error, 1)
	go func() {
		for attempt, expectedKind := range []string{"enroll", "rotate"} {
			connection, err := listener.Accept(context.Background())
			if err != nil {
				serverError <- err
				return
			}
			stream, err := connection.AcceptStream(context.Background())
			if err != nil {
				serverError <- err
				return
			}
			var request protocol.RegistrationRequest
			if err := protocol.ReadFrame(stream, &request); err != nil {
				serverError <- err
				return
			}
			if request.ProjectID != "project" || request.EnvironmentID != "environment" || request.Kind != expectedKind {
				serverError <- errors.New("the registration request did not contain the expected Railway identity operation")
				return
			}
			err = protocol.WriteFrame(stream, protocol.RegistrationResponse{RequestID: fmt.Sprintf("request-%d", attempt), State: "approved", CertificatePEM: []byte("certificate"), CertificateEnd: time.Now().Add(24 * time.Hour).Unix(), VirtualPrefix: "fd40::/16", RealPrefix: "fd12::/16", DNSSuffix: "shop.production.railway.internal", LeaseExpiresAt: time.Now().Add(24 * time.Hour).Unix()})
			_ = stream.Close()
			serverError <- err
		}
	}()
	cfg := config.Connector{Common: config.Common{EdgeID: "edge", CABundle: common.CABundle}, RegistrationMode: "dynamic", RegistrationEndpoint: listener.Addr().String(), IdentityDir: t.TempDir(), EnrollmentNonce: "nonce", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "production", ProjectAlias: "shop", EnvironmentAlias: "production"}
	configured, err := Ensure(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	if configured.VirtualPrefix != netip.MustParsePrefix("fd40::/16") || configured.Common.ConnectorID != "project/environment" || len(configured.Common.PrivateKey) == 0 {
		t.Fatalf("Ensure() = %+v", configured)
	}
	configuredAgain, err := Ensure(context.Background(), cfg)
	if err != nil || configuredAgain.VirtualPrefix != configured.VirtualPrefix {
		t.Fatalf("cached Ensure() = %+v, %v", configuredAgain, err)
	}
	identity, err := loadOrCreate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	identity.IdentityCreatedAt = time.Now().Add(-identityLifetime - time.Hour).Unix()
	if err := save(filepath.Join(cfg.IdentityDir, "registration.json"), identity); err != nil {
		t.Fatal(err)
	}
	rotated, err := Ensure(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	if rotated.IdentityKeyID == configured.IdentityKeyID {
		t.Fatal("Ensure() did not rotate the expired identity key")
	}
}

func TestRegistrationServerRunsAndStops(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	certificate, key := testIntermediate(t)
	common := registrationEdgeCredentials(t, "edge")
	edgeCfg := config.Edge{Common: common, RegistrationListenAddr: address, IntermediateCertificate: certificate, IntermediatePrivateKey: key, PreviewLease: 24 * time.Hour, PersistentLease: 30 * 24 * time.Hour}
	server, err := NewServer(edgeCfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	clientTLS, err := transport.RegistrationClientTLS(common)
	if err != nil {
		t.Fatal(err)
	}
	identityPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	request := protocol.RegistrationRequest{Kind: "enroll", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "preview", ProjectAlias: "shop", EnvironmentAlias: "preview", IdentityKey: identityPublic, TransportKey: identityPublic}
	request.Proof = Proof([]byte("nonce"), request)
	var response protocol.RegistrationResponse
	for attempt := 0; attempt < 50; attempt++ {
		attemptContext, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
		response, err = exchange(attemptContext, address, clientTLS, request)
		stop()
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil || response.State != "pending" {
		t.Fatalf("registration exchange = %#v, %v", response, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("registration server did not stop")
	}
}

func TestResponseForPendingExpiresStaleRequest(t *testing.T) {
	server := &Server{}
	response := server.responseForPending(context.Background(), registry.PendingRequest{
		ID:        "stale-request",
		State:     "pending",
		ExpiresAt: time.Now().Add(-time.Second),
	})
	if response.State != "expired" || response.ErrorCode != "request_expired" {
		t.Fatalf("responseForPending() = %#v", response)
	}
}

func TestRegistrationRateWindowIsBounded(t *testing.T) {
	now := time.Now()
	server := &Server{source: make(map[string]*rateWindow)}
	for index := range 2048 {
		server.source[fmt.Sprint(index)] = &rateWindow{start: now}
	}
	if server.allow("unknown") {
		t.Fatal("allow() admitted a new source when the cache was full")
	}
	server.source["0"] = &rateWindow{start: now.Add(-2 * time.Minute)}
	if !server.allow("new-source") {
		t.Fatal("allow() did not evict an expired rate window")
	}
}

func registrationEdgeCredentials(t *testing.T, edgeID string) config.Common {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "registration edge"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{{Scheme: "spiffe", Host: "tailbridge.local", Path: "/edge/" + edgeID}}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := x509.MarshalPKCS8PrivateKey(private)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	return config.Common{EdgeID: edgeID, CABundle: certificate, Certificate: certificate, PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})}
}

func testIntermediate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "online"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := x509.MarshalPKCS8PrivateKey(private)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}
