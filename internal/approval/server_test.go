package approval

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/config"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/enrollment"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/oidc"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/pki"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/registry"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/status"
)

func TestPendingRequestRequiresAllowedTailscaleTag(t *testing.T) {
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	nonce := "pending-secret"
	registrationRequest := protocol.RegistrationRequest{ProjectID: "project", EnvironmentID: "environment", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32)}
	request := registry.PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "preview", ProjectAlias: "project", EnvironmentAlias: "preview", IdentityKey: registrationRequest.IdentityKey, TransportKey: registrationRequest.TransportKey, Proof: enrollment.Proof([]byte(nonce), registrationRequest)}
	if _, _, err := store.CreatePending(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	server := &Server{config: config.Edge{ApprovalTailscaleTags: []string{"tag:ci"}}, store: store, logger: slog.Default(), whois: func(context.Context, string) ([]string, error) { return []string{"tag:ci"}, nil }}
	httpRequest := httptest.NewRequest(http.MethodGet, "http://edge/v1/pending?projectId=project&environmentId=environment", nil)
	httpRequest.Header.Set("X-Tailbridge-Enrollment-Nonce", nonce)
	httpRequest.RemoteAddr = "100.64.0.2:1234"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusOK || recorder.Body.String() == "" {
		t.Fatalf("pending response = %d %q", recorder.Code, recorder.Body.String())
	}
	server.whois = func(context.Context, string) ([]string, error) { return []string{"tag:other"}, nil }
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthorized response = %d", recorder.Code)
	}
}

func TestTagMatching(t *testing.T) {
	if !hasAllowedTag([]string{"tag:one", "tag:two"}, []string{"tag:two"}) {
		t.Fatal("hasAllowedTag() did not find an allowed tag")
	}
	if hasAllowedTag([]string{"tag:one"}, []string{"tag:two"}) {
		t.Fatal("hasAllowedTag() accepted another tag")
	}
}

func TestPendingExpired(t *testing.T) {
	if !pendingExpired(registry.PendingRequest{State: "pending", ExpiresAt: time.Now().Add(-time.Second)}) {
		t.Fatal("pendingExpired() accepted an expired request")
	}
	if pendingExpired(registry.PendingRequest{State: "approved", ExpiresAt: time.Now().Add(-time.Second)}) {
		t.Fatal("pendingExpired() rejected an approved request")
	}
}

func TestApprovalServerRunsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server := &Server{config: config.Edge{ApprovalListenAddr: "127.0.0.1:0"}, logger: slog.Default()}
	if err := server.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalServerWaitsForInterface(t *testing.T) {
	original := resolveApprovalAddress
	defer func() { resolveApprovalAddress = original }()
	ready := make(chan struct{})
	calls := 0
	resolveApprovalAddress = func(string) (string, error) {
		calls++
		if calls == 1 {
			return "", errors.New("interface is not ready")
		}
		close(ready)
		return "127.0.0.1:0", nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := &Server{config: config.Edge{ApprovalListenAddr: "tailscale0:9443"}, logger: slog.Default()}
	go func() { done <- server.Run(ctx) }()
	<-ready
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("approval address attempts = %d", calls)
	}
}

func TestNewServerBuildsDependencies(t *testing.T) {
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	certificate, privateKey := approvalIntermediate(t)
	metrics := status.New("test")
	server, err := NewServer(config.Edge{OIDCPolicies: []byte(`[]`), IntermediateCertificate: certificate, IntermediatePrivateKey: privateKey}, store, slog.Default(), metrics)
	if err != nil || server.validator == nil || server.issuer == nil || server.status != metrics {
		t.Fatalf("NewServer() = %#v, %v", server, err)
	}
	if _, err := NewServer(config.Edge{OIDCPolicies: []byte(`{`)}, store, slog.Default()); err == nil {
		t.Fatal("NewServer() accepted invalid OIDC policy JSON")
	}
}

func TestApprovalRejectsInvalidBindingsAndFreeze(t *testing.T) {
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(context.Background(), netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	nonce := "nonce"
	registrationRequest := protocol.RegistrationRequest{ProjectID: "project", EnvironmentID: "environment", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32)}
	pending := registry.PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "preview", ProjectAlias: "shop", EnvironmentAlias: "preview", IdentityKey: registrationRequest.IdentityKey, TransportKey: registrationRequest.TransportKey, Proof: enrollment.Proof([]byte(nonce), registrationRequest)}
	if _, _, err := store.CreatePending(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	server := &Server{config: config.Edge{RegistrationFrozen: true, PreviewLease: 24}, store: store, logger: slog.Default()}
	request := httptest.NewRequest(http.MethodPost, "/v1/approve", strings.NewReader(`{"requestId":"request","providerId":"github","oidcToken":"token","enrollmentNonce":"nonce","publicFingerprint":"wrong"}`))
	recorder := httptest.NewRecorder()
	server.approve(recorder, request)
	if recorder.Code != http.StatusLocked {
		t.Fatalf("frozen approval status = %d", recorder.Code)
	}
	server.config.RegistrationFrozen = false
	recorder = httptest.NewRecorder()
	server.approve(recorder, request.Clone(context.Background()))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("reused invalid body status = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/approve", strings.NewReader(`{"requestId":"request","providerId":"github","oidcToken":"token","enrollmentNonce":"nonce","publicFingerprint":"wrong"}`))
	recorder = httptest.NewRecorder()
	server.approve(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("fingerprint mismatch status = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/pending/request", nil)
	request.Header.Set("X-Tailbridge-Enrollment-Nonce", nonce)
	request.SetPathValue("id", "request")
	recorder = httptest.NewRecorder()
	server.pending(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("pending status = %d", recorder.Code)
	}
	if class, _ := server.lease("preview"); class != "preview" {
		t.Fatalf("lease class = %q", class)
	}
	if address, err := interfaceAddress("127.0.0.1:9443"); err != nil || address != "127.0.0.1:9443" {
		t.Fatalf("interfaceAddress() = %q, %v", address, err)
	}
	if _, err := interfaceAddress("invalid"); err == nil {
		t.Fatal("interfaceAddress() accepted an invalid address")
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/pending/missing", nil)
	request.SetPathValue("id", "missing")
	recorder = httptest.NewRecorder()
	server.pending(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing pending status = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/pending?projectId=missing&environmentId=missing", nil)
	recorder = httptest.NewRecorder()
	server.pendingForIdentity(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing identity status = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/approve", strings.NewReader(`{"requestId":"request","providerId":"github","oidcToken":"token","enrollmentNonce":"wrong","publicFingerprint":"`+registry.Fingerprint(pending.IdentityKey)+`"}`))
	recorder = httptest.NewRecorder()
	server.approve(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("invalid proof status = %d", recorder.Code)
	}
	identityKey := make([]byte, ed25519.PublicKeySize)
	identityKey[0] = 2
	transportKey := make([]byte, ed25519.PublicKeySize)
	transportKey[0] = 3
	binding := protocol.RegistrationRequest{ProjectID: "new-project", EnvironmentID: "new-environment", IdentityKey: identityKey, TransportKey: transportKey}
	newPending := registry.PendingRequest{ID: "new-request", ProjectID: binding.ProjectID, EnvironmentID: binding.EnvironmentID, EnvironmentName: "preview", ProjectAlias: "new", EnvironmentAlias: "preview", IdentityKey: identityKey, TransportKey: transportKey, Proof: enrollment.Proof([]byte("nonce"), binding)}
	if _, _, err := store.CreatePending(context.Background(), newPending); err != nil {
		t.Fatal(err)
	}
	server.config.NewProjectsFrozen = true
	request = httptest.NewRequest(http.MethodPost, "/v1/approve", strings.NewReader(`{"requestId":"new-request","providerId":"github","oidcToken":"token","enrollmentNonce":"nonce","publicFingerprint":"`+registry.Fingerprint(identityKey)+`"}`))
	recorder = httptest.NewRecorder()
	server.approve(recorder, request)
	if recorder.Code != http.StatusLocked {
		t.Fatalf("new-project freeze status = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/revoke", strings.NewReader(`{}`))
	recorder = httptest.NewRecorder()
	server.revoke(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid revocation status = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/revoke", strings.NewReader(`{"projectId":"missing","environmentId":"missing","providerId":"github","oidcToken":"token"}`))
	recorder = httptest.NewRecorder()
	server.revoke(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing revocation status = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/pending/request", nil)
	request.RemoteAddr = "invalid"
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("malformed caller status = %d", recorder.Code)
	}
}

func TestApprovalAndRevocation(t *testing.T) {
	ctx := context.Background()
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	identityPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	transportPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	registrationRequest := protocol.RegistrationRequest{ProjectID: "project", EnvironmentID: "environment", IdentityKey: identityPublic, TransportKey: transportPublic}
	nonce := "deployment-secret"
	pending := registry.PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "production", ProjectAlias: "shop", EnvironmentAlias: "production", IdentityKey: identityPublic, TransportKey: transportPublic, Proof: enrollment.Proof([]byte(nonce), registrationRequest)}
	created, _, err := store.CreatePending(ctx, pending)
	if err != nil || created.ID == "" {
		t.Fatalf("CreatePending() = %#v, %v", created, err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []map[string]string{{"kid": "test", "kty": "RSA", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer jwks.Close()
	policy := oidc.Policy{ID: "github", Issuer: "https://issuer.example", JWKSURL: jwks.URL, Audiences: []string{"tailbridge-enrollment"}, MaxTokenAge: 5 * time.Minute, ProjectIDClaim: "project", EnvironmentClaim: "environment", RepositoryIDClaim: "repository_id", RepositoryClaim: "repository", WorkflowRefClaim: "workflow_ref", WorkflowSHAClaim: "workflow_sha", RunIDClaim: "run_id", RunAttemptClaim: "run_attempt"}
	validator, err := oidc.New([]oidc.Policy{policy}, jwks.Client())
	if err != nil {
		t.Fatal(err)
	}
	certificate, privateKey := approvalIntermediate(t)
	issuer, err := pki.New(certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	workflowSHA := strings.Repeat("a", 40)
	claims := map[string]any{"iss": policy.Issuer, "aud": policy.Audiences[0], "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "jti": "approve-jti", "project": "project", "environment": "production", "repository_id": "123", "repository": "org/repo", "workflow_ref": "org/workflows/enroll.yml@" + workflowSHA, "workflow_sha": workflowSHA, "run_id": "10", "run_attempt": "1"}
	server := &Server{config: config.Edge{ApprovalTailscaleTags: []string{"tag:ci"}, PersistentEnvironments: []string{"production"}, PersistentLease: 30 * 24 * time.Hour, SlotQuarantine: 24 * time.Hour}, store: store, validator: validator, issuer: issuer, logger: slog.Default(), whois: func(context.Context, string) ([]string, error) { return []string{"tag:ci"}, nil }}
	body, _ := json.Marshal(approvalRequest{RequestID: pending.ID, ProviderID: "github", OIDCToken: approvalToken(t, key, claims), EnrollmentNonce: nonce, PublicFingerprint: registry.Fingerprint(identityPublic)})
	request := httptest.NewRequest(http.MethodPost, "http://edge/v1/approve", strings.NewReader(string(body)))
	request.RemoteAddr = "100.64.0.2:1234"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("approval response = %d %q", response.Code, response.Body.String())
	}
	registration, err := store.Registration(ctx, "project", "environment")
	if err != nil || registration.State != "approved" || registration.LeaseClass != "persistent" {
		t.Fatalf("Registration() = %#v, %v", registration, err)
	}
	if err := store.MarkReady(ctx, "project", "environment"); err != nil {
		t.Fatal(err)
	}
	generation, err := store.PendingRouteGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRouteGeneration(ctx, generation.ID, nil); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "http://edge/v1/pending/request", nil)
	request.Header.Set("X-Tailbridge-Enrollment-Nonce", nonce)
	request.SetPathValue("id", "request")
	request.RemoteAddr = "100.64.0.2:1234"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"ready"`) {
		t.Fatalf("ready response = %d %q", response.Code, response.Body.String())
	}

	claims["jti"] = "revoke-jti"
	revokeBody, _ := json.Marshal(revokeRequest{ProjectID: "project", EnvironmentID: "environment", ProviderID: "github", OIDCToken: approvalToken(t, key, claims)})
	request = httptest.NewRequest(http.MethodPost, "http://edge/v1/revoke", strings.NewReader(string(revokeBody)))
	request.RemoteAddr = "100.64.0.2:1234"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("revocation response = %d %q", response.Code, response.Body.String())
	}
}

func approvalToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func approvalIntermediate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "online"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	privateRaw, _ := x509.MarshalPKCS8PrivateKey(private)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateRaw})
}
