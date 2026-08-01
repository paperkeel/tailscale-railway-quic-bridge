package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/protocol"
)

func TestServerTLSConfiguration(t *testing.T) {
	common, _, _ := testCredentials(t, "edge", "railway-production", x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	configuration, err := ServerTLS(common)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MinVersion != tls.VersionTLS13 {
		t.Fatalf("got minimum TLS version %d", configuration.MinVersion)
	}
	if configuration.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("got client authentication mode %d", configuration.ClientAuth)
	}
	if configuration.ClientCAs == nil || len(configuration.Certificates) != 1 {
		t.Fatal("server TLS credentials are incomplete")
	}
	if len(configuration.NextProtos) != 1 || configuration.NextProtos[0] != protocol.ALPN {
		t.Fatalf("got ALPN values %v", configuration.NextProtos)
	}
}

func TestClientTLSConfiguration(t *testing.T) {
	common, _, _ := testCredentials(t, "connector", "railway-production", x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	configuration, err := ClientTLS(common)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MinVersion != tls.VersionTLS13 || !configuration.InsecureSkipVerify {
		t.Fatal("client TLS verification settings are incorrect")
	}
	if configuration.RootCAs == nil || len(configuration.Certificates) != 1 {
		t.Fatal("client TLS credentials are incomplete")
	}
	if len(configuration.NextProtos) != 1 || configuration.NextProtos[0] != protocol.ALPN {
		t.Fatalf("got ALPN values %v", configuration.NextProtos)
	}
}

func TestVerifyIdentity(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name        string
		role        string
		identityID  string
		verifyRole  string
		verifyID    string
		leafUsage   x509.ExtKeyUsage
		verifyUsage x509.ExtKeyUsage
		expires     time.Time
		otherCA     bool
		wantError   bool
	}{
		{name: "valid connector", role: "connector", identityID: "railway-production", verifyRole: "connector", verifyID: "railway-production", leafUsage: x509.ExtKeyUsageClientAuth, verifyUsage: x509.ExtKeyUsageClientAuth, expires: now.Add(time.Hour)},
		{name: "valid edge", role: "edge", identityID: "railway-production", verifyRole: "edge", verifyID: "railway-production", leafUsage: x509.ExtKeyUsageServerAuth, verifyUsage: x509.ExtKeyUsageServerAuth, expires: now.Add(time.Hour)},
		{name: "wrong role", role: "edge", identityID: "railway-production", verifyRole: "connector", verifyID: "railway-production", leafUsage: x509.ExtKeyUsageClientAuth, verifyUsage: x509.ExtKeyUsageClientAuth, expires: now.Add(time.Hour), wantError: true},
		{name: "wrong connector ID", role: "connector", identityID: "other", verifyRole: "connector", verifyID: "railway-production", leafUsage: x509.ExtKeyUsageClientAuth, verifyUsage: x509.ExtKeyUsageClientAuth, expires: now.Add(time.Hour), wantError: true},
		{name: "wrong usage", role: "connector", identityID: "railway-production", verifyRole: "connector", verifyID: "railway-production", leafUsage: x509.ExtKeyUsageServerAuth, verifyUsage: x509.ExtKeyUsageClientAuth, expires: now.Add(time.Hour), wantError: true},
		{name: "expired", role: "connector", identityID: "railway-production", verifyRole: "connector", verifyID: "railway-production", leafUsage: x509.ExtKeyUsageClientAuth, verifyUsage: x509.ExtKeyUsageClientAuth, expires: now.Add(-time.Hour), wantError: true},
		{name: "untrusted CA", role: "connector", identityID: "railway-production", verifyRole: "connector", verifyID: "railway-production", leafUsage: x509.ExtKeyUsageClientAuth, verifyUsage: x509.ExtKeyUsageClientAuth, expires: now.Add(time.Hour), otherCA: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, leaf, roots := testCredentials(t, test.role, test.identityID, test.leafUsage, test.expires)
			if test.otherCA {
				other, _, _ := testCredentials(t, "edge", "unused", x509.ExtKeyUsageServerAuth, now.Add(time.Hour))
				roots = x509.NewCertPool()
				if !roots.AppendCertsFromPEM(other.CABundle) {
					t.Fatal("failed to load the other CA")
				}
			}
			verify := verifyIdentity(roots, test.verifyRole, test.verifyID, test.verifyUsage)
			err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
			if test.wantError && err == nil {
				t.Fatal("expected identity verification to fail")
			}
			if !test.wantError && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyIdentityRejectsMissingCertificate(t *testing.T) {
	if err := verifyIdentity(x509.NewCertPool(), "edge", "test", x509.ExtKeyUsageServerAuth)(tls.ConnectionState{}); err == nil {
		t.Fatal("expected a missing peer certificate to fail")
	}
}

func TestCredentialsRejectInvalidInput(t *testing.T) {
	valid, _, _ := testCredentials(t, "edge", "test", x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	tests := []struct {
		name   string
		common config.Common
	}{
		{name: "invalid certificate", common: config.Common{Certificate: []byte("invalid"), PrivateKey: valid.PrivateKey, CABundle: valid.CABundle}},
		{name: "invalid CA", common: config.Common{Certificate: valid.Certificate, PrivateKey: valid.PrivateKey, CABundle: []byte("invalid")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := credentials(test.common); err == nil {
				t.Fatal("expected invalid TLS credentials to fail")
			}
		})
	}
}

func testCredentials(t *testing.T, role, id string, usage x509.ExtKeyUsage, expires time.Time) (config.Common, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tailbridge test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := url.Parse("spiffe://tailbridge.local/" + role + "/" + id)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: id},
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     expires,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		URIs:         []*url.URL{identity},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	common := config.Common{
		ConnectorID: id,
		CABundle:    caPEM,
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load the test CA")
	}
	return common, leaf, roots
}
