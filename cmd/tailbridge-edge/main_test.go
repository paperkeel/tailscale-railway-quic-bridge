//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunReturnsConfigurationExitCode(t *testing.T) {
	t.Setenv("TB_MTLS_CA_B64", "")
	if code := run(context.Background()); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunReturnsConfigurationExitCodeWhenAdminAddressIsOccupied(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close occupied listener: %v", err)
		}
	})
	setValidEdgeEnvironment(t, listener.Addr().String())

	if code := run(context.Background()); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func setValidEdgeEnvironment(t *testing.T, adminAddress string) {
	t.Helper()
	certificate, key := testCredentials(t)
	for name, value := range map[string]string{
		"TB_CONNECTOR_ID":             "test-connector",
		"TB_ENVIRONMENT":              "test",
		"TB_MTLS_CA_B64":              certificate,
		"TB_MTLS_CERT_B64":            certificate,
		"TB_MTLS_KEY_B64":             key,
		"TB_ADMIN_LISTEN_ADDR":        adminAddress,
		"TB_MANAGE_TAILSCALE":         "false",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "",
		"SENTRY_DSN":                  "",
	} {
		t.Setenv(name, value)
	}
}

func testCredentials(t *testing.T) (string, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	certificate := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedCertificate := encodePEM("CERTIFICATE", certificate.Certificate[0])
	return encodedCertificate, encodePEM("PRIVATE KEY", key)
}

func encodePEM(kind string, data []byte) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}))
}
