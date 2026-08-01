package config

import (
	"encoding/base64"
	"net/netip"
	"testing"
)

func TestAllowed(t *testing.T) {
	routes, err := prefixes("fd12::/16,10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if !Allowed(routes, netip.MustParseAddr("fd12::10")) {
		t.Fatal("expected Railway DNS address to be allowed")
	}
	if Allowed(routes, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected public address to be denied")
	}
}

func TestPrefixesRejectInvalid(t *testing.T) {
	if _, err := prefixes("not-a-prefix"); err == nil {
		t.Fatal("expected invalid prefix to fail")
	}
}

func TestConnectorUsesRailwayPort(t *testing.T) {
	setConnectorEnvironment(t)
	t.Setenv("PORT", "8080")
	configuration, err := LoadConnector()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.AdminAddr != "[::]:8080" {
		t.Fatalf("expected Railway port, got %q", configuration.AdminAddr)
	}
}

func TestConnectorRejectsMissingEndpoint(t *testing.T) {
	setConnectorEnvironment(t)
	t.Setenv("TB_EDGE_ENDPOINT", "")
	if _, err := LoadConnector(); err == nil {
		t.Fatal("expected a missing edge endpoint to fail")
	}
}

func TestDurationRejectsNonPositiveValue(t *testing.T) {
	t.Setenv("TEST_DURATION", "0s")
	if _, err := duration("TEST_DURATION", 1); err == nil {
		t.Fatal("expected a non-positive duration to fail")
	}
}

func setConnectorEnvironment(t *testing.T) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte("test"))
	for name, value := range map[string]string{
		"TB_CONNECTOR_ID":         "railway-production",
		"TB_ENVIRONMENT":          "production",
		"TB_MTLS_CA_B64":          encoded,
		"TB_MTLS_CERT_B64":        encoded,
		"TB_MTLS_KEY_B64":         encoded,
		"TB_EDGE_ENDPOINT":        "edge.example.com:4433",
		"TB_ALLOWED_DESTINATIONS": "fd12::/16",
	} {
		t.Setenv(name, value)
	}
}
