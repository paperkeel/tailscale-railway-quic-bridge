package config

import (
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestAllowed(t *testing.T) {
	routes, err := prefixes("fd12::/16,10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if !Allowed(routes, netip.MustParseAddr("fd12::10")) {
		t.Fatal("Allowed() rejected the Railway DNS address.")
	}
	if Allowed(routes, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("Allowed() accepted the public address.")
	}
}

func TestPrefixesRejectInvalid(t *testing.T) {
	if _, err := prefixes("not-a-prefix"); err == nil {
		t.Fatal("prefixes() accepted a prefix that is not valid.")
	}
}

func TestIntersectPrefixes(t *testing.T) {
	first := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd12::/16"),
	}
	second := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("fd12:3456::/32"),
		netip.MustParsePrefix("10.20.0.1/16"),
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("fd12:3456::/32"),
	}
	got := IntersectPrefixes(first, second)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("route %d is %v, want %v", index, got[index], want[index])
		}
	}
}

func TestValidateAcceptedRoutes(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd12::/16")}
	tests := []struct {
		name     string
		accepted []string
		wantErr  string
	}{
		{name: "valid subsets", accepted: []string{"10.20.0.0/16", "fd12:3456::/32"}},
		{name: "empty routes", wantErr: "accepted no routes"},
		{name: "invalid CIDR", accepted: []string{"invalid"}, wantErr: "not a valid CIDR"},
		{name: "broader route", accepted: []string{"0.0.0.0/0"}, wantErr: "outside the allowed destinations"},
		{name: "duplicate route", accepted: []string{"10.20.0.0/16", "10.20.1.1/16"}, wantErr: "occurs more than once"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateAcceptedRoutes(test.accepted, allowed)
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("got error %v, want text %q", err, test.wantErr)
			}
		})
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
		t.Fatal("LoadConnector() accepted a missing edge endpoint.")
	}
}

func TestConfigurationFlowLimits(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "minimum", value: "1", valid: true},
		{name: "maximum", value: "1000000", valid: true},
		{name: "zero", value: "0"},
		{name: "too large", value: "1000001"},
		{name: "not an integer", value: "many"},
	}
	for _, environmentName := range []string{"TB_MAX_TCP_FLOWS", "TB_MAX_UDP_FLOWS"} {
		for _, test := range tests {
			t.Run(environmentName+"/"+test.name, func(t *testing.T) {
				setConnectorEnvironment(t)
				t.Setenv(environmentName, test.value)
				configuration, err := LoadConnector()
				if test.valid && err != nil {
					t.Fatal(err)
				}
				if !test.valid && err == nil {
					t.Fatalf("expected %s=%q to fail", environmentName, test.value)
				}
				if test.valid {
					got := configuration.MaxTCPFlows
					if environmentName == "TB_MAX_UDP_FLOWS" {
						got = configuration.MaxUDPFlows
					}
					want, err := strconv.ParseInt(test.value, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					if got != want {
						t.Fatalf("got flow limit %d, want %d", got, want)
					}
				}
			})
		}
	}
}

func TestEdgeConfigurationValidation(t *testing.T) {
	setEdgeEnvironment(t)
	configuration, err := LoadEdge()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MaxUDPFlows != 4096 {
		t.Fatalf("got UDP flow limit %d, want 4096", configuration.MaxUDPFlows)
	}

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "invalid QUIC listener", key: "TB_QUIC_LISTEN_ADDR", value: "localhost"},
		{name: "invalid TCP listener", key: "TB_TCP_LISTEN_ADDR", value: "[::]:0"},
		{name: "invalid UDP listener", key: "TB_UDP_LISTEN_ADDR", value: "[::]:dns"},
		{name: "listener whitespace", key: "TB_ADMIN_LISTEN_ADDR", value: "127.0.0.1 :9090"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEdgeEnvironment(t)
			t.Setenv(test.key, test.value)
			if _, err := LoadEdge(); err == nil {
				t.Fatalf("expected %s=%q to fail", test.key, test.value)
			}
		})
	}
}

func TestConfigurationDefaultsUDPFlowLimit(t *testing.T) {
	setConnectorEnvironment(t)
	configuration, err := LoadConnector()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MaxUDPFlows != 4096 {
		t.Fatalf("got UDP flow limit %d, want 4096", configuration.MaxUDPFlows)
	}
}

func TestConnectorRejectsInvalidAddresses(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "endpoint without host", key: "TB_EDGE_ENDPOINT", value: ":4433"},
		{name: "endpoint without port", key: "TB_EDGE_ENDPOINT", value: "edge.example.com"},
		{name: "endpoint service port", key: "TB_EDGE_ENDPOINT", value: "edge.example.com:https"},
		{name: "admin zero port", key: "TB_ADMIN_LISTEN_ADDR", value: "127.0.0.1:0"},
		{name: "admin malformed IPv6", key: "TB_ADMIN_LISTEN_ADDR", value: "::1:9002"},
		{name: "endpoint whitespace", key: "TB_EDGE_ENDPOINT", value: "edge example.com:4433"},
		{name: "endpoint newline", key: "TB_EDGE_ENDPOINT", value: "edge.example.com:4433\nINJECTED=true"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setConnectorEnvironment(t)
			t.Setenv(test.key, test.value)
			if _, err := LoadConnector(); err == nil {
				t.Fatalf("expected %s=%q to fail", test.key, test.value)
			}
		})
	}
}

func TestConnectorRejectsInvalidLogLevel(t *testing.T) {
	setConnectorEnvironment(t)
	t.Setenv("TB_LOG_LEVEL", "verbose")
	if _, err := LoadConnector(); err == nil {
		t.Fatal("expected an invalid log level to fail")
	}
}

func TestDurationRejectsNonPositiveValue(t *testing.T) {
	t.Setenv("TEST_DURATION", "0s")
	if _, err := duration("TEST_DURATION", 1); err == nil {
		t.Fatal("duration() accepted a non-positive duration.")
	}
}

func TestConnectorRejectsUnsafeNames(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "TB_CONNECTOR_ID", value: "connector\nINJECTED=true"},
		{name: "TB_ENVIRONMENT", value: "not safe"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setConnectorEnvironment(t)
			t.Setenv(test.name, test.value)
			if _, err := LoadConnector(); err == nil {
				t.Fatalf("LoadConnector() accepted unsafe %s", test.name)
			}
		})
	}
}

func setConnectorEnvironment(t *testing.T) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte("test"))
	for name, value := range map[string]string{
		"TB_EDGE_ID":              "edge-production",
		"TB_CONNECTOR_ID":         "railway-production",
		"TB_ENVIRONMENT":          "production",
		"TB_MTLS_CA_B64":          encoded,
		"TB_MTLS_CERT_B64":        encoded,
		"TB_MTLS_KEY_B64":         encoded,
		"TB_EDGE_ENDPOINT":        "edge.example.com:4433",
		"TB_ALLOWED_DESTINATIONS": "fd12::/16",
		"TB_VIRTUAL_PREFIX":       "fd20::/16",
		"TB_REAL_PREFIX":          "fd12::/16",
		"TB_DNS_SUFFIX":           "production.railway.internal",
	} {
		t.Setenv(name, value)
	}
	for _, name := range []string{
		"PORT",
		"TB_ADMIN_LISTEN_ADDR",
		"TB_LOG_LEVEL",
		"TB_MAX_TCP_FLOWS",
		"TB_MAX_UDP_FLOWS",
	} {
		t.Setenv(name, "")
	}
}

func setEdgeEnvironment(t *testing.T) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte("test"))
	for name, value := range map[string]string{
		"TB_EDGE_ID":        "edge-production",
		"TB_MTLS_CA_B64":    encoded,
		"TB_MTLS_CERT_B64":  encoded,
		"TB_MTLS_KEY_B64":   encoded,
		"TB_ALLOWED_ROUTES": "fd20::/11",
		"TB_CONNECTORS_B64": base64.StdEncoding.EncodeToString([]byte(`[{"connectorId":"railway-production","environment":"production","slot":0,"virtualPrefix":"fd20::/16","realPrefix":"fd12::/16","dnsSuffix":"production.railway.internal"}]`)),
	} {
		t.Setenv(name, value)
	}
	for _, name := range []string{
		"TB_ADMIN_LISTEN_ADDR",
		"TB_LOG_LEVEL",
		"TB_MAX_TCP_FLOWS",
		"TB_MAX_UDP_FLOWS",
		"TB_QUIC_LISTEN_ADDR",
		"TB_TCP_LISTEN_ADDR",
		"TB_UDP_LISTEN_ADDR",
	} {
		t.Setenv(name, "")
	}
}

func TestConnectorLoadsDNSConfiguration(t *testing.T) {
	setConnectorEnvironment(t)
	configuration, err := LoadConnector()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.EdgeID != "edge-production" || configuration.VirtualPrefix != netip.MustParsePrefix("fd20::/16") || configuration.RealPrefix != netip.MustParsePrefix("fd12::/16") {
		t.Fatalf("connector identity and prefixes = %+v", configuration)
	}
	if configuration.DNSSuffix != "production.railway.internal" {
		t.Fatalf("DNS suffix = %q", configuration.DNSSuffix)
	}
}

func TestEdgeLoadsConnectorRegistry(t *testing.T) {
	setEdgeEnvironment(t)
	configuration, err := LoadEdge()
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Connectors) != 1 {
		t.Fatalf("connector count = %d, want 1", len(configuration.Connectors))
	}
	target := configuration.Connectors[0]
	if target.ConnectorID != "railway-production" || target.Slot != 0 || target.VirtualPrefix != netip.MustParsePrefix("fd20::/16") || target.RealPrefix != netip.MustParsePrefix("fd12::/16") {
		t.Fatalf("connector target = %+v", target)
	}
}

func TestEdgeRejectsDuplicateConnectorSlots(t *testing.T) {
	setEdgeEnvironment(t)
	payload := `[{"connectorId":"one","environment":"production","slot":0,"virtualPrefix":"fd20::/16","realPrefix":"fd12::/16","dnsSuffix":"one.railway.internal"},{"connectorId":"two","environment":"staging","slot":0,"virtualPrefix":"fd20::/16","realPrefix":"fd12::/16","dnsSuffix":"two.railway.internal"}]`
	t.Setenv("TB_CONNECTORS_B64", base64.StdEncoding.EncodeToString([]byte(payload)))
	if _, err := LoadEdge(); err == nil {
		t.Fatal("LoadEdge() accepted duplicate connector slots")
	}
}
