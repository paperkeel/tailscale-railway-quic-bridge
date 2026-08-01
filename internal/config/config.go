package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Common struct {
	ConnectorID string
	Environment string
	CABundle    []byte
	Certificate []byte
	PrivateKey  []byte
	AdminAddr   string
	LogLevel    string
}

type Edge struct {
	Common
	QUICListenAddr  string
	TCPListenAddr   string
	UDPListenAddr   string
	AllowedRoutes   []netip.Prefix
	MaxTCPFlows     int64
	UDPIdleTimeout  time.Duration
	ManageTailscale bool
}

type Connector struct {
	Common
	EdgeEndpoint        string
	AllowedDestinations []netip.Prefix
	MaxTCPFlows         int64
	DialTimeout         time.Duration
	ReconnectMin        time.Duration
	ReconnectMax        time.Duration
	UDPIdleTimeout      time.Duration
}

func LoadEdge() (Edge, error) {
	c, err := loadCommon("127.0.0.1:9090")
	if err != nil {
		return Edge{}, err
	}
	routes, err := prefixes(required("TB_ALLOWED_ROUTES"))
	if err != nil {
		return Edge{}, fmt.Errorf("TB_ALLOWED_ROUTES: %w", err)
	}
	maxFlows, err := int64Value("TB_MAX_TCP_FLOWS", 4096)
	if err != nil {
		return Edge{}, err
	}
	udpIdle, err := duration("TB_UDP_IDLE_TIMEOUT", 30*time.Second)
	if err != nil {
		return Edge{}, err
	}
	manageTailscale, err := boolValue("TB_MANAGE_TAILSCALE", true)
	if err != nil {
		return Edge{}, err
	}
	return Edge{
		Common:          c,
		QUICListenAddr:  value("TB_QUIC_LISTEN_ADDR", ":4433"),
		TCPListenAddr:   value("TB_TCP_LISTEN_ADDR", "[::]:15001"),
		UDPListenAddr:   value("TB_UDP_LISTEN_ADDR", "[::]:15002"),
		AllowedRoutes:   routes,
		MaxTCPFlows:     maxFlows,
		UDPIdleTimeout:  udpIdle,
		ManageTailscale: manageTailscale,
	}, nil
}

func LoadConnector() (Connector, error) {
	adminAddress := "[::]:9002"
	if port := required("PORT"); port != "" && required("TB_ADMIN_LISTEN_ADDR") == "" {
		parsed, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsed == 0 {
			return Connector{}, fmt.Errorf("PORT must be a valid TCP port, got %q", port)
		}
		adminAddress = "[::]:" + port
	}
	c, err := loadCommon(adminAddress)
	if err != nil {
		return Connector{}, err
	}
	destinations, err := prefixes(required("TB_ALLOWED_DESTINATIONS"))
	if err != nil {
		return Connector{}, fmt.Errorf("TB_ALLOWED_DESTINATIONS: %w", err)
	}
	dialTimeout, err := duration("TB_TCP_DIAL_TIMEOUT", 10*time.Second)
	if err != nil {
		return Connector{}, err
	}
	minDelay, err := duration("TB_RECONNECT_MIN_DELAY", 250*time.Millisecond)
	if err != nil {
		return Connector{}, err
	}
	maxDelay, err := duration("TB_RECONNECT_MAX_DELAY", 15*time.Second)
	if err != nil {
		return Connector{}, err
	}
	if minDelay > maxDelay {
		return Connector{}, errors.New("TB_RECONNECT_MIN_DELAY must not exceed TB_RECONNECT_MAX_DELAY")
	}
	udpIdle, err := duration("TB_UDP_IDLE_TIMEOUT", 30*time.Second)
	if err != nil {
		return Connector{}, err
	}
	maxFlows, err := int64Value("TB_MAX_TCP_FLOWS", 4096)
	if err != nil {
		return Connector{}, err
	}
	edgeEndpoint := required("TB_EDGE_ENDPOINT")
	if edgeEndpoint == "" {
		return Connector{}, errors.New("TB_EDGE_ENDPOINT is required")
	}
	if _, _, err := net.SplitHostPort(edgeEndpoint); err != nil {
		return Connector{}, fmt.Errorf("TB_EDGE_ENDPOINT: %w", err)
	}
	return Connector{
		Common:              c,
		EdgeEndpoint:        edgeEndpoint,
		AllowedDestinations: destinations,
		MaxTCPFlows:         maxFlows,
		DialTimeout:         dialTimeout,
		ReconnectMin:        minDelay,
		ReconnectMax:        maxDelay,
		UDPIdleTimeout:      udpIdle,
	}, nil
}

func loadCommon(defaultAdmin string) (Common, error) {
	ca, err := decoded("TB_MTLS_CA_B64")
	if err != nil {
		return Common{}, err
	}
	cert, err := decoded("TB_MTLS_CERT_B64")
	if err != nil {
		return Common{}, err
	}
	key, err := decoded("TB_MTLS_KEY_B64")
	if err != nil {
		return Common{}, err
	}
	c := Common{
		ConnectorID: required("TB_CONNECTOR_ID"),
		Environment: required("TB_ENVIRONMENT"),
		CABundle:    ca,
		Certificate: cert,
		PrivateKey:  key,
		AdminAddr:   value("TB_ADMIN_LISTEN_ADDR", defaultAdmin),
		LogLevel:    value("TB_LOG_LEVEL", "info"),
	}
	if c.ConnectorID == "" || c.Environment == "" {
		return Common{}, errors.New("TB_CONNECTOR_ID and TB_ENVIRONMENT are required")
	}
	return c, nil
}

func prefixes(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("at least one CIDR is required")
	}
	parts := strings.Split(raw, ",")
	result := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func Allowed(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func decoded(name string) ([]byte, error) {
	raw := required(name)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", name, err)
	}
	return data, nil
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return parsed, nil
}

func int64Value(name string, fallback int64) (int64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func boolValue(name string, fallback bool) (bool, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return parsed, nil
}

func required(name string) string { return strings.TrimSpace(os.Getenv(name)) }
func value(name, fallback string) string {
	if v := required(name); v != "" {
		return v
	}
	return fallback
}
