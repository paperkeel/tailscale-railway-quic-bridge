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
	"unicode"
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
	MaxUDPFlows     int64
	UDPIdleTimeout  time.Duration
	ManageTailscale bool
}

type Connector struct {
	Common
	EdgeEndpoint        string
	AllowedDestinations []netip.Prefix
	MaxTCPFlows         int64
	MaxUDPFlows         int64
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
	maxUDPFlows, err := int64Value("TB_MAX_UDP_FLOWS", 4096)
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
	edge := Edge{
		Common:          c,
		QUICListenAddr:  value("TB_QUIC_LISTEN_ADDR", ":4433"),
		TCPListenAddr:   value("TB_TCP_LISTEN_ADDR", "[::]:15001"),
		UDPListenAddr:   value("TB_UDP_LISTEN_ADDR", "[::]:15002"),
		AllowedRoutes:   routes,
		MaxTCPFlows:     maxFlows,
		MaxUDPFlows:     maxUDPFlows,
		UDPIdleTimeout:  udpIdle,
		ManageTailscale: manageTailscale,
	}
	for name, address := range map[string]string{
		"TB_ADMIN_LISTEN_ADDR": edge.AdminAddr,
		"TB_QUIC_LISTEN_ADDR":  edge.QUICListenAddr,
		"TB_TCP_LISTEN_ADDR":   edge.TCPListenAddr,
		"TB_UDP_LISTEN_ADDR":   edge.UDPListenAddr,
	} {
		if err := validateAddress(name, address, false); err != nil {
			return Edge{}, err
		}
	}
	return edge, nil
}

func LoadConnector() (Connector, error) {
	adminAddress := "[::]:9002"
	if port := required("PORT"); port != "" && required("TB_ADMIN_LISTEN_ADDR") == "" {
		parsed, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsed == 0 {
			return Connector{}, fmt.Errorf("PORT must contain a valid TCP port. The value is %q.", port)
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
	maxUDPFlows, err := int64Value("TB_MAX_UDP_FLOWS", 4096)
	if err != nil {
		return Connector{}, err
	}
	edgeEndpoint := required("TB_EDGE_ENDPOINT")
	if edgeEndpoint == "" {
		return Connector{}, errors.New("TB_EDGE_ENDPOINT is required")
	}
	if err := validateAddress("TB_EDGE_ENDPOINT", edgeEndpoint, true); err != nil {
		return Connector{}, err
	}
	if err := validateAddress("TB_ADMIN_LISTEN_ADDR", c.AdminAddr, false); err != nil {
		return Connector{}, err
	}
	return Connector{
		Common:              c,
		EdgeEndpoint:        edgeEndpoint,
		AllowedDestinations: destinations,
		MaxTCPFlows:         maxFlows,
		MaxUDPFlows:         maxUDPFlows,
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
	if !validName(c.ConnectorID) {
		return Common{}, errors.New("TB_CONNECTOR_ID must start with a letter or digit and contain at most 63 letters, digits, periods, underscores, or hyphens")
	}
	if !validName(c.Environment) {
		return Common{}, errors.New("TB_ENVIRONMENT must start with a letter or digit and contain at most 63 letters, digits, periods, underscores, or hyphens")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return Common{}, fmt.Errorf("TB_LOG_LEVEL must be debug, info, warn, or error, got %q", c.LogLevel)
	}
	return c, nil
}

func validName(value string) bool {
	if len(value) < 1 || len(value) > 63 || !asciiLetterOrDigit(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiLetterOrDigit(character) && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func asciiLetterOrDigit(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func prefixes(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("specify at least one CIDR")
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

// IntersectPrefixes returns the address ranges present in both prefix sets.
func IntersectPrefixes(first, second []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, 0)
	for _, left := range first {
		left = left.Masked()
		for _, right := range second {
			right = right.Masked()
			if left.Addr().BitLen() != right.Addr().BitLen() || !left.Overlaps(right) {
				continue
			}
			intersection := left
			if right.Bits() > left.Bits() {
				intersection = right
			}
			redundant := false
			for _, existing := range result {
				if existing.Bits() <= intersection.Bits() && existing.Contains(intersection.Addr()) {
					redundant = true
					break
				}
			}
			if redundant {
				continue
			}
			for index := len(result) - 1; index >= 0; index-- {
				if intersection.Bits() <= result[index].Bits() && intersection.Contains(result[index].Addr()) {
					result = append(result[:index], result[index+1:]...)
				}
			}
			result = append(result, intersection)
		}
	}
	return result
}

// ValidateAcceptedRoutes parses accepted routes and checks that each route is unique and allowed.
func ValidateAcceptedRoutes(accepted []string, allowed []netip.Prefix) ([]netip.Prefix, error) {
	if len(accepted) == 0 {
		return nil, errors.New("the edge accepted no routes")
	}
	seen := make(map[netip.Prefix]struct{}, len(accepted))
	result := make([]netip.Prefix, 0, len(accepted))
	for _, raw := range accepted {
		route, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("accepted route %q is not a valid CIDR: %w", raw, err)
		}
		route = route.Masked()
		if _, ok := seen[route]; ok {
			return nil, fmt.Errorf("accepted route %q occurs more than once", route)
		}
		seen[route] = struct{}{}
		valid := false
		for _, candidate := range allowed {
			candidate = candidate.Masked()
			if candidate.Addr().BitLen() == route.Addr().BitLen() && candidate.Bits() <= route.Bits() && candidate.Contains(route.Addr()) {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("accepted route %q is outside the allowed destinations", route)
		}
		result = append(result, route)
	}
	return result, nil
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
	if err != nil || parsed < 1 || parsed > 1_000_000 {
		return 0, fmt.Errorf("%s must be an integer from 1 through 1000000", name)
	}
	return parsed, nil
}

func validateAddress(name, address string, requireHost bool) error {
	if strings.IndexFunc(address, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) >= 0 {
		return fmt.Errorf("%s must not contain whitespace or control characters", name)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s must be a host and port: %w", name, err)
	}
	if requireHost && strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s must include a host", name)
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return fmt.Errorf("%s must include a port from 1 through 65535", name)
	}
	return nil
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
