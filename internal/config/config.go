package config

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Common struct {
	EdgeID         string
	ConnectorID    string
	Environment    string
	CABundle       []byte
	Certificate    []byte
	PrivateKey     []byte
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error) `json:"-"`
	AdminAddr      string
	LogLevel       string
}

type Edge struct {
	Common
	Connectors              []ConnectorTarget
	RegistrationMode        string
	QUICListenAddr          string
	RegistrationListenAddr  string
	ApprovalListenAddr      string
	DNSListenAddr           string
	RegistryPath            string
	VirtualNetwork          netip.Prefix
	ExcludedPrefixes        []netip.Prefix
	RegistrationFrozen      bool
	NewProjectsFrozen       bool
	AllowedProjectIDs       []string
	OIDCPolicies            []byte
	IntermediateCertificate []byte
	IntermediatePrivateKey  []byte
	ApprovalTailscaleTags   []string
	PreviewLease            time.Duration
	PersistentLease         time.Duration
	SlotQuarantine          time.Duration
	PersistentEnvironments  []string
	ReconcileInterval       time.Duration
	TCPListenAddr           string
	UDPListenAddr           string
	AllowedRoutes           []netip.Prefix
	MaxTCPFlows             int64
	MaxUDPFlows             int64
	UDPIdleTimeout          time.Duration
	ManageTailscale         bool
}

type Connector struct {
	Common
	RegistrationMode     string
	RegistrationEndpoint string
	IdentityDir          string
	EnrollmentNonce      string
	ProjectID            string
	EnvironmentID        string
	EnvironmentName      string
	DeploymentID         string
	ProjectAlias         string
	EnvironmentAlias     string
	IdentityKeyID        string
	EdgeEndpoint         string
	VirtualPrefix        netip.Prefix
	RealPrefix           netip.Prefix
	DNSSuffix            string
	AllowedDestinations  []netip.Prefix
	MaxTCPFlows          int64
	MaxUDPFlows          int64
	DialTimeout          time.Duration
	ReconnectMin         time.Duration
	ReconnectMax         time.Duration
	UDPIdleTimeout       time.Duration
}

type ConnectorTarget struct {
	ConnectorID     string
	ProjectID       string
	Environment     string
	EnvironmentName string
	Slot            int
	VirtualPrefix   netip.Prefix
	RealPrefix      netip.Prefix
	DNSSuffix       string
}

type connectorTargetJSON struct {
	ConnectorID     string `json:"connectorId"`
	ProjectID       string `json:"projectId,omitempty"`
	Environment     string `json:"environment"`
	EnvironmentName string `json:"environmentName,omitempty"`
	Slot            int    `json:"slot"`
	VirtualPrefix   string `json:"virtualPrefix"`
	RealPrefix      string `json:"realPrefix"`
	DNSSuffix       string `json:"dnsSuffix"`
}

func LoadEdge() (Edge, error) {
	c, err := loadCommon("127.0.0.1:9090", false)
	if err != nil {
		return Edge{}, err
	}
	registrationMode := value("TB_REGISTRATION_MODE", "static")
	if registrationMode != "static" && registrationMode != "dynamic" && registrationMode != "migration" {
		return Edge{}, errors.New("TB_REGISTRATION_MODE must be static, dynamic, or migration")
	}
	var connectors []ConnectorTarget
	if encoded := required("TB_CONNECTORS_B64"); encoded != "" {
		connectors, err = connectorTargets(encoded)
		if err != nil {
			return Edge{}, fmt.Errorf("TB_CONNECTORS_B64: %w", err)
		}
	} else if registrationMode == "static" {
		return Edge{}, errors.New("TB_CONNECTORS_B64 is required in static registration mode")
	}
	routes := make([]netip.Prefix, 0, len(connectors))
	for _, connector := range connectors {
		routes = append(routes, connector.RealPrefix)
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
	virtualNetwork, err := virtualNetworkValue(value("TB_VIRTUAL_NETWORK", "fd40::/10"))
	if err != nil {
		return Edge{}, err
	}
	excludedPrefixes, err := prefixes(value("TB_EXCLUDED_PREFIXES", "fd12::/16"))
	if err != nil {
		return Edge{}, fmt.Errorf("TB_EXCLUDED_PREFIXES: %w", err)
	}
	for _, excluded := range excludedPrefixes {
		if virtualNetwork.Contains(excluded.Addr()) || excluded.Contains(virtualNetwork.Addr()) {
			return Edge{}, fmt.Errorf("TB_VIRTUAL_NETWORK must not overlap excluded prefix %s", excluded)
		}
	}
	registrationFrozen, err := boolValue("TB_REGISTRATION_FROZEN", false)
	if err != nil {
		return Edge{}, err
	}
	newProjectsFrozen, err := boolValue("TB_NEW_PROJECTS_FROZEN", true)
	if err != nil {
		return Edge{}, err
	}
	previewLease, err := duration("TB_PREVIEW_LEASE", 24*time.Hour)
	if err != nil {
		return Edge{}, err
	}
	persistentLease, err := duration("TB_PERSISTENT_LEASE", 30*24*time.Hour)
	if err != nil {
		return Edge{}, err
	}
	quarantine, err := duration("TB_SLOT_QUARANTINE", 24*time.Hour)
	if err != nil {
		return Edge{}, err
	}
	reconcileInterval, err := duration("TB_RECONCILE_INTERVAL", time.Minute)
	if err != nil {
		return Edge{}, err
	}
	var oidcPolicies, intermediateCertificate, intermediatePrivateKey []byte
	if registrationMode != "static" {
		oidcPolicies, err = decoded("TB_OIDC_POLICIES_B64")
		if err != nil {
			return Edge{}, err
		}
		intermediateCertificate, err = decoded("TB_INTERMEDIATE_CERT_B64")
		if err != nil {
			return Edge{}, err
		}
		intermediatePrivateKey, err = decoded("TB_INTERMEDIATE_KEY_B64")
		if err != nil {
			return Edge{}, err
		}
	}
	allowedProjectIDs, err := decodedStringList("TB_ALLOWED_PROJECT_IDS_B64")
	if err != nil {
		return Edge{}, err
	}
	edge := Edge{
		Common:                  c,
		Connectors:              connectors,
		RegistrationMode:        registrationMode,
		QUICListenAddr:          value("TB_QUIC_LISTEN_ADDR", ":4433"),
		RegistrationListenAddr:  value("TB_REGISTRATION_LISTEN_ADDR", ":4434"),
		ApprovalListenAddr:      value("TB_APPROVAL_LISTEN_ADDR", "tailscale0:9443"),
		DNSListenAddr:           value("TB_DNS_LISTEN_ADDR", "tailscale0:53"),
		RegistryPath:            value("TB_REGISTRY_PATH", "/var/lib/tailbridge/registry/tailbridge.db"),
		VirtualNetwork:          virtualNetwork,
		ExcludedPrefixes:        excludedPrefixes,
		RegistrationFrozen:      registrationFrozen,
		NewProjectsFrozen:       newProjectsFrozen,
		AllowedProjectIDs:       allowedProjectIDs,
		OIDCPolicies:            oidcPolicies,
		IntermediateCertificate: intermediateCertificate,
		IntermediatePrivateKey:  intermediatePrivateKey,
		ApprovalTailscaleTags:   commaValues(value("TB_APPROVAL_TAILSCALE_TAGS", "tag:tailbridge-ci")),
		PreviewLease:            previewLease,
		PersistentLease:         persistentLease,
		SlotQuarantine:          quarantine,
		PersistentEnvironments:  commaValues(value("TB_PERSISTENT_ENVIRONMENTS", "production,staging,development")),
		ReconcileInterval:       reconcileInterval,
		TCPListenAddr:           value("TB_TCP_LISTEN_ADDR", "[::]:15001"),
		UDPListenAddr:           value("TB_UDP_LISTEN_ADDR", "[::]:15002"),
		AllowedRoutes:           routes,
		MaxTCPFlows:             maxFlows,
		MaxUDPFlows:             maxUDPFlows,
		UDPIdleTimeout:          udpIdle,
		ManageTailscale:         manageTailscale,
	}
	for name, address := range map[string]string{
		"TB_ADMIN_LISTEN_ADDR":        edge.AdminAddr,
		"TB_QUIC_LISTEN_ADDR":         edge.QUICListenAddr,
		"TB_TCP_LISTEN_ADDR":          edge.TCPListenAddr,
		"TB_UDP_LISTEN_ADDR":          edge.UDPListenAddr,
		"TB_REGISTRATION_LISTEN_ADDR": edge.RegistrationListenAddr,
	} {
		if err := validateAddress(name, address, false); err != nil {
			return Edge{}, err
		}
	}
	return edge, nil
}

func LoadConnector() (Connector, error) {
	registrationMode := value("TB_REGISTRATION_MODE", "static")
	if registrationMode == "dynamic" {
		return loadDynamicConnector()
	}
	if registrationMode != "static" {
		return Connector{}, errors.New("TB_REGISTRATION_MODE must be static or dynamic")
	}
	adminAddress, err := connectorAdminAddress()
	if err != nil {
		return Connector{}, err
	}
	c, err := loadCommon(adminAddress, true)
	if err != nil {
		return Connector{}, err
	}
	destinations, err := prefixes(required("TB_ALLOWED_DESTINATIONS"))
	if err != nil {
		return Connector{}, fmt.Errorf("TB_ALLOWED_DESTINATIONS: %w", err)
	}
	virtualPrefix, err := ipv6Prefix16("TB_VIRTUAL_PREFIX", required("TB_VIRTUAL_PREFIX"))
	if err != nil {
		return Connector{}, err
	}
	if !netip.MustParsePrefix("fd20::/11").Contains(virtualPrefix.Addr()) {
		return Connector{}, errors.New("TB_VIRTUAL_PREFIX must be inside fd20::/11")
	}
	realPrefix, err := ipv6Prefix16("TB_REAL_PREFIX", value("TB_REAL_PREFIX", "fd12::/16"))
	if err != nil {
		return Connector{}, err
	}
	dnsSuffix, err := dnsSuffixValue("TB_DNS_SUFFIX", required("TB_DNS_SUFFIX"))
	if err != nil {
		return Connector{}, err
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
		RegistrationMode:    "static",
		EdgeEndpoint:        edgeEndpoint,
		VirtualPrefix:       virtualPrefix,
		RealPrefix:          realPrefix,
		DNSSuffix:           dnsSuffix,
		AllowedDestinations: destinations,
		MaxTCPFlows:         maxFlows,
		MaxUDPFlows:         maxUDPFlows,
		DialTimeout:         dialTimeout,
		ReconnectMin:        minDelay,
		ReconnectMax:        maxDelay,
		UDPIdleTimeout:      udpIdle,
	}, nil
}

func loadDynamicConnector() (Connector, error) {
	adminAddress, err := connectorAdminAddress()
	if err != nil {
		return Connector{}, err
	}
	trust, err := decoded("TB_TRUST_BUNDLE_B64")
	if err != nil {
		return Connector{}, err
	}
	destinations, err := prefixes(value("TB_ALLOWED_DESTINATIONS", "fd12::/16"))
	if err != nil {
		return Connector{}, fmt.Errorf("TB_ALLOWED_DESTINATIONS: %w", err)
	}
	realPrefix, err := ipv6Prefix16("TB_REAL_PREFIX", value("TB_REAL_PREFIX", "fd12::/16"))
	if err != nil {
		return Connector{}, err
	}
	maxTCP, err := int64Value("TB_MAX_TCP_FLOWS", 4096)
	if err != nil {
		return Connector{}, err
	}
	maxUDP, err := int64Value("TB_MAX_UDP_FLOWS", 4096)
	if err != nil {
		return Connector{}, err
	}
	dialTimeout, err := duration("TB_TCP_DIAL_TIMEOUT", 10*time.Second)
	if err != nil {
		return Connector{}, err
	}
	reconnectMin, err := duration("TB_RECONNECT_MIN_DELAY", time.Second)
	if err != nil {
		return Connector{}, err
	}
	reconnectMax, err := duration("TB_RECONNECT_MAX_DELAY", 30*time.Second)
	if err != nil {
		return Connector{}, err
	}
	udpIdle, err := duration("TB_UDP_IDLE_TIMEOUT", 30*time.Second)
	if err != nil {
		return Connector{}, err
	}
	result := Connector{
		RegistrationMode:     "dynamic",
		RegistrationEndpoint: required("TB_REGISTRATION_ENDPOINT"),
		IdentityDir:          value("TB_IDENTITY_DIR", "/var/lib/tailbridge"),
		EnrollmentNonce:      required("TB_ENROLLMENT_NONCE"),
		ProjectID:            required("RAILWAY_PROJECT_ID"),
		EnvironmentID:        required("RAILWAY_ENVIRONMENT_ID"),
		EnvironmentName:      required("RAILWAY_ENVIRONMENT_NAME"),
		DeploymentID:         required("RAILWAY_DEPLOYMENT_ID"),
		ProjectAlias:         required("TB_DNS_PROJECT_ALIAS"),
		EnvironmentAlias:     required("TB_DNS_ENVIRONMENT_ALIAS"),
		EdgeEndpoint:         required("TB_EDGE_ENDPOINT"),
		RealPrefix:           realPrefix,
		AllowedDestinations:  destinations,
		MaxTCPFlows:          maxTCP,
		MaxUDPFlows:          maxUDP,
		DialTimeout:          dialTimeout,
		ReconnectMin:         reconnectMin,
		ReconnectMax:         reconnectMax,
		UDPIdleTimeout:       udpIdle,
		Common:               Common{EdgeID: required("TB_EDGE_ID"), CABundle: trust, AdminAddr: value("TB_ADMIN_LISTEN_ADDR", adminAddress), LogLevel: value("TB_LOG_LEVEL", "info")},
	}
	if err := validateCommon(result.Common, false); err != nil {
		return Connector{}, err
	}
	for name, candidate := range map[string]string{
		"TB_EDGE_ENDPOINT":         result.EdgeEndpoint,
		"TB_REGISTRATION_ENDPOINT": result.RegistrationEndpoint,
		"RAILWAY_PROJECT_ID":       result.ProjectID,
		"RAILWAY_ENVIRONMENT_ID":   result.EnvironmentID,
		"RAILWAY_ENVIRONMENT_NAME": result.EnvironmentName,
		"TB_DNS_PROJECT_ALIAS":     result.ProjectAlias,
		"TB_DNS_ENVIRONMENT_ALIAS": result.EnvironmentAlias,
	} {
		if candidate == "" {
			return Connector{}, fmt.Errorf("%s is required in dynamic registration mode", name)
		}
	}
	if !validDNSLabel(result.ProjectAlias) || !validDNSLabel(result.EnvironmentAlias) {
		return Connector{}, errors.New("TB_DNS_PROJECT_ALIAS and TB_DNS_ENVIRONMENT_ALIAS must be valid DNS labels")
	}
	if result.EnrollmentNonce == "" {
		if _, err := os.Stat(filepath.Join(result.IdentityDir, "registration.json")); errors.Is(err, os.ErrNotExist) {
			return Connector{}, errors.New("TB_ENROLLMENT_NONCE is required for the first dynamic registration")
		}
	}
	if err := validateAddress("TB_EDGE_ENDPOINT", result.EdgeEndpoint, true); err != nil {
		return Connector{}, err
	}
	if err := validateAddress("TB_REGISTRATION_ENDPOINT", result.RegistrationEndpoint, true); err != nil {
		return Connector{}, err
	}
	if err := validateAddress("TB_ADMIN_LISTEN_ADDR", result.AdminAddr, false); err != nil {
		return Connector{}, err
	}
	return result, nil
}

func loadCommon(defaultAdmin string, requireConnector bool) (Common, error) {
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
		EdgeID:      required("TB_EDGE_ID"),
		ConnectorID: required("TB_CONNECTOR_ID"),
		Environment: required("TB_ENVIRONMENT"),
		CABundle:    ca,
		Certificate: cert,
		PrivateKey:  key,
		AdminAddr:   value("TB_ADMIN_LISTEN_ADDR", defaultAdmin),
		LogLevel:    value("TB_LOG_LEVEL", "info"),
	}
	if err := validateCommon(c, requireConnector); err != nil {
		return Common{}, err
	}
	return c, nil
}

func connectorAdminAddress() (string, error) {
	adminAddress := "[::]:9002"
	if port := required("PORT"); port != "" && required("TB_ADMIN_LISTEN_ADDR") == "" {
		parsed, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsed == 0 {
			return "", fmt.Errorf("PORT must contain a valid TCP port. The value is %q.", port)
		}
		adminAddress = "[::]:" + port
	}
	return adminAddress, nil
}

func validateCommon(c Common, requireConnector bool) error {
	if c.EdgeID == "" {
		return errors.New("TB_EDGE_ID is required")
	}
	if !validName(c.EdgeID) {
		return errors.New("TB_EDGE_ID must start with a letter or digit and contain at most 63 letters, digits, periods, underscores, or hyphens")
	}
	if requireConnector && (c.ConnectorID == "" || c.Environment == "") {
		return errors.New("TB_CONNECTOR_ID and TB_ENVIRONMENT are required")
	}
	if c.ConnectorID != "" && !validName(c.ConnectorID) {
		return errors.New("TB_CONNECTOR_ID must start with a letter or digit and contain at most 63 letters, digits, periods, underscores, or hyphens")
	}
	if c.Environment != "" && !validName(c.Environment) {
		return errors.New("TB_ENVIRONMENT must start with a letter or digit and contain at most 63 letters, digits, periods, underscores, or hyphens")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("TB_LOG_LEVEL must be debug, info, warn, or error, got %q", c.LogLevel)
	}
	return nil
}

func connectorTargets(encoded string) ([]ConnectorTarget, error) {
	if encoded == "" {
		return nil, errors.New("is required")
	}
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("is not valid base64: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var values []connectorTargetJSON
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("does not contain a valid connector array: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("contains data after the connector array")
	}
	if len(values) < 1 || len(values) > 32 {
		return nil, errors.New("must contain from 1 through 32 connectors")
	}
	seenIDs := make(map[string]struct{}, len(values))
	seenSlots := make(map[int]struct{}, len(values))
	seenPrefixes := make(map[netip.Prefix]struct{}, len(values))
	result := make([]ConnectorTarget, 0, len(values))
	virtualRange := netip.MustParsePrefix("fd20::/11")
	for index, value := range values {
		if !validName(value.ConnectorID) || !validName(value.Environment) {
			return nil, fmt.Errorf("connector %d has an invalid connectorId or environment", index)
		}
		if value.Slot < 0 || value.Slot > 31 {
			return nil, fmt.Errorf("connector %q has slot %d outside 0 through 31", value.ConnectorID, value.Slot)
		}
		virtualPrefix, err := ipv6Prefix16("virtualPrefix", value.VirtualPrefix)
		if err != nil || !virtualRange.Contains(virtualPrefix.Addr()) {
			return nil, fmt.Errorf("connector %q virtualPrefix must be an IPv6 /16 inside fd20::/11", value.ConnectorID)
		}
		virtualBytes := virtualPrefix.Addr().As16()
		if int(virtualBytes[1]-0x20) != value.Slot {
			return nil, fmt.Errorf("connector %q virtualPrefix does not match slot %d", value.ConnectorID, value.Slot)
		}
		realPrefix, err := ipv6Prefix16("realPrefix", value.RealPrefix)
		if err != nil {
			return nil, fmt.Errorf("connector %q: %w", value.ConnectorID, err)
		}
		suffix, err := dnsSuffixValue("dnsSuffix", value.DNSSuffix)
		if err != nil {
			return nil, fmt.Errorf("connector %q: %w", value.ConnectorID, err)
		}
		if _, exists := seenIDs[value.ConnectorID]; exists {
			return nil, fmt.Errorf("connectorId %q occurs more than once", value.ConnectorID)
		}
		if _, exists := seenSlots[value.Slot]; exists {
			return nil, fmt.Errorf("slot %d occurs more than once", value.Slot)
		}
		if _, exists := seenPrefixes[virtualPrefix]; exists {
			return nil, fmt.Errorf("virtualPrefix %q occurs more than once", virtualPrefix)
		}
		seenIDs[value.ConnectorID] = struct{}{}
		seenSlots[value.Slot] = struct{}{}
		seenPrefixes[virtualPrefix] = struct{}{}
		environmentName := value.EnvironmentName
		if environmentName == "" {
			environmentName = value.Environment
		}
		result = append(result, ConnectorTarget{
			ConnectorID: value.ConnectorID, ProjectID: value.ProjectID, Environment: value.Environment, EnvironmentName: environmentName, Slot: value.Slot,
			VirtualPrefix: virtualPrefix, RealPrefix: realPrefix, DNSSuffix: suffix,
		})
	}
	return result, nil
}

func ipv6Prefix16(name, raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || !prefix.Addr().Is6() || prefix.Bits() != 16 || prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("%s must be a canonical IPv6 /16", name)
	}
	return prefix, nil
}

func virtualNetworkValue(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || !prefix.Addr().Is6() || prefix.Bits() < 10 || prefix.Bits() > 16 || prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("TB_VIRTUAL_NETWORK must be a canonical IPv6 prefix from /10 through /16")
	}
	if !netip.MustParsePrefix("fd00::/8").Contains(prefix.Addr()) {
		return netip.Prefix{}, errors.New("TB_VIRTUAL_NETWORK must be inside fd00::/8")
	}
	return prefix, nil
}

func commaValues(raw string) []string {
	var values []string
	for _, part := range strings.Split(raw, ",") {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func decodedStringList(name string) ([]string, error) {
	raw := required(name)
	if raw == "" {
		return nil, nil
	}
	payload, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", name, err)
	}
	var values []string
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("%s does not contain a string array: %w", name, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("%s contains data after the string array", name)
	}
	for _, item := range values {
		if strings.TrimSpace(item) == "" {
			return nil, fmt.Errorf("%s contains an empty project ID", name)
		}
	}
	return values, nil
}

func dnsSuffixValue(name, raw string) (string, error) {
	suffix := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
	if suffix == "" || suffix == "railway.internal" || !strings.HasSuffix(suffix, ".railway.internal") {
		return "", fmt.Errorf("%s must be a subdomain of railway.internal", name)
	}
	for _, label := range strings.Split(suffix, ".") {
		if !validDNSLabel(label) {
			return "", fmt.Errorf("%s contains an invalid DNS label", name)
		}
	}
	return suffix, nil
}

func validDNSLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || !asciiLetterOrDigit(label[0]) || !asciiLetterOrDigit(label[len(label)-1]) {
		return false
	}
	for index := 1; index < len(label)-1; index++ {
		if !asciiLetterOrDigit(label[index]) && label[index] != '-' {
			return false
		}
	}
	return true
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
