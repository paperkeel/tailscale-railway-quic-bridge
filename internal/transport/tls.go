package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/config"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/protocol"
)

func ServerTLS(c config.Common) (*tls.Config, error) {
	certificate, roots, err := credentials(c)
	if err != nil {
		return nil, err
	}
	configuration := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		NextProtos:   []string{protocol.ALPNV3, protocol.ALPN},
		VerifyConnection: func(state tls.ConnectionState) error {
			if err := verifyPeerCertificate(state, roots, x509.ExtKeyUsageClientAuth); err != nil {
				return err
			}
			if state.NegotiatedProtocol == protocol.ALPNV3 {
				_, _, _, err := PeerConnectorIdentityV3(state)
				return err
			}
			_, err := PeerIdentity(state, "connector")
			return err
		},
	}
	if c.GetCertificate != nil {
		configuration.Certificates = nil
		configuration.GetCertificate = c.GetCertificate
	}
	return configuration, nil
}

func ClientTLS(c config.Common) (*tls.Config, error) {
	certificate, roots, err := credentials(c)
	if err != nil {
		return nil, err
	}
	edgeID := c.EdgeID
	if edgeID == "" {
		edgeID = c.ConnectorID
	}
	alpn := protocol.ALPN
	if c.Environment != "" && c.ConnectorID != "" && strings.Contains(c.ConnectorID, "/") {
		alpn = protocol.ALPNV3
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            roots,
		NextProtos:         []string{alpn},
		InsecureSkipVerify: true,
		VerifyConnection:   verifyIdentity(roots, "edge", edgeID, x509.ExtKeyUsageServerAuth),
	}, nil
}

func PeerConnectorIdentityV3(state tls.ConnectionState) (string, string, string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", "", "", errors.New("peer certificate is missing")
	}
	const prefix = "/connector/"
	for _, candidate := range state.PeerCertificates[0].URIs {
		if candidate.Scheme != "spiffe" || candidate.Host != "tailbridge.local" || !strings.HasPrefix(candidate.Path, prefix) || candidate.RawQuery != "" || candidate.Fragment != "" {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(candidate.Path, prefix), "/")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return "", "", "", errors.New("peer connector identity is not valid")
		}
		return parts[0], parts[1], parts[2], nil
	}
	return "", "", "", errors.New("peer certificate has no connector identity")
}

// RegistrationServerTLS authenticates the public registration endpoint to a
// connector. Connector authentication happens through the enrollment proof.
func RegistrationServerTLS(c config.Common) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil {
		return nil, err
	}
	configuration := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{protocol.RegistrationALPN},
	}
	if c.GetCertificate != nil {
		configuration.Certificates = nil
		configuration.GetCertificate = c.GetCertificate
	}
	return configuration, nil
}

func RegistrationClientTLS(c config.Common) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CABundle) {
		return nil, errors.New("TB_TRUST_BUNDLE_B64 contains no certificates")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		RootCAs:            roots,
		NextProtos:         []string{protocol.RegistrationALPN},
		InsecureSkipVerify: true,
		VerifyConnection:   verifyIdentity(roots, "edge", c.EdgeID, x509.ExtKeyUsageServerAuth),
	}, nil
}

func verifyRoleIdentity(roots *x509.CertPool, role string, usage x509.ExtKeyUsage) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if err := verifyPeerCertificate(state, roots, usage); err != nil {
			return err
		}
		_, err := PeerIdentity(state, role)
		return err
	}
}

func verifyIdentity(roots *x509.CertPool, role, id string, usage x509.ExtKeyUsage) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if err := verifyPeerCertificate(state, roots, usage); err != nil {
			return err
		}
		identity, err := PeerIdentity(state, role)
		if err != nil {
			return err
		}
		if identity != id {
			return fmt.Errorf("peer identity does not match spiffe://tailbridge.local/%s/%s", role, id)
		}
		return nil
	}
}

func verifyPeerCertificate(state tls.ConnectionState, roots *x509.CertPool, usage x509.ExtKeyUsage) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("peer certificate is missing")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}

func PeerIdentity(state tls.ConnectionState, role string) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is missing")
	}
	prefix := "spiffe://tailbridge.local/" + role + "/"
	var identity string
	for _, candidate := range state.PeerCertificates[0].URIs {
		value := candidate.String()
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		id := strings.TrimPrefix(value, prefix)
		if id == "" || strings.Contains(id, "/") || candidate.RawQuery != "" || candidate.Fragment != "" {
			return "", fmt.Errorf("peer %s identity is not valid", role)
		}
		if identity != "" {
			return "", fmt.Errorf("peer has more than one %s identity", role)
		}
		identity = id
	}
	if identity == "" {
		return "", fmt.Errorf("peer certificate has no %s identity", role)
	}
	return identity, nil
}

func credentials(c config.Common) (tls.Certificate, *x509.CertPool, error) {
	certificate, err := tls.X509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CABundle) {
		return tls.Certificate{}, nil, errors.New("TB_MTLS_CA_B64 contains no certificates")
	}
	return certificate, roots, nil
}
