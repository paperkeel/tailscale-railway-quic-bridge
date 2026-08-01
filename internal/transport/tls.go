package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/protocol"
)

func ServerTLS(c config.Common) (*tls.Config, error) {
	certificate, roots, err := credentials(c)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{certificate},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        roots,
		NextProtos:       []string{protocol.ALPN},
		VerifyConnection: verifyIdentity(roots, "connector", c.ConnectorID, x509.ExtKeyUsageClientAuth),
	}, nil
}

func ClientTLS(c config.Common) (*tls.Config, error) {
	certificate, roots, err := credentials(c)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            roots,
		NextProtos:         []string{protocol.ALPN},
		InsecureSkipVerify: true,
		VerifyConnection:   verifyIdentity(roots, "edge", c.ConnectorID, x509.ExtKeyUsageServerAuth),
	}, nil
}

func verifyIdentity(roots *x509.CertPool, role, id string, usage x509.ExtKeyUsage) func(tls.ConnectionState) error {
	want := "spiffe://tailbridge.local/" + role + "/" + id
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("peer certificate is missing")
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return err
		}
		for _, identity := range state.PeerCertificates[0].URIs {
			if identity.String() == want {
				return nil
			}
		}
		return fmt.Errorf("peer identity does not match %s", want)
	}
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
