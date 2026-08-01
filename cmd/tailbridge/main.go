package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init":
		if err := initialize(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tailbridge <init|version>")
	os.Exit(2)
}

func initialize(arguments []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	output := flags.String("output", ".", "directory for generated environment files")
	connectorID := flags.String("connector-id", "railway-production", "stable connector identity")
	environment := flags.String("environment", "production", "Railway environment name")
	edgeEndpoint := flags.String("edge-endpoint", "edge.example.com:4433", "public edge QUIC endpoint")
	force := flags.Bool("force", false, "replace existing generated files")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	caCert, caKey, err := certificateAuthority(*connectorID)
	if err != nil {
		return err
	}
	edgeCert, edgeKey, err := leaf(caCert, caKey, "edge", *connectorID, true)
	if err != nil {
		return err
	}
	connectorCert, connectorKey, err := leaf(caCert, caKey, "connector", *connectorID, false)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*output, 0o700); err != nil {
		return err
	}
	edgePath := filepath.Join(*output, "edge.env")
	connectorPath := filepath.Join(*output, "connector.env")
	policyPath := filepath.Join(*output, "tailscale-policy.hujson")
	if !*force {
		for _, path := range []string{edgePath, connectorPath, policyPath} {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to replace %s without --force", path)
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	common := func(cert, key []byte) string {
		return fmt.Sprintf("TB_CONNECTOR_ID=%s\nTB_ENVIRONMENT=%s\nTB_MTLS_CA_B64=%s\nTB_MTLS_CERT_B64=%s\nTB_MTLS_KEY_B64=%s\n", *connectorID, *environment, b64(caCert.Raw), b64PEM("CERTIFICATE", cert), b64PEM("PRIVATE KEY", key))
	}
	edge := common(edgeCert, edgeKey) + "TB_ALLOWED_ROUTES=fd12::/16\nTB_QUIC_LISTEN_ADDR=:4433\nTS_AUTHKEY=replace-me\nTS_HOSTNAME=tailbridge-" + *environment + "\nTS_STATE_DIR=/var/lib/tailscale\nTS_AUTH_ONCE=true\nTS_USERSPACE=false\nTS_EXTRA_ARGS=--advertise-routes=fd12::/16 --advertise-tags=tag:tailbridge\n"
	connector := common(connectorCert, connectorKey) + "TB_EDGE_ENDPOINT=" + *edgeEndpoint + "\nTB_ALLOWED_DESTINATIONS=fd12::/16\n"
	if err := writeSecret(edgePath, edge, *force); err != nil {
		return err
	}
	if err := writeSecret(connectorPath, connector, *force); err != nil {
		return err
	}
	policy := "{\n\t\"tagOwners\": { \"tag:tailbridge\": [\"autogroup:admin\"] },\n\t\"autoApprovers\": { \"routes\": { \"fd12::/16\": [\"tag:tailbridge\"] } }\n}\n"
	if err := writeSecret(policyPath, policy, *force); err != nil {
		return err
	}
	fmt.Printf("wrote Tailbridge configuration to %s\n", *output)
	return nil
}

func certificateAuthority(name string) (*x509.Certificate, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Tailbridge " + name + " CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(raw)
	return certificate, privateKey, err
}

func leaf(ca *x509.Certificate, caKey ed25519.PrivateKey, role, id string, server bool) ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	identity, _ := url.Parse("spiffe://tailbridge.local/" + role + "/" + id)
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if server {
		usage = append(usage, x509.ExtKeyUsageServerAuth)
	}
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "tailbridge-" + role + "-" + id}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 3, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage, URIs: []*url.URL{identity}}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	return raw, key, err
}

func serial() *big.Int {
	value, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return value
}
func b64(raw []byte) string { return b64PEM("CERTIFICATE", raw) }
func b64PEM(kind string, raw []byte) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: raw}))
}
func writeSecret(path, content string, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return file.Chmod(0o600)
}
