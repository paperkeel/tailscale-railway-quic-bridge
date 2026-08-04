package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

type Issuer struct {
	certificate *x509.Certificate
	privateKey  crypto.Signer
	now         func() time.Time
}

func (i *Issuer) Edge(edgeID string, lifetime time.Duration) (tls.Certificate, time.Time, error) {
	if edgeID == "" || strings.ContainsAny(edgeID, "/?#%") || lifetime <= 0 {
		return tls.Certificate{}, time.Time{}, errors.New("edge certificate request is not valid")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, time.Time{}, fmt.Errorf("create edge certificate key: %w", err)
	}
	now := i.now().UTC()
	if now.Before(i.certificate.NotBefore) || !i.certificate.NotAfter.After(now) {
		return tls.Certificate{}, time.Time{}, errors.New("online intermediate certificate is not currently valid")
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(i.certificate.NotAfter) {
		notAfter = i.certificate.NotAfter
	}
	identity := &url.URL{Scheme: "spiffe", Host: "tailbridge.local", Path: "/edge/" + edgeID}
	serial, err := newSerial()
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "tailbridge-edge-" + edgeID}, NotBefore: now.Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{identity}}
	raw, err := x509.CreateCertificate(rand.Reader, template, i.certificate, publicKey, i.privateKey)
	if err != nil {
		return tls.Certificate{}, time.Time{}, fmt.Errorf("issue edge certificate: %w", err)
	}
	keyRaw, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, time.Time{}, fmt.Errorf("encode edge certificate key: %w", err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.certificate.Raw})...)
	certificate, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}))
	return certificate, notAfter, err
}

func New(certificatePEM, privateKeyPEM []byte) (*Issuer, error) {
	certificateBlock, _ := pem.Decode(certificatePEM)
	keyBlock, _ := pem.Decode(privateKeyPEM)
	if certificateBlock == nil || keyBlock == nil {
		return nil, errors.New("online intermediate certificate or key is not valid PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || !certificate.IsCA {
		return nil, errors.New("online intermediate certificate is not a CA")
	}
	keyValue, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse online intermediate key: %w", err)
	}
	privateKey, ok := keyValue.(crypto.Signer)
	certificateKey, certificateKeyOK := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !certificateKeyOK || !certificateKey.Equal(privateKey.Public()) {
		return nil, errors.New("online intermediate certificate and key do not match")
	}
	return &Issuer{certificate: certificate, privateKey: privateKey, now: time.Now}, nil
}

func (i *Issuer) Connector(projectID, environmentID, keyID string, publicKey ed25519.PublicKey, lifetime time.Duration) ([]byte, string, time.Time, error) {
	if len(publicKey) != ed25519.PublicKeySize || projectID == "" || environmentID == "" || keyID == "" || lifetime <= 0 {
		return nil, "", time.Time{}, errors.New("connector certificate request is not valid")
	}
	for _, segment := range []string{projectID, environmentID, keyID} {
		if strings.ContainsAny(segment, "/?#%") {
			return nil, "", time.Time{}, errors.New("connector identity segment contains a reserved character")
		}
	}
	serial, err := newSerial()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	identity, err := url.Parse(fmt.Sprintf("spiffe://tailbridge.local/connector/%s/%s/%s", projectID, environmentID, keyID))
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("create connector identity: %w", err)
	}
	now := i.now().UTC()
	if now.Before(i.certificate.NotBefore) || !i.certificate.NotAfter.After(now) {
		return nil, "", time.Time{}, errors.New("online intermediate certificate is not currently valid")
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(i.certificate.NotAfter) {
		notAfter = i.certificate.NotAfter
	}
	if !notAfter.After(now) {
		return nil, "", time.Time{}, errors.New("online intermediate leaves no validity for the connector certificate")
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tailbridge-connector-" + environmentID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identity},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, i.certificate, publicKey, i.privateKey)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("issue connector certificate: %w", err)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	chain := append(leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.certificate.Raw})...)
	return chain, serial.Text(16), notAfter, nil
}

func newSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("create certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}
