package pki

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"testing"
	"time"
)

func TestIssueConnectorCertificate(t *testing.T) {
	if _, err := New([]byte("invalid"), []byte("invalid")); err == nil {
		t.Fatal("New() accepted invalid PEM")
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "online"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rawCA, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(private)
	issuer, err := New(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawCA}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	if err != nil {
		t.Fatal(err)
	}
	connectorPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	chain, id, expires, err := issuer.Connector("project", "environment", "key", connectorPublic, 24*time.Hour)
	if err != nil || id == "" || expires.Before(now.Add(23*time.Hour)) {
		t.Fatalf("Connector() id=%q expires=%v err=%v", id, expires, err)
	}
	block, _ := pem.Decode(chain)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(certificate.URIs) != 1 || certificate.URIs[0].String() != "spiffe://tailbridge.local/connector/project/environment/key" {
		t.Fatalf("issued certificate = %#v, %v", certificate, err)
	}
	if _, _, _, err := issuer.Connector("project/other", "environment", "key", connectorPublic, time.Hour); err == nil {
		t.Fatal("Connector() accepted a reserved identity character")
	}
	if _, _, _, err := issuer.Connector("project", "environment", "key", connectorPublic, 0); err == nil {
		t.Fatal("Connector() accepted a zero lifetime")
	}
	issuer.now = func() time.Time { return caTemplate.NotAfter.Add(time.Second) }
	if _, _, _, err := issuer.Connector("project", "environment", "key", connectorPublic, time.Hour); err == nil {
		t.Fatal("Connector() accepted an expired intermediate")
	}
	issuer.now = time.Now
	edgeCertificate, edgeExpiry, err := issuer.Edge("edge", 24*time.Hour)
	if err != nil || len(edgeCertificate.Certificate) != 2 || !edgeExpiry.After(now) {
		t.Fatalf("Edge() certificate=%#v expiry=%v err=%v", edgeCertificate, edgeExpiry, err)
	}
	if _, _, err := issuer.Edge("invalid/edge", time.Hour); err == nil {
		t.Fatal("Edge() accepted a reserved identity character")
	}
	manager, err := NewEdgeManager("edge", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawCA}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.GetCertificate(nil)
	if err != nil || len(first.Certificate) != 2 {
		t.Fatalf("GetCertificate() = %#v, %v", first, err)
	}
	manager.renewAfter = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Millisecond)
	defer cancel()
	if err := manager.Run(ctx, slog.Default()); err != nil {
		t.Fatal(err)
	}
	second, err := manager.GetCertificate(nil)
	if err != nil || second == first {
		t.Fatalf("rotated GetCertificate() = %#v, %v", second, err)
	}
}
