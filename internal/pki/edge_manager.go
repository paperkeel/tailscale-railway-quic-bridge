package pki

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	edgeCertificateLifetime = 24 * time.Hour
	edgeCertificateRenewal  = 12 * time.Hour
)

type EdgeManager struct {
	issuer     *Issuer
	edgeID     string
	value      atomic.Pointer[tls.Certificate]
	renewAfter time.Duration
}

func NewEdgeManager(edgeID string, certificatePEM, privateKeyPEM []byte) (*EdgeManager, error) {
	issuer, err := New(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	manager := &EdgeManager{issuer: issuer, edgeID: edgeID, renewAfter: edgeCertificateRenewal}
	if err := manager.rotate(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *EdgeManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := m.value.Load()
	if certificate == nil {
		return nil, errors.New("edge certificate is not available")
	}
	return certificate, nil
}

func (m *EdgeManager) Run(ctx context.Context, logger *slog.Logger) error {
	delay := m.renewAfter
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if err := m.rotate(); err != nil {
				logger.Error("edge certificate renewal failed", "event.name", "certificate.renewed", "credential", "edge", "outcome", "failure", "error", err)
				delay = time.Minute
			} else {
				logger.Info("edge certificate renewed", "event.name", "certificate.renewed", "credential", "edge", "outcome", "success")
				delay = m.renewAfter
			}
			timer.Reset(delay)
		}
	}
}

func (m *EdgeManager) rotate() error {
	certificate, _, err := m.issuer.Edge(m.edgeID, edgeCertificateLifetime)
	if err != nil {
		return err
	}
	m.value.Store(&certificate)
	return nil
}
