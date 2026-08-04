package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/pki"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/registry"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/transport"
	"github.com/quic-go/quic-go"
)

type Server struct {
	config config.Edge
	store  *registry.Store
	logger *slog.Logger
	issuer *pki.Issuer
	status *status.Server
	limit  chan struct{}
	mu     sync.Mutex
	source map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	count int
}

func NewServer(cfg config.Edge, store *registry.Store, logger *slog.Logger, metrics ...*status.Server) (*Server, error) {
	issuer, err := pki.New(cfg.IntermediateCertificate, cfg.IntermediatePrivateKey)
	if err != nil {
		return nil, err
	}
	server := &Server{config: cfg, store: store, logger: logger, issuer: issuer, source: make(map[string]*rateWindow), limit: make(chan struct{}, 64)}
	if len(metrics) > 0 {
		server.status = metrics[0]
	}
	return server, nil
}

func (s *Server) Run(ctx context.Context) error {
	tlsConfig, err := transport.RegistrationServerTLS(s.config.Common)
	if err != nil {
		return fmt.Errorf("configure registration TLS: %w", err)
	}
	listener, err := quic.ListenAddr(s.config.RegistrationListenAddr, tlsConfig, transport.QUICConfig(64))
	if err != nil {
		return fmt.Errorf("listen for registration: %w", err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept registration: %w", err)
		}
		select {
		case s.limit <- struct{}{}:
			go func() {
				defer func() { <-s.limit }()
				s.handle(ctx, conn)
			}()
		default:
			_ = conn.CloseWithError(1, "registration capacity reached")
		}
	}
}

func (s *Server) handle(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "registration exchange complete")
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()
	var request protocol.RegistrationRequest
	if err := protocol.ReadFrame(stream, &request); err != nil {
		return
	}
	response := s.process(ctx, conn.RemoteAddr(), request)
	if err := protocol.WriteFrame(stream, response); err != nil {
		return
	}
	_ = stream.Close()
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
}

func (s *Server) process(ctx context.Context, source net.Addr, request protocol.RegistrationRequest) (response protocol.RegistrationResponse) {
	started := time.Now()
	defer func() {
		if s.status != nil {
			reason := response.ErrorCode
			if reason == "" {
				reason = response.State
			}
			s.status.ObserveRegistration(response.State, reason, time.Since(started))
		}
	}()
	sourceAddress := sourceHost(source)
	if request.Kind == "renew" {
		return s.renew(ctx, sourceAddress, request)
	}
	if request.RequestID != "" {
		if !s.allow(sourceAddress) {
			return protocol.RegistrationResponse{RequestID: request.RequestID, State: "rejected", ErrorCode: "rate_limited", RetryAfterMS: 60000}
		}
		pending, err := s.store.Pending(ctx, request.RequestID)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				return protocol.RegistrationResponse{RequestID: request.RequestID, State: "expired", ErrorCode: "request_not_found"}
			}
			return protocol.RegistrationResponse{RequestID: request.RequestID, State: "rejected", ErrorCode: "internal_error", RetryAfterMS: 1000}
		}
		return s.responseForPending(ctx, pending)
	}
	if s.config.RegistrationFrozen {
		s.logger.Warn("registration blocked", "event.name", "registration.frozen", "source_address", source.String(), "project_id", request.ProjectID, "environment_id", request.EnvironmentID, "freeze_state", true)
		return protocol.RegistrationResponse{State: "frozen", ErrorCode: "registration_frozen"}
	}
	if !s.allow(sourceAddress) {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "rate_limited", RetryAfterMS: 60000}
	}
	if request.ProjectID == "" || request.EnvironmentID == "" || request.EnvironmentName == "" || len(request.IdentityKey) != 32 || len(request.TransportKey) != 32 || len(request.Proof) != 32 {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "invalid_request"}
	}
	id, err := randomRequestID()
	if err != nil {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "internal_error"}
	}
	pending, created, err := s.store.CreatePending(ctx, registry.PendingRequest{
		ID: id, Kind: request.Kind, ProjectID: request.ProjectID, EnvironmentID: request.EnvironmentID,
		EnvironmentName: request.EnvironmentName, ProjectAlias: request.ProjectAlias,
		EnvironmentAlias: request.EnvironmentAlias, IdentityKey: request.IdentityKey,
		TransportKey: request.TransportKey, Proof: request.Proof, SourceAddress: sourceAddress,
	})
	if errors.Is(err, registry.ErrIdentityConflict) {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "identity_rotation_required"}
	}
	if errors.Is(err, registry.ErrRateLimited) {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "pending_limit", RetryAfterMS: 60000}
	}
	if err != nil {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "internal_error"}
	}
	s.logger.Info("registration requested", "event.name", "registration.requested", "request_id", pending.ID, "source_address", source.String(), "project_id", pending.ProjectID, "environment_id", pending.EnvironmentID, "public_key_fingerprint", pending.IdentityKeyID, "created", created)
	return protocol.RegistrationResponse{RequestID: pending.ID, State: "pending", RetryAfterMS: 1000}
}

func sourceHost(source net.Addr) string {
	host, _, err := net.SplitHostPort(source.String())
	if err == nil {
		return host
	}
	return source.String()
}

func (s *Server) renew(ctx context.Context, sourceAddress string, request protocol.RegistrationRequest) protocol.RegistrationResponse {
	if !s.allow(sourceAddress) || request.ProjectID == "" || request.EnvironmentID == "" || len(request.IdentityKey) != ed25519.PublicKeySize || len(request.TransportKey) != ed25519.PublicKeySize || len(request.Proof) != ed25519.SignatureSize {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "invalid_renewal"}
	}
	registration, err := s.store.Registration(ctx, request.ProjectID, request.EnvironmentID)
	if err != nil {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "unknown_identity"}
	}
	keyID := registry.Fingerprint(request.IdentityKey)
	activeKey, err := s.store.ActiveIdentityKey(ctx, registration.ID, keyID)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(activeKey), RenewalMessage(request), request.Proof) {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "invalid_identity_proof"}
	}
	certificate, certificateID, certificateEnd, err := s.issuer.Connector(request.ProjectID, request.EnvironmentID, keyID, ed25519.PublicKey(request.TransportKey), 24*time.Hour)
	if err != nil {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "certificate_issuance"}
	}
	leaseDuration := s.config.PreviewLease
	for _, persistent := range s.config.PersistentEnvironments {
		if persistent == registration.EnvironmentName {
			leaseDuration = s.config.PersistentLease
			break
		}
	}
	registration, err = s.store.Renew(ctx, registration, keyID, certificate, certificateID, certificateEnd, leaseDuration)
	if err != nil {
		return protocol.RegistrationResponse{State: "rejected", ErrorCode: "renewal_rejected"}
	}
	s.logger.Info("connector certificate renewed", "event.name", "certificate.renewed", "project_id", registration.ProjectID, "environment_id", registration.EnvironmentID, "public_key_fingerprint", keyID, "certificate_expiry", certificateEnd)
	return protocol.RegistrationResponse{State: "approved", VirtualPrefix: registration.VirtualPrefix.String(), RealPrefix: registration.RealPrefix.String(), DNSSuffix: registration.ProjectAlias + "." + registration.EnvironmentAlias + ".railway.internal", CertificatePEM: certificate, CertificateEnd: certificateEnd.Unix(), LeaseExpiresAt: registration.LeaseExpiresAt.Unix()}
}

func (s *Server) responseForPending(ctx context.Context, pending registry.PendingRequest) protocol.RegistrationResponse {
	if pending.State == "pending" && !pending.ExpiresAt.After(time.Now()) {
		return protocol.RegistrationResponse{RequestID: pending.ID, State: "expired", ErrorCode: "request_expired"}
	}
	if pending.State == "approved" {
		registration, err := s.store.Registration(ctx, pending.ProjectID, pending.EnvironmentID)
		if err != nil {
			return protocol.RegistrationResponse{RequestID: pending.ID, State: "pending", RetryAfterMS: 1000}
		}
		credential, err := s.store.Credential(ctx, registration.ID)
		if err != nil {
			return protocol.RegistrationResponse{RequestID: pending.ID, State: "pending", RetryAfterMS: 1000}
		}
		return protocol.RegistrationResponse{RequestID: pending.ID, State: "approved", VirtualPrefix: registration.VirtualPrefix.String(), RealPrefix: registration.RealPrefix.String(), DNSSuffix: pending.ProjectAlias + "." + pending.EnvironmentAlias + ".railway.internal", CertificatePEM: credential.CertificatePEM, CertificateEnd: credential.NotAfter.Unix(), LeaseExpiresAt: registration.LeaseExpiresAt.Unix()}
	}
	return protocol.RegistrationResponse{RequestID: pending.ID, State: pending.State, RetryAfterMS: 1000}
}

func (s *Server) allow(source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.source) >= 1024 {
		for key, candidate := range s.source {
			if now.Sub(candidate.start) >= time.Minute {
				delete(s.source, key)
			}
		}
		if len(s.source) >= 2048 {
			if _, known := s.source[source]; !known {
				return false
			}
		}
	}
	window := s.source[source]
	if window == nil || now.Sub(window.start) >= time.Minute {
		s.source[source] = &rateWindow{start: now, count: 1}
		return true
	}
	window.count++
	return window.count <= 30
}

func randomRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
