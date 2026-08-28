package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"slices"
	"time"

	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/config"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/enrollment"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/oidc"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/pki"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/registry"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/status"
)

type Server struct {
	config    config.Edge
	store     *registry.Store
	validator *oidc.Validator
	issuer    *pki.Issuer
	logger    *slog.Logger
	whois     func(context.Context, string) ([]string, error)
	status    *status.Server
}

var resolveApprovalAddress = interfaceAddress

type approvalRequest struct {
	RequestID         string `json:"requestId"`
	ProviderID        string `json:"providerId"`
	OIDCToken         string `json:"oidcToken"`
	EnrollmentNonce   string `json:"enrollmentNonce"`
	PublicFingerprint string `json:"publicFingerprint"`
}

type revokeRequest struct {
	ProjectID     string `json:"projectId"`
	EnvironmentID string `json:"environmentId"`
	ProviderID    string `json:"providerId"`
	OIDCToken     string `json:"oidcToken"`
}

func NewServer(cfg config.Edge, store *registry.Store, logger *slog.Logger, metrics ...*status.Server) (*Server, error) {
	var policies []oidc.Policy
	if err := json.Unmarshal(cfg.OIDCPolicies, &policies); err != nil {
		return nil, fmt.Errorf("parse TB_OIDC_POLICIES_B64: %w", err)
	}
	validator, err := oidc.New(policies, nil)
	if err != nil {
		return nil, err
	}
	issuer, err := pki.New(cfg.IntermediateCertificate, cfg.IntermediatePrivateKey)
	if err != nil {
		return nil, err
	}
	server := &Server{config: cfg, store: store, validator: validator, issuer: issuer, logger: logger, whois: tailscaleTags}
	if len(metrics) > 0 {
		server.status = metrics[0]
	}
	return server, nil
}

func (s *Server) Run(ctx context.Context) error {
	waitContext, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var address string
	var err error
	for {
		address, err = resolveApprovalAddress(s.config.ApprovalListenAddr)
		if err == nil {
			break
		}
		host, _, splitErr := net.SplitHostPort(s.config.ApprovalListenAddr)
		if splitErr != nil || host == "" {
			return err
		}
		if _, parseErr := netip.ParseAddr(host); parseErr == nil {
			return err
		}
		select {
		case <-waitContext.Done():
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("wait for approval listener address: %w", err)
		case <-time.After(250 * time.Millisecond):
		}
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for approvals: %w", err)
	}
	server := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/pending", s.pendingForIdentity)
	mux.HandleFunc("GET /v1/pending/{id}", s.pending)
	mux.HandleFunc("POST /v1/approve", s.approve)
	mux.HandleFunc("POST /v1/revoke", s.revoke)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			http.Error(response, "The caller address is not valid.", http.StatusForbidden)
			return
		}
		tags, err := s.whois(request.Context(), host)
		if err != nil || !hasAllowedTag(tags, s.config.ApprovalTailscaleTags) {
			s.logger.Warn("approval caller rejected", "event.name", "approval.rejected", "source_address", host, "reason", "tailscale_identity")
			http.Error(response, "The Tailscale identity is not allowed.", http.StatusForbidden)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(response, request)
	})
}

func (s *Server) pendingForIdentity(response http.ResponseWriter, request *http.Request) {
	requests, err := s.store.PendingForIdentity(request.Context(), request.URL.Query().Get("projectId"), request.URL.Query().Get("environmentId"))
	if err != nil {
		http.Error(response, "The registry could not read pending requests.", http.StatusInternalServerError)
		return
	}
	if len(requests) == 0 {
		http.Error(response, "The registration request was not found.", http.StatusNotFound)
		return
	}
	pending := requests[len(requests)-1]
	if pendingExpired(pending) {
		http.Error(response, "The registration request was not found.", http.StatusNotFound)
		return
	}
	if !authorizedPending(request, pending) {
		http.Error(response, "The registration request was not found.", http.StatusNotFound)
		return
	}
	if pendingExpired(pending) {
		http.Error(response, "The registration request was not found.", http.StatusNotFound)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"requestId": pending.ID, "state": s.readinessState(request.Context(), pending), "projectId": pending.ProjectID, "environmentId": pending.EnvironmentID, "environmentName": pending.EnvironmentName, "publicFingerprint": pending.IdentityKeyID})
}

func (s *Server) pending(response http.ResponseWriter, request *http.Request) {
	pending, err := s.store.Pending(request.Context(), request.PathValue("id"))
	if errors.Is(err, registry.ErrNotFound) {
		http.Error(response, "The registration request was not found.", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(response, "The registry could not read the request.", http.StatusInternalServerError)
		return
	}
	if !authorizedPending(request, pending) {
		http.Error(response, "The registration request was not found.", http.StatusNotFound)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"requestId": pending.ID, "state": s.readinessState(request.Context(), pending), "projectId": pending.ProjectID,
		"environmentId": pending.EnvironmentID, "environmentName": pending.EnvironmentName,
		"publicFingerprint": pending.IdentityKeyID, "projectAlias": pending.ProjectAlias,
		"environmentAlias": pending.EnvironmentAlias,
	})
}

func (s *Server) readinessState(ctx context.Context, pending registry.PendingRequest) string {
	if pending.State != "approved" {
		return pending.State
	}
	registration, err := s.store.Registration(ctx, pending.ProjectID, pending.EnvironmentID)
	if err != nil || registration.State != "ready" {
		return "connecting"
	}
	generation, err := s.store.PendingRouteGeneration(ctx)
	if err == nil && slices.Contains(generation.DesiredRoutes, registration.VirtualPrefix) {
		return "connecting"
	}
	if err != nil && !errors.Is(err, registry.ErrNotFound) {
		return "connecting"
	}
	return "ready"
}

func authorizedPending(request *http.Request, pending registry.PendingRequest) bool {
	nonce := request.Header.Get("X-Tailbridge-Enrollment-Nonce")
	registrationRequest := protocol.RegistrationRequest{ProjectID: pending.ProjectID, EnvironmentID: pending.EnvironmentID, IdentityKey: pending.IdentityKey, TransportKey: pending.TransportKey}
	return nonce != "" && hmac.Equal(pending.Proof, enrollment.Proof([]byte(nonce), registrationRequest))
}

func pendingExpired(pending registry.PendingRequest) bool {
	return pending.State == "pending" && !pending.ExpiresAt.After(time.Now())
}

func (s *Server) approve(response http.ResponseWriter, request *http.Request) {
	var input approvalRequest
	if err := decode(request, &input); err != nil {
		http.Error(response, "The approval request is not valid.", http.StatusBadRequest)
		return
	}
	pending, err := s.store.Pending(request.Context(), input.RequestID)
	if err != nil {
		http.Error(response, "The registration request was not found.", http.StatusNotFound)
		return
	}
	if s.config.RegistrationFrozen {
		s.reject(response, pending, "registration_frozen", http.StatusLocked)
		return
	}
	if pending.IdentityKeyID != input.PublicFingerprint {
		s.reject(response, pending, "fingerprint_mismatch", http.StatusForbidden)
		return
	}
	registrationRequest := protocol.RegistrationRequest{ProjectID: pending.ProjectID, EnvironmentID: pending.EnvironmentID, IdentityKey: pending.IdentityKey, TransportKey: pending.TransportKey}
	if !hmac.Equal(pending.Proof, enrollment.Proof([]byte(input.EnrollmentNonce), registrationRequest)) {
		s.reject(response, pending, "enrollment_proof", http.StatusForbidden)
		return
	}
	if s.config.NewProjectsFrozen {
		known, err := s.store.ProjectKnown(request.Context(), pending.ProjectID)
		if err != nil {
			http.Error(response, "The registry could not check the project.", http.StatusInternalServerError)
			return
		}
		if !known && !slices.Contains(s.config.AllowedProjectIDs, pending.ProjectID) {
			s.reject(response, pending, "new_projects_frozen", http.StatusLocked)
			return
		}
	}
	identity, err := s.validator.Validate(request.Context(), input.ProviderID, input.OIDCToken, oidc.Request{ProjectID: pending.ProjectID, EnvironmentName: pending.EnvironmentName})
	if err != nil {
		s.observeOIDC("failure", "validation")
		s.reject(response, pending, "oidc_validation", http.StatusForbidden)
		return
	}
	s.observeOIDC("success", "accepted")
	certificate, certificateID, certificateEnd, err := s.issuer.Connector(pending.ProjectID, pending.EnvironmentID, pending.IdentityKeyID, ed25519.PublicKey(pending.TransportKey), 24*time.Hour)
	if err != nil {
		http.Error(response, "The connector certificate could not be issued.", http.StatusInternalServerError)
		return
	}
	leaseClass, leaseDuration := s.lease(pending.EnvironmentName)
	audit, _ := json.Marshal(map[string]string{"repository_id": identity.RepositoryID, "repository": identity.Repository, "workflow_ref": identity.WorkflowRef, "workflow_sha": identity.WorkflowSHA, "run_id": identity.RunID, "run_attempt": identity.RunAttempt})
	registration, created, err := s.store.Approve(request.Context(), registry.Approval{
		RequestID: pending.ID, ProviderID: identity.ProviderID, JTI: identity.JTI,
		JTIExpiresAt: identity.ExpiresAt, LeaseClass: leaseClass, LeaseDuration: leaseDuration,
		RealPrefix: netip.MustParsePrefix("fd12::/16"), CertificatePEM: certificate,
		CertificateID: certificateID, CertificateEnd: certificateEnd, AuditJSON: string(audit),
	})
	if errors.Is(err, registry.ErrReplay) {
		s.reject(response, pending, "oidc_replay", http.StatusConflict)
		return
	}
	if errors.Is(err, registry.ErrPoolExhausted) {
		s.reject(response, pending, "address_pool_exhausted", http.StatusInsufficientStorage)
		return
	}
	if err != nil {
		http.Error(response, "The registration could not be approved.", http.StatusInternalServerError)
		return
	}
	s.logger.Info("registration approved", "event.name", "registration.approved", "request_id", pending.ID, "project_id", pending.ProjectID, "environment_id", pending.EnvironmentID, "repository_id", identity.RepositoryID, "workflow_run_id", identity.RunID, "public_key_fingerprint", pending.IdentityKeyID, "route", registration.VirtualPrefix.String(), "created", created)
	writeJSON(response, http.StatusOK, map[string]any{"state": "approved", "created": created, "virtualPrefix": registration.VirtualPrefix.String(), "leaseExpiresAt": registration.LeaseExpiresAt})
}

func (s *Server) revoke(response http.ResponseWriter, request *http.Request) {
	var input revokeRequest
	if err := decode(request, &input); err != nil || input.ProjectID == "" || input.EnvironmentID == "" {
		http.Error(response, "The revocation request is not valid.", http.StatusBadRequest)
		return
	}
	registration, err := s.store.Registration(request.Context(), input.ProjectID, input.EnvironmentID)
	if err != nil {
		http.Error(response, "The registration was not found.", http.StatusNotFound)
		return
	}
	identity, err := s.validator.Validate(request.Context(), input.ProviderID, input.OIDCToken, oidc.Request{ProjectID: input.ProjectID, EnvironmentName: registration.EnvironmentName})
	if err != nil {
		s.observeOIDC("failure", "validation")
		http.Error(response, "The revocation identity is not allowed.", http.StatusForbidden)
		return
	}
	s.observeOIDC("success", "accepted")
	if err := s.store.ConsumeReplay(request.Context(), identity.ProviderID, identity.JTI, identity.ExpiresAt); err != nil {
		http.Error(response, "The revocation token was already used.", http.StatusConflict)
		return
	}
	audit, _ := json.Marshal(map[string]string{"repository_id": identity.RepositoryID, "workflow_ref": identity.WorkflowRef, "run_id": identity.RunID})
	if err := s.store.Revoke(request.Context(), input.ProjectID, input.EnvironmentID, s.config.SlotQuarantine, string(audit)); err != nil {
		http.Error(response, "The registration could not be revoked.", http.StatusBadRequest)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"state": "revoked"})
}

func (s *Server) observeOIDC(result, reason string) {
	if s.status != nil {
		s.status.ObserveOIDC(result, reason)
	}
}

func (s *Server) reject(response http.ResponseWriter, pending registry.PendingRequest, reason string, status int) {
	s.logger.Warn("registration approval rejected", "event.name", "registration.rejected", "request_id", pending.ID, "project_id", pending.ProjectID, "environment_id", pending.EnvironmentID, "public_key_fingerprint", pending.IdentityKeyID, "freeze_state", s.config.RegistrationFrozen, "reason", reason)
	writeJSON(response, status, map[string]string{"state": "rejected", "reason": reason})
}

func (s *Server) lease(environment string) (string, time.Duration) {
	if slices.Contains(s.config.PersistentEnvironments, environment) {
		return "persistent", s.config.PersistentLease
	}
	return "preview", s.config.PreviewLease
}

func tailscaleTags(ctx context.Context, address string) ([]string, error) {
	command := exec.CommandContext(ctx, "/usr/local/bin/tailscale", "whois", "--json", address)
	payload, err := command.Output()
	if err != nil {
		return nil, err
	}
	var result struct {
		Node struct {
			Tags []string `json:"Tags"`
		} `json:"Node"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return nil, err
	}
	return result.Node.Tags, nil
}

func interfaceAddress(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("approval listener address is not valid: %w", err)
	}
	if host == "" {
		return "", errors.New("approval listener must not use an unspecified address")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.IsUnspecified() {
			return "", errors.New("approval listener must not use an unspecified address")
		}
		return net.JoinHostPort(host, port), nil
	}
	device, err := net.InterfaceByName(host)
	if err != nil {
		return "", fmt.Errorf("find approval interface %q: %w", host, err)
	}
	addresses, err := device.Addrs()
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() {
			return net.JoinHostPort(prefix.Addr().String(), port), nil
		}
	}
	return "", fmt.Errorf("interface %q has no IPv4 address", host)
}

func hasAllowedTag(actual, allowed []string) bool {
	for _, tag := range actual {
		if slices.Contains(allowed, tag) {
			return true
		}
	}
	return false
}

func decode(request *http.Request, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 64*1024))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
