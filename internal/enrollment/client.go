package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/config"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/registry"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/transport"
	"github.com/quic-go/quic-go"
)

type localIdentity struct {
	RequestID             string `json:"requestId"`
	ProjectID             string `json:"projectId"`
	EnvironmentID         string `json:"environmentId"`
	IdentityKeyPEM        []byte `json:"identityKeyPem"`
	IdentityCreatedAt     int64  `json:"identityCreatedAt"`
	PendingIdentityKeyPEM []byte `json:"pendingIdentityKeyPem,omitempty"`
	TransportKeyPEM       []byte `json:"transportKeyPem"`
	CertificatePEM        []byte `json:"certificatePem,omitempty"`
	CertificateEnd        int64  `json:"certificateEnd,omitempty"`
	VirtualPrefix         string `json:"virtualPrefix,omitempty"`
	RealPrefix            string `json:"realPrefix,omitempty"`
	DNSSuffix             string `json:"dnsSuffix,omitempty"`
	LeaseExpiresAt        int64  `json:"leaseExpiresAt,omitempty"`
}

const identityLifetime = 365 * 24 * time.Hour

func Ensure(ctx context.Context, cfg config.Connector) (config.Connector, error) {
	if cfg.RegistrationMode != "dynamic" {
		return cfg, nil
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
	}
	identity, err := loadOrCreate(cfg)
	if err != nil {
		return config.Connector{}, err
	}
	if len(identity.CertificatePEM) > 0 && identity.IdentityCreatedAt <= time.Now().Add(-identityLifetime).Unix() && len(identity.PendingIdentityKeyPEM) == 0 && cfg.EnrollmentNonce != "" {
		_, pendingPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return config.Connector{}, fmt.Errorf("create connector rotation key: %w", err)
		}
		identity.PendingIdentityKeyPEM = encodePrivateKey(pendingPrivate)
		identity.RequestID = ""
		if err := save(filepath.Join(cfg.IdentityDir, "registration.json"), identity); err != nil {
			return config.Connector{}, err
		}
	}
	if len(identity.PendingIdentityKeyPEM) > 0 || len(identity.CertificatePEM) == 0 || identity.CertificateEnd <= time.Now().Add(12*time.Hour).Unix() || identity.LeaseExpiresAt <= time.Now().Add(12*time.Hour).Unix() {
		identity, err = register(ctx, cfg, identity)
		if err != nil {
			return config.Connector{}, err
		}
	}
	virtualPrefix, err := netip.ParsePrefix(identity.VirtualPrefix)
	if err != nil {
		return config.Connector{}, fmt.Errorf("read assigned virtual prefix: %w", err)
	}
	realPrefix, err := netip.ParsePrefix(identity.RealPrefix)
	if err != nil {
		return config.Connector{}, fmt.Errorf("read assigned real prefix: %w", err)
	}
	if _, err := privateKey(identity.TransportKeyPEM); err != nil {
		return config.Connector{}, err
	}
	identityPrivate, err := privateKey(identity.IdentityKeyPEM)
	if err != nil {
		return config.Connector{}, err
	}
	cfg.VirtualPrefix = virtualPrefix
	cfg.RealPrefix = realPrefix
	cfg.DNSSuffix = identity.DNSSuffix
	cfg.IdentityKeyID = registry.Fingerprint(identityPrivate.Public().(ed25519.PublicKey))
	cfg.Common.ConnectorID = cfg.ProjectID + "/" + cfg.EnvironmentID
	cfg.Common.Environment = cfg.EnvironmentID
	cfg.Common.Certificate = identity.CertificatePEM
	cfg.Common.PrivateKey = identity.TransportKeyPEM
	return cfg, nil
}

func loadOrCreate(cfg config.Connector) (localIdentity, error) {
	if err := os.MkdirAll(cfg.IdentityDir, 0o700); err != nil {
		return localIdentity{}, fmt.Errorf("create identity directory: %w", err)
	}
	path := filepath.Join(cfg.IdentityDir, "registration.json")
	payload, err := os.ReadFile(path)
	if err == nil {
		var identity localIdentity
		if err := json.Unmarshal(payload, &identity); err != nil {
			return localIdentity{}, fmt.Errorf("read connector identity: %w", err)
		}
		if identity.ProjectID != cfg.ProjectID || identity.EnvironmentID != cfg.EnvironmentID {
			return localIdentity{}, errors.New("the stored connector identity belongs to another Railway environment")
		}
		if identity.IdentityCreatedAt == 0 {
			identity.IdentityCreatedAt = time.Now().Unix()
			if err := save(path, identity); err != nil {
				return localIdentity{}, err
			}
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return localIdentity{}, fmt.Errorf("read connector identity: %w", err)
	}
	_, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return localIdentity{}, fmt.Errorf("create connector identity key: %w", err)
	}
	_, transportPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return localIdentity{}, fmt.Errorf("create connector transport key: %w", err)
	}
	identity := localIdentity{ProjectID: cfg.ProjectID, EnvironmentID: cfg.EnvironmentID, IdentityKeyPEM: encodePrivateKey(identityPrivate), IdentityCreatedAt: time.Now().Unix(), TransportKeyPEM: encodePrivateKey(transportPrivate)}
	if err := save(path, identity); err != nil {
		return localIdentity{}, err
	}
	return identity, nil
}

func register(ctx context.Context, cfg config.Connector, identity localIdentity) (localIdentity, error) {
	tlsConfig, err := transport.RegistrationClientTLS(cfg.Common)
	if err != nil {
		return localIdentity{}, fmt.Errorf("configure registration TLS: %w", err)
	}
	identityPEM := identity.IdentityKeyPEM
	if len(identity.PendingIdentityKeyPEM) > 0 {
		identityPEM = identity.PendingIdentityKeyPEM
	}
	identityPublic := publicKey(identityPEM)
	transportPublic := publicKey(identity.TransportKeyPEM)
	request := protocol.RegistrationRequest{
		RequestID: identity.RequestID, Kind: "enroll", ProjectID: cfg.ProjectID,
		EnvironmentID: cfg.EnvironmentID, EnvironmentName: cfg.EnvironmentName,
		DeploymentID: cfg.DeploymentID, ProjectAlias: cfg.ProjectAlias,
		EnvironmentAlias: cfg.EnvironmentAlias, IdentityKey: identityPublic,
		TransportKey: transportPublic,
	}
	if len(identity.PendingIdentityKeyPEM) > 0 {
		request.Kind = "rotate"
		request.Proof = Proof([]byte(cfg.EnrollmentNonce), request)
	} else if len(identity.CertificatePEM) > 0 {
		request.Kind = "renew"
		identityPrivate, err := privateKey(identity.IdentityKeyPEM)
		if err != nil {
			return localIdentity{}, err
		}
		request.Proof = ed25519.Sign(identityPrivate, RenewalMessage(request))
	} else {
		request.Proof = Proof([]byte(cfg.EnrollmentNonce), request)
	}
	delay := time.Second
	for ctx.Err() == nil {
		response, err := exchange(ctx, cfg.RegistrationEndpoint, tlsConfig, request)
		if err == nil {
			identity.RequestID = response.RequestID
			switch response.State {
			case "approved":
				if len(identity.PendingIdentityKeyPEM) > 0 {
					identity.IdentityKeyPEM = identity.PendingIdentityKeyPEM
					identity.PendingIdentityKeyPEM = nil
					identity.IdentityCreatedAt = time.Now().Unix()
				}
				identity.CertificatePEM = response.CertificatePEM
				identity.CertificateEnd = response.CertificateEnd
				identity.VirtualPrefix = response.VirtualPrefix
				identity.RealPrefix = response.RealPrefix
				identity.DNSSuffix = response.DNSSuffix
				identity.LeaseExpiresAt = response.LeaseExpiresAt
				if err := save(filepath.Join(cfg.IdentityDir, "registration.json"), identity); err != nil {
					return localIdentity{}, err
				}
				return identity, nil
			case "expired":
				identity.RequestID = ""
				request.RequestID = ""
				if err := save(filepath.Join(cfg.IdentityDir, "registration.json"), identity); err != nil {
					return localIdentity{}, err
				}
				continue
			case "rejected", "frozen":
				if response.ErrorCode == "rate_limited" || response.ErrorCode == "pending_limit" || response.ErrorCode == "internal_error" {
					break
				}
				identity.RequestID = ""
				if err := save(filepath.Join(cfg.IdentityDir, "registration.json"), identity); err != nil {
					return localIdentity{}, err
				}
				return localIdentity{}, fmt.Errorf("registration stopped with status %s: %s", response.State, response.ErrorCode)
			}
			request.RequestID = response.RequestID
			if err := save(filepath.Join(cfg.IdentityDir, "registration.json"), identity); err != nil {
				return localIdentity{}, err
			}
		}
		retryDelay := delay
		if responseRetry := time.Duration(response.RetryAfterMS) * time.Millisecond; responseRetry > retryDelay && responseRetry <= 30*time.Second {
			retryDelay = responseRetry
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return localIdentity{}, ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, 30*time.Second)
	}
	return localIdentity{}, ctx.Err()
}

func exchange(ctx context.Context, endpoint string, tlsConfig *tls.Config, request protocol.RegistrationRequest) (protocol.RegistrationResponse, error) {
	conn, err := quic.DialAddr(ctx, endpoint, tlsConfig, transport.QUICConfig(8))
	if err != nil {
		return protocol.RegistrationResponse{}, err
	}
	defer conn.CloseWithError(0, "registration exchange complete")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return protocol.RegistrationResponse{}, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return protocol.RegistrationResponse{}, err
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()
	if err := protocol.WriteFrame(stream, request); err != nil {
		return protocol.RegistrationResponse{}, err
	}
	var response protocol.RegistrationResponse
	if err := protocol.ReadFrame(stream, &response); err != nil {
		return protocol.RegistrationResponse{}, err
	}
	return response, nil
}

func Proof(nonce []byte, request protocol.RegistrationRequest) []byte {
	mac := hmac.New(sha256.New, nonce)
	mac.Write([]byte(request.ProjectID))
	mac.Write([]byte{0})
	mac.Write([]byte(request.EnvironmentID))
	mac.Write([]byte{0})
	mac.Write(request.IdentityKey)
	mac.Write([]byte{0})
	mac.Write(request.TransportKey)
	return mac.Sum(nil)
}

func RenewalMessage(request protocol.RegistrationRequest) []byte {
	digest := sha256.New()
	digest.Write([]byte("tailbridge-renewal-v1\x00"))
	digest.Write([]byte(request.ProjectID))
	digest.Write([]byte{0})
	digest.Write([]byte(request.EnvironmentID))
	digest.Write([]byte{0})
	digest.Write(request.IdentityKey)
	digest.Write([]byte{0})
	digest.Write(request.TransportKey)
	return digest.Sum(nil)
}

func encodePrivateKey(key ed25519.PrivateKey) []byte {
	raw, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
}

func privateKey(value []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, errors.New("stored connector key is not valid PEM")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := raw.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("stored connector key is not Ed25519")
	}
	return key, nil
}

func publicKey(value []byte) ed25519.PublicKey {
	key, err := privateKey(value)
	if err != nil {
		return nil
	}
	return key.Public().(ed25519.PublicKey)
}

func save(path string, value localIdentity) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, payload, 0o600); err != nil {
		return fmt.Errorf("write connector identity: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("commit connector identity: %w", err)
	}
	return nil
}
