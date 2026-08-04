package registry

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRegistrationLifecycle(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd40::/10"), []netip.Prefix{netip.MustParsePrefix("fd50::/16")}); err != nil {
		t.Fatal(err)
	}
	request := PendingRequest{ID: "request-one", Kind: "enroll", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "preview-1", ProjectAlias: "shop", EnvironmentAlias: "pr-1", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32), SourceAddress: "192.0.2.1"}
	pending, created, err := store.CreatePending(ctx, request)
	if err != nil || !created || pending.IdentityKeyID == "" {
		t.Fatalf("CreatePending() = %#v, %v, %v", pending, created, err)
	}
	if _, created, err := store.CreatePending(ctx, request); err != nil || created {
		t.Fatalf("idempotent CreatePending() created=%v err=%v", created, err)
	}
	conflict := request
	conflict.ID = "request-two"
	conflict.IdentityKey = append([]byte(nil), request.IdentityKey...)
	conflict.IdentityKey[0] = 1
	if _, _, err := store.CreatePending(ctx, conflict); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("conflicting CreatePending() error = %v", err)
	}
	approval := Approval{RequestID: request.ID, ProviderID: "github", JTI: "token-one", JTIExpiresAt: now.Add(time.Minute), LeaseClass: "preview", LeaseDuration: 24 * time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16"), CertificatePEM: []byte("certificate"), CertificateID: "certificate-one", CertificateEnd: now.Add(24 * time.Hour), AuditJSON: `{}`}
	registration, created, err := store.Approve(ctx, approval)
	if err != nil || !created || registration.VirtualPrefix != netip.MustParsePrefix("fd40::/16") {
		t.Fatalf("Approve() = %#v, %v, %v", registration, created, err)
	}
	if _, created, err := store.Approve(ctx, approval); err != nil || created {
		t.Fatalf("idempotent Approve() created=%v err=%v", created, err)
	}
	if credential, err := store.Credential(ctx, registration.ID); err != nil || credential.IdentityKeyID != pending.IdentityKeyID {
		t.Fatalf("Credential() = %#v, %v", credential, err)
	}
	if key, err := store.ActiveIdentityKey(ctx, registration.ID, pending.IdentityKeyID); err != nil || len(key) != 32 {
		t.Fatalf("ActiveIdentityKey() = %x, %v", key, err)
	}
	if byAlias, err := store.RegistrationByAlias(ctx, "shop", "pr-1"); err != nil || byAlias.ID != registration.ID {
		t.Fatalf("RegistrationByAlias() = %#v, %v", byAlias, err)
	}
	if known, err := store.ProjectKnown(ctx, "project"); err != nil || !known {
		t.Fatalf("ProjectKnown() = %v, %v", known, err)
	}
	if stats, err := store.Stats(ctx); err != nil || stats.Active != 1 || stats.Allocated != 1 || stats.Available != 62 {
		t.Fatalf("Stats() = %#v, %v", stats, err)
	}
	if err := store.ConsumeReplay(ctx, "github", "separate-token", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeReplay(ctx, "github", "separate-token", now.Add(time.Minute)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed ConsumeReplay() error = %v", err)
	}
	if err := store.MarkReady(ctx, "project", "environment"); err != nil {
		t.Fatal(err)
	}
	rotation := request
	rotation.ID = "rotation"
	rotation.Kind = "rotate"
	rotation.IdentityKey = make([]byte, 32)
	rotation.IdentityKey[0] = 2
	if _, _, err := store.CreatePending(ctx, rotation); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Approve(ctx, Approval{RequestID: rotation.ID, ProviderID: "github", JTI: "rotation-token", JTIExpiresAt: now.Add(time.Minute), LeaseClass: "preview", LeaseDuration: 24 * time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16")}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteIdentityRotation(ctx, registration.ID, Fingerprint(rotation.IdentityKey), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	renewed, err := store.Renew(ctx, mustRegistration(t, store), Fingerprint(rotation.IdentityKey), []byte("new certificate"), "certificate-two", now.Add(48*time.Hour), 24*time.Hour)
	if err != nil || !renewed.LeaseExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("Renew() = %#v, %v", renewed, err)
	}
	var activeCertificates int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates WHERE registration_id = ? AND state = 'active'`, registration.ID).Scan(&activeCertificates); err != nil || activeCertificates != 1 {
		t.Fatalf("active certificate count = %d, %v", activeCertificates, err)
	}
	if err := store.Revoke(ctx, "project", "environment", 24*time.Hour, `{}`); err != nil {
		t.Fatal(err)
	}
	if active, err := store.Active(ctx); err != nil || len(active) != 0 {
		t.Fatalf("Active() = %#v, %v", active, err)
	}
	generation, err := store.PendingRouteGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRouteGeneration(ctx, generation.ID, errors.New("retry")); err != nil {
		t.Fatal(err)
	}
	if retry, err := store.PendingRouteGeneration(ctx); err != nil || retry.LastError != "retry" {
		t.Fatalf("PendingRouteGeneration() = %#v, %v", retry, err)
	}
}

func TestLeaseExpiryWithdrawsRoute(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	request := PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "preview", EnvironmentName: "preview", ProjectAlias: "project", EnvironmentAlias: "preview", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32)}
	if _, _, err := store.CreatePending(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Approve(ctx, Approval{RequestID: request.ID, ProviderID: "provider", JTI: "jti", JTIExpiresAt: now.Add(time.Minute), LeaseClass: "preview", LeaseDuration: time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16")}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	expired, err := store.Expire(ctx, 24*time.Hour)
	if err != nil || len(expired) != 1 {
		t.Fatalf("Expire() = %#v, %v", expired, err)
	}
	if active, err := store.Active(ctx); err != nil || len(active) != 0 {
		t.Fatalf("Active() after expiry = %#v, %v", active, err)
	}
	if _, err := store.Pending(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Pending() missing error = %v", err)
	}
}

func TestConcurrentApprovalCommitsOnce(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	request := PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "production", ProjectAlias: "shop", EnvironmentAlias: "production", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32)}
	if _, _, err := store.CreatePending(ctx, request); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for index := range 2 {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, _, err := store.Approve(ctx, Approval{RequestID: request.ID, ProviderID: "provider", JTI: string(rune('a' + index)), JTIExpiresAt: time.Now().Add(time.Minute), LeaseClass: "persistent", LeaseDuration: time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16")})
			results <- err
		}(index)
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	active, err := store.Active(ctx)
	if err != nil || len(active) != 1 {
		t.Fatalf("Active() = %#v, %v", active, err)
	}
}

func TestConcurrentPendingRequestsKeepOneIdentity(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	requests := []PendingRequest{
		{ID: "one", ProjectID: "project", EnvironmentID: "environment", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32), SourceAddress: "192.0.2.1"},
		{ID: "two", ProjectID: "project", EnvironmentID: "environment", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32), SourceAddress: "192.0.2.2"},
	}
	requests[1].IdentityKey[0] = 1
	results := make(chan error, len(requests))
	var wait sync.WaitGroup
	for _, request := range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, err := store.CreatePending(context.Background(), request)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	var successful, conflicting int
	for err := range results {
		switch {
		case err == nil:
			successful++
		case errors.Is(err, ErrIdentityConflict):
			conflicting++
		default:
			t.Fatal(err)
		}
	}
	if successful != 1 || conflicting != 1 {
		t.Fatalf("concurrent pending results: successful=%d conflicting=%d", successful, conflicting)
	}
}

func TestStaticRegistrationMigration(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd20::/15"), nil); err != nil {
		t.Fatal(err)
	}
	static := StaticRegistration{ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "production", ConnectorID: "legacy", VirtualPrefix: netip.MustParsePrefix("fd20::/16"), RealPrefix: netip.MustParsePrefix("fd12::/16")}
	if err := store.ImportStatic(ctx, []StaticRegistration{static}); err != nil {
		t.Fatal(err)
	}
	other := PendingRequest{ID: "other", Kind: "enroll", ProjectID: "other-project", EnvironmentID: "other-environment", EnvironmentName: "preview", ProjectAlias: "other", EnvironmentAlias: "preview", IdentityKey: bytes.Repeat([]byte{1}, 32), TransportKey: bytes.Repeat([]byte{2}, 32), Proof: make([]byte, 32)}
	if _, _, err := store.CreatePending(ctx, other); err != nil {
		t.Fatal(err)
	}
	allocated, _, err := store.Approve(ctx, Approval{RequestID: other.ID, ProviderID: "provider", JTI: "other-jti", JTIExpiresAt: time.Now().Add(time.Minute), LeaseClass: "preview", LeaseDuration: 24 * time.Hour, RealPrefix: static.RealPrefix})
	if err != nil || allocated.VirtualPrefix != netip.MustParsePrefix("fd21::/16") {
		t.Fatalf("new allocation = %#v, err=%v", allocated, err)
	}
	request := PendingRequest{ID: "migration", Kind: "enroll", ProjectID: static.ProjectID, EnvironmentID: static.EnvironmentID, EnvironmentName: "production", ProjectAlias: "shop", EnvironmentAlias: "production", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32)}
	if _, _, err := store.CreatePending(ctx, request); err != nil {
		t.Fatal(err)
	}
	registration, created, err := store.Approve(ctx, Approval{RequestID: request.ID, ProviderID: "provider", JTI: "migration-jti", JTIExpiresAt: time.Now().Add(time.Minute), LeaseClass: "persistent", LeaseDuration: 30 * 24 * time.Hour, RealPrefix: static.RealPrefix})
	if err != nil || created || registration.IdentityType != "dynamic-v3" || registration.VirtualPrefix != static.VirtualPrefix {
		t.Fatalf("migrated registration = %#v, created=%v, err=%v", registration, created, err)
	}
}

func mustRegistration(t *testing.T, store *Store) Registration {
	t.Helper()
	registration, err := store.Registration(context.Background(), "project", "environment")
	if err != nil {
		t.Fatal(err)
	}
	return registration
}
