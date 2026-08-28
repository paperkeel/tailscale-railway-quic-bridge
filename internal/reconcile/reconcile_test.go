package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/registry"
)

type fakePolicy struct {
	routes  []netip.Prefix
	history [][]netip.Prefix
	err     error
}

func (p *fakePolicy) Replace(_ context.Context, routes []netip.Prefix) error {
	p.routes = append([]netip.Prefix(nil), routes...)
	p.history = append(p.history, p.routes)
	return p.err
}

func TestRouteReconciliationAppliesCompleteGeneration(t *testing.T) {
	ctx := context.Background()
	store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitializePool(ctx, netip.MustParsePrefix("fd40::/16"), nil); err != nil {
		t.Fatal(err)
	}
	request := registry.PendingRequest{ID: "request", ProjectID: "project", EnvironmentID: "environment", EnvironmentName: "production", ProjectAlias: "project", EnvironmentAlias: "production", IdentityKey: make([]byte, 32), TransportKey: make([]byte, 32), Proof: make([]byte, 32)}
	if _, _, err := store.CreatePending(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Approve(ctx, registry.Approval{RequestID: request.ID, ProviderID: "provider", JTI: "jti", JTIExpiresAt: time.Now().Add(time.Minute), LeaseClass: "persistent", LeaseDuration: time.Hour, RealPrefix: netip.MustParsePrefix("fd12::/16")}); err != nil {
		t.Fatal(err)
	}
	policy := new(fakePolicy)
	reconciler := NewRoutes(store, policy, nil, time.Minute, 24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reconciler.run = func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		if slices.Contains(arguments, "prefs") {
			return json.Marshal(map[string]any{"AdvertiseRoutes": []string{"fd40::/16"}})
		}
		return nil, nil
	}
	if err := reconciler.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policy.routes, []netip.Prefix{netip.MustParsePrefix("fd40::/16")}) {
		t.Fatalf("policy routes = %v", policy.routes)
	}
	reconciler.interval = time.Millisecond
	runContext, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	if err := reconciler.Run(runContext); err != nil {
		t.Fatal(err)
	}
}

func TestRouteReconciliationFailurePaths(t *testing.T) {
	newReconciler := func(t *testing.T) (*Routes, *fakePolicy) {
		t.Helper()
		store, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		policy := new(fakePolicy)
		return NewRoutes(store, policy, []netip.Prefix{netip.MustParsePrefix("fd40::/16")}, time.Minute, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil))), policy
	}
	t.Run("read preferences", func(t *testing.T) {
		reconciler, _ := newReconciler(t)
		reconciler.run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unavailable") }
		if err := reconciler.reconcile(context.Background()); err == nil {
			t.Fatal("reconcile() accepted a preferences read failure")
		}
	})
	t.Run("parse preferences", func(t *testing.T) {
		reconciler, _ := newReconciler(t)
		reconciler.run = func(context.Context, string, ...string) ([]byte, error) { return []byte("invalid"), nil }
		if err := reconciler.reconcile(context.Background()); err == nil {
			t.Fatal("reconcile() accepted invalid preferences")
		}
	})
	t.Run("rollback policy after set", func(t *testing.T) {
		reconciler, policy := newReconciler(t)
		calls := 0
		reconciler.run = func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
			if slices.Contains(arguments, "prefs") {
				calls++
				if calls == 1 {
					return json.Marshal(map[string]any{"AdvertiseRoutes": []string{"fd30::/16"}})
				}
			}
			return json.Marshal(map[string]any{"AdvertiseRoutes": []string{"fd40::/16"}})
		}
		policy.err = errors.New("nft failed")
		if err := reconciler.reconcile(context.Background()); err == nil {
			t.Fatal("reconcile() accepted a policy failure")
		}
	})
	t.Run("rollback policy after tailscale", func(t *testing.T) {
		reconciler, policy := newReconciler(t)
		reconciler.run = func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
			if slices.Contains(arguments, "set") {
				return nil, errors.New("tailscale failed")
			}
			return json.Marshal(map[string]any{"AdvertiseRoutes": []string{}})
		}
		if err := reconciler.reconcile(context.Background()); err == nil || len(policy.history) != 2 {
			t.Fatalf("reconcile() error=%v policy history=%v", err, policy.history)
		}
	})
	t.Run("verify drift", func(t *testing.T) {
		reconciler, _ := newReconciler(t)
		reconciler.run = func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
			return json.Marshal(map[string]any{"AdvertiseRoutes": []string{}})
		}
		if err := reconciler.reconcile(context.Background()); err == nil {
			t.Fatal("reconcile() accepted route drift")
		}
	})
}
