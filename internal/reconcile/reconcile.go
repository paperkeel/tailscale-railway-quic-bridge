package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/registry"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
)

type Policy interface {
	Replace(context.Context, []netip.Prefix) error
}

type Routes struct {
	store        *registry.Store
	policy       Policy
	interval     time.Duration
	quarantine   time.Duration
	staticRoutes []netip.Prefix
	logger       *slog.Logger
	run          func(context.Context, string, ...string) ([]byte, error)
	status       *status.Server
}

func NewRoutes(store *registry.Store, policy Policy, staticRoutes []netip.Prefix, interval, quarantine time.Duration, logger *slog.Logger, metrics ...*status.Server) *Routes {
	routes := &Routes{store: store, policy: policy, staticRoutes: append([]netip.Prefix(nil), staticRoutes...), interval: interval, quarantine: quarantine, logger: logger, run: runCommand}
	if len(metrics) > 0 {
		routes.status = metrics[0]
	}
	return routes
}

func (r *Routes) Run(ctx context.Context) error {
	if err := r.reconcile(ctx); err != nil {
		r.logger.Error("route reconciliation failed", "event.name", "route.reconciled", "outcome", "failure", "error", err)
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := r.store.Expire(ctx, r.quarantine); err != nil {
				r.logger.Error("lease expiry failed", "event.name", "lease.expired", "error", err)
			}
			if err := r.reconcile(ctx); err != nil {
				r.logger.Error("route reconciliation failed", "event.name", "route.reconciled", "outcome", "failure", "error", err)
			}
		}
	}
}

func (r *Routes) reconcile(ctx context.Context) (resultErr error) {
	started := time.Now()
	defer func() {
		if r.status != nil {
			result := "success"
			if resultErr != nil {
				result = "failure"
			}
			r.status.ObserveRouteReconcile(result, time.Since(started))
		}
	}()
	generation, generationErr := r.store.PendingRouteGeneration(ctx)
	active, err := r.store.Active(ctx)
	if err != nil {
		return err
	}
	routes := append([]netip.Prefix(nil), r.staticRoutes...)
	for _, registration := range active {
		routes = append(routes, registration.VirtualPrefix)
	}
	slices.SortFunc(routes, func(left, right netip.Prefix) int { return left.Addr().Compare(right.Addr()) })
	routes = slices.Compact(routes)
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, route.String())
	}
	previousPayload, err := r.run(ctx, "/usr/local/bin/tailscale", "debug", "prefs")
	if err != nil {
		return fmt.Errorf("read current Tailscale routes: %w", err)
	}
	var previous struct {
		AdvertiseRoutes []string `json:"AdvertiseRoutes"`
	}
	if err := json.Unmarshal(previousPayload, &previous); err != nil {
		return fmt.Errorf("parse current Tailscale routes: %w", err)
	}
	slices.Sort(previous.AdvertiseRoutes)
	setRoutes := func(want []string) error {
		_, err := r.run(ctx, "/usr/local/bin/tailscale", "set", "--advertise-routes="+strings.Join(want, ","))
		return err
	}
	removesRoute := false
	for _, route := range previous.AdvertiseRoutes {
		if !slices.Contains(values, route) {
			removesRoute = true
			break
		}
	}
	if removesRoute {
		err = setRoutes(values)
		if err == nil {
			err = r.policy.Replace(ctx, routes)
			if err != nil {
				_ = setRoutes(previous.AdvertiseRoutes)
			}
		}
	} else {
		err = r.policy.Replace(ctx, routes)
		if err == nil {
			err = setRoutes(values)
			if err != nil {
				previousPrefixes := make([]netip.Prefix, 0, len(previous.AdvertiseRoutes))
				for _, raw := range previous.AdvertiseRoutes {
					if prefix, parseErr := netip.ParsePrefix(raw); parseErr == nil {
						previousPrefixes = append(previousPrefixes, prefix)
					}
				}
				_ = r.policy.Replace(ctx, previousPrefixes)
			}
		}
	}
	if err != nil {
		if generationErr == nil {
			_ = r.store.CompleteRouteGeneration(ctx, generation.ID, err)
		}
		return fmt.Errorf("apply route generation: %w", err)
	}
	payload, err := r.run(ctx, "/usr/local/bin/tailscale", "debug", "prefs")
	if err == nil {
		var preferences struct {
			AdvertiseRoutes []string `json:"AdvertiseRoutes"`
		}
		err = json.Unmarshal(payload, &preferences)
		slices.Sort(preferences.AdvertiseRoutes)
		if err == nil && !slices.Equal(preferences.AdvertiseRoutes, values) {
			err = errors.New("Tailscale did not report the expected advertised routes")
		}
	}
	if err != nil {
		if generationErr == nil {
			_ = r.store.CompleteRouteGeneration(ctx, generation.ID, err)
		}
		return fmt.Errorf("verify Tailscale routes: %w", err)
	}
	if generationErr == nil {
		if err := r.store.CompleteRouteGeneration(ctx, generation.ID, nil); err != nil {
			return err
		}
	} else if !errors.Is(generationErr, registry.ErrNotFound) {
		return generationErr
	}
	r.logger.Info("routes reconciled", "event.name", "route.reconciled", "outcome", "success", "route_count", len(routes))
	return nil
}

func runCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
