//go:build linux

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/approval"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/edge"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/enrollment"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/logging"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/observability"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/pki"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/registry"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
	"golang.org/x/sync/errgroup"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx))
}

func run(ctx context.Context) int {
	defer observability.Recover()
	cfg, err := config.LoadEdge()
	if err != nil {
		slog.Error("Tailbridge configuration is not valid.", "error", err)
		return 2
	}
	logger := logging.New(cfg.LogLevel)
	shutdown, err := observability.Setup(context.Background(), "tailbridge-edge", version, logger)
	if err != nil {
		logger.Error("Tailbridge could not configure observability.", "error", err)
		return 2
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(shutdownContext); err != nil {
			logger.Error("Tailbridge could not stop observability.", "error", err)
		}
	}()
	var certificateManager *pki.EdgeManager
	if cfg.RegistrationMode != "static" {
		certificateManager, err = pki.NewEdgeManager(cfg.EdgeID, cfg.IntermediateCertificate, cfg.IntermediatePrivateKey)
		if err != nil {
			logger.Error("Tailbridge could not configure edge certificate rotation.", "error", err)
			return 2
		}
		cfg.GetCertificate = certificateManager.GetCertificate
	}
	state := status.New(version)
	admin, err := state.Listen(cfg.AdminAddr)
	if err != nil {
		logger.Error("Tailbridge could not bind the administration listener.", "error", err)
		return 2
	}
	group, groupContext := errgroup.WithContext(ctx)
	if certificateManager != nil {
		group.Go(func() error { return certificateManager.Run(groupContext, logger) })
	}
	group.Go(func() error { return admin.Serve(groupContext) })
	edgeServer := edge.New(cfg, logger, state)
	if cfg.RegistrationMode != "static" {
		store, err := registry.Open(cfg.RegistryPath)
		if err != nil {
			logger.Error("Tailbridge could not open the connector registry.", "error", err)
			return 2
		}
		defer store.Close()
		if err := store.InitializePool(ctx, cfg.VirtualNetwork, cfg.ExcludedPrefixes); err != nil {
			logger.Error("Tailbridge could not initialize the virtual address pool.", "error", err)
			return 2
		}
		if cfg.RegistrationMode == "migration" {
			imports := make([]registry.StaticRegistration, 0, len(cfg.Connectors))
			for _, connector := range cfg.Connectors {
				if connector.ProjectID == "" {
					continue
				}
				imports = append(imports, registry.StaticRegistration{ProjectID: connector.ProjectID, EnvironmentID: connector.Environment, EnvironmentName: connector.Environment, ConnectorID: connector.ConnectorID, VirtualPrefix: connector.VirtualPrefix, RealPrefix: connector.RealPrefix})
			}
			if err := store.ImportStatic(ctx, imports); err != nil {
				logger.Error("Tailbridge could not import static registrations.", "error", err)
				return 2
			}
		}
		edgeServer, err = edge.NewWithStore(ctx, cfg, store, logger, state)
		if err != nil {
			logger.Error("Tailbridge could not load dynamic registrations.", "error", err)
			return 2
		}
		approvalServer, err := approval.NewServer(cfg, store, logger, state)
		if err != nil {
			logger.Error("Tailbridge could not configure the approval service.", "error", err)
			return 2
		}
		registrationServer, err := enrollment.NewServer(cfg, store, logger, state)
		if err != nil {
			logger.Error("Tailbridge could not configure the registration service.", "error", err)
			return 2
		}
		group.Go(func() error { return registrationServer.Run(groupContext) })
		group.Go(func() error { return approvalServer.Run(groupContext) })
	}
	group.Go(func() error { return edgeServer.Run(groupContext) })
	if err := group.Wait(); err != nil && ctx.Err() == nil {
		observability.Capture(err)
		logger.Error("edge stopped", "error", err)
		return 1
	}
	return 0
}
