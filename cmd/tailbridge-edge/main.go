//go:build linux

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/edge"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/logging"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/observability"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
)

var version = "dev"

func main() {
	defer observability.Recover()
	cfg, err := config.LoadEdge()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	logger := logging.New(cfg.LogLevel)
	shutdown, err := observability.Setup(context.Background(), "tailbridge-edge", version, logger)
	if err != nil {
		logger.Error("observability setup failed", "error", err)
		os.Exit(2)
	}
	defer func() { _ = shutdown(context.Background()) }()
	state := status.New(version)
	go func() {
		if err := state.Listen(cfg.AdminAddr); err != nil {
			logger.Error("admin server stopped", "error", err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := edge.New(cfg, logger, state).Run(ctx); err != nil {
		observability.Capture(err)
		logger.Error("edge stopped", "error", err)
		os.Exit(1)
	}
}
