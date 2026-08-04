package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/connector"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/enrollment"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/logging"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/observability"
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
	cfg, err := config.LoadConnector()
	if err != nil {
		slog.Error("Tailbridge configuration is not valid.", "error", err)
		return 2
	}
	logger := logging.New(cfg.LogLevel)
	if cfg.RegistrationMode == "dynamic" {
		cfg, err = enrollment.Ensure(ctx, cfg)
		if err != nil {
			logger.Error("The connector could not complete registration.", "error", err)
			return 1
		}
	}
	shutdown, err := observability.Setup(context.Background(), "tailbridge-connector", version, logger)
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
	state := status.New(version)
	admin, err := state.Listen(cfg.AdminAddr)
	if err != nil {
		logger.Error("Tailbridge could not bind the administration listener.", "error", err)
		return 2
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error { return admin.Serve(groupContext) })
	group.Go(func() error {
		err := connector.New(cfg, logger, state, version).Run(groupContext)
		if groupContext.Err() != nil {
			return nil
		}
		return err
	})
	if err := group.Wait(); err != nil && ctx.Err() == nil {
		observability.Capture(err)
		logger.Error("connector stopped", "error", err)
		return 1
	}
	return 0
}
