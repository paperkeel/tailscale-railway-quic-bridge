package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/getsentry/sentry-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type Shutdown func(context.Context) error

func Setup(ctx context.Context, service, version string, logger *slog.Logger) (Shutdown, error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	otelEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	otelRate := 0.01
	if otelEndpoint != "" {
		var err error
		otelRate, err = sampleRate("OTEL_TRACES_SAMPLER_ARG", otelRate)
		if err != nil {
			return nil, err
		}
	}
	sentryDSN := os.Getenv("SENTRY_DSN")
	sentryRate := 0.01
	if sentryDSN != "" {
		var err error
		sentryRate, err = sampleRate("SENTRY_TRACES_SAMPLE_RATE", sentryRate)
		if err != nil {
			return nil, err
		}
	}

	shutdown := func(context.Context) error { return nil }
	if otelEndpoint != "" {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, err
		}
		provider := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(otelRate))),
			sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", service), attribute.String("service.version", version))),
		)
		otel.SetTracerProvider(provider)
		shutdown = provider.Shutdown
		logger.Info("Tailbridge enabled OpenTelemetry.", "service", service)
	}
	if sentryDSN != "" {
		if err := sentry.Init(sentry.ClientOptions{Dsn: sentryDSN, Environment: os.Getenv("SENTRY_ENVIRONMENT"), Release: value("SENTRY_RELEASE", version), EnableTracing: true, TracesSampleRate: sentryRate}); err != nil {
			shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdown(shutdownContext)
			return nil, err
		}
		previous := shutdown
		shutdown = func(ctx context.Context) error {
			var flushErr error
			if !sentry.Flush(2 * time.Second) {
				flushErr = errors.New("Sentry did not flush before the timeout")
			}
			return errors.Join(flushErr, previous(ctx))
		}
		logger.Info("Tailbridge enabled Sentry.", "service", service)
	}
	return shutdown, nil
}

func Capture(err error) {
	if err != nil && os.Getenv("SENTRY_DSN") != "" {
		sentry.CaptureException(err)
	}
}

func Recover() {
	if recovered := recover(); recovered != nil {
		sentry.CurrentHub().Recover(recovered)
		sentry.Flush(2 * time.Second)
		panic(recovered)
	}
}

func sampleRate(name string, fallback float64) (float64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(value) || value < 0 || value > 1 {
		return 0, fmt.Errorf("%s must be a number from 0 through 1", name)
	}
	return value, nil
}

func value(name, fallback string) string {
	if result := os.Getenv(name); result != "" {
		return result
	}
	return fallback
}
