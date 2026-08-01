package observability

import (
	"context"
	"log/slog"
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
	shutdown := func(context.Context) error { return nil }
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, err
		}
		rate := floatValue("OTEL_TRACES_SAMPLER_ARG", 0.01)
		provider := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(rate))),
			sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", service), attribute.String("service.version", version))),
		)
		otel.SetTracerProvider(provider)
		shutdown = provider.Shutdown
		logger.Info("OpenTelemetry enabled", "service", service)
	}
	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{Dsn: dsn, Environment: os.Getenv("SENTRY_ENVIRONMENT"), Release: value("SENTRY_RELEASE", version), EnableTracing: true, TracesSampleRate: floatValue("SENTRY_TRACES_SAMPLE_RATE", 0.01)}); err != nil {
			return nil, err
		}
		previous := shutdown
		shutdown = func(ctx context.Context) error {
			sentry.Flush(2 * time.Second)
			return previous(ctx)
		}
		logger.Info("Sentry enabled", "service", service)
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

func floatValue(name string, fallback float64) float64 {
	value, err := strconv.ParseFloat(os.Getenv(name), 64)
	if err != nil || value < 0 || value > 1 {
		return fallback
	}
	return value
}

func value(name, fallback string) string {
	if result := os.Getenv(name); result != "" {
		return result
	}
	return fallback
}
