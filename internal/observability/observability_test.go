package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestSampleRate(t *testing.T) {
	const name = "TEST_SAMPLE_RATE"
	tests := []struct {
		name    string
		value   string
		want    float64
		wantErr bool
	}{
		{name: "default", want: 0.25},
		{name: "zero", value: "0", want: 0},
		{name: "one", value: "1", want: 1},
		{name: "fraction", value: "0.5", want: 0.5},
		{name: "negative", value: "-0.1", wantErr: true},
		{name: "too large", value: "1.1", wantErr: true},
		{name: "not a number", value: "NaN", wantErr: true},
		{name: "text", value: "often", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(name, test.value)
			got, err := sampleRate(name, 0.25)
			if (err != nil) != test.wantErr {
				t.Fatalf("sampleRate() error = %v, wantErr %t", err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("sampleRate() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSetupIgnoresSampleRatesForDisabledExporters(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "invalid")
	t.Setenv("SENTRY_DSN", "")
	t.Setenv("SENTRY_TRACES_SAMPLE_RATE", "invalid")

	shutdown, err := Setup(context.Background(), "test", "dev", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSetupValidatesEnabledExporterSampleRate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name      string
		enableKey string
		enable    string
		rateKey   string
	}{
		{name: "OpenTelemetry", enableKey: "OTEL_EXPORTER_OTLP_ENDPOINT", enable: "http://localhost:4318", rateKey: "OTEL_TRACES_SAMPLER_ARG"},
		{name: "Sentry", enableKey: "SENTRY_DSN", enable: "https://public@example.com/1", rateKey: "SENTRY_TRACES_SAMPLE_RATE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("SENTRY_DSN", "")
			t.Setenv(test.enableKey, test.enable)
			t.Setenv(test.rateKey, "invalid")

			shutdown, err := Setup(context.Background(), "test", "dev", logger)
			if shutdown != nil {
				t.Fatal("Setup returned a shutdown function with an invalid sample rate")
			}
			if err == nil || !strings.Contains(err.Error(), test.rateKey) {
				t.Fatalf("Setup error = %v, want an error for %s", err, test.rateKey)
			}
		})
	}
}
