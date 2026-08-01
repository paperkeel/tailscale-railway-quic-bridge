package logging

import (
	"context"
	"log/slog"
	"testing"
)

func TestNewUsesConfiguredLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		disabled slog.Level
		enabled  slog.Level
	}{
		{name: "debug", level: "debug", disabled: slog.LevelDebug - 1, enabled: slog.LevelDebug},
		{name: "info", level: "info", disabled: slog.LevelDebug, enabled: slog.LevelInfo},
		{name: "warn", level: "warn", disabled: slog.LevelInfo, enabled: slog.LevelWarn},
		{name: "error", level: "error", disabled: slog.LevelWarn, enabled: slog.LevelError},
		{name: "invalid defaults to info", level: "loud", disabled: slog.LevelDebug, enabled: slog.LevelInfo},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := New(test.level)
			if logger.Enabled(context.Background(), test.disabled) {
				t.Errorf("level %s is enabled", test.disabled)
			}
			if !logger.Enabled(context.Background(), test.enabled) {
				t.Errorf("level %s is disabled", test.enabled)
			}
		})
	}
}
