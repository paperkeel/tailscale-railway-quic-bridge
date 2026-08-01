package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeProtectsExistingSecrets(t *testing.T) {
	directory := t.TempDir()
	arguments := []string{"--output", directory, "--connector-id", "test-pair", "--environment", "test", "--edge-endpoint", "127.0.0.1:4433"}
	if err := initialize(arguments); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"edge.env", "connector.env", "tailscale-policy.hujson"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected %s to use mode 0600, got %o", name, info.Mode().Perm())
		}
	}
	if err := initialize(arguments); err == nil {
		t.Fatal("expected initialization to protect existing files")
	}
}
