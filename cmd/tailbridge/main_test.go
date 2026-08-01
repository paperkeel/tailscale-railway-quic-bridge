package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunExitCodes(t *testing.T) {
	if code := run([]string{"tailbridge"}); code != 2 {
		t.Fatalf("run() = %d, want 2 for missing command", code)
	}
	if code := run([]string{"tailbridge", "unknown"}); code != 2 {
		t.Fatalf("run() = %d, want 2 for an unknown command", code)
	}
	if code := run([]string{"tailbridge", "version"}); code != 0 {
		t.Fatalf("run() = %d, want 0 for version", code)
	}
	if code := run([]string{"tailbridge", "version", "extra"}); code != 2 {
		t.Fatalf("run() = %d, want 2 for unexpected version arguments", code)
	}
	if code := run([]string{"tailbridge", "init", "--help"}); code != 0 {
		t.Fatalf("run() = %d, want 0 for init help", code)
	}
	if code := run([]string{"tailbridge", "init", "--unknown"}); code != 2 {
		t.Fatalf("run() = %d, want 2 for invalid init flags", code)
	}
	if code := run([]string{"tailbridge", "init", "extra"}); code != 2 {
		t.Fatalf("run() = %d, want 2 for unexpected init arguments", code)
	}
}

func TestInitializeRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "connector newline", arguments: []string{"--connector-id", "safe\nTB_ENVIRONMENT=injected"}},
		{name: "environment space", arguments: []string{"--environment", "not safe"}},
		{name: "connector too long", arguments: []string{"--connector-id", strings.Repeat("a", 64)}},
		{name: "endpoint newline", arguments: []string{"--edge-endpoint", "edge.example.com:4433\nINJECTED=true"}},
		{name: "positional argument", arguments: []string{"unexpected"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "output")
			arguments := append([]string{"--output", directory}, test.arguments...)
			if err := initialize(arguments); err == nil {
				t.Fatal("expected initialization to reject unsafe input")
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatalf("expected no output directory, got %v", err)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		valid    bool
	}{
		{endpoint: "edge.example.com:4433", valid: true},
		{endpoint: "127.0.0.1:1", valid: true},
		{endpoint: "[2001:db8::1]:65535", valid: true},
		{endpoint: "edge.example.com", valid: false},
		{endpoint: ":4433", valid: false},
		{endpoint: "2001:db8::1:4433", valid: false},
		{endpoint: "edge.example.com:0", valid: false},
		{endpoint: "edge.example.com:65536", valid: false},
		{endpoint: "edge.example.com:https", valid: false},
		{endpoint: "edge example.com:4433", valid: false},
		{endpoint: "edge.example.com:4433\x00", valid: false},
	}
	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			err := validateEndpoint(test.endpoint)
			if test.valid && err != nil {
				t.Fatalf("expected a valid endpoint: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("expected an invalid endpoint")
			}
		})
	}
}

func TestGeneratedCertificatesUseRoleSpecificEKUs(t *testing.T) {
	ca, caKey, err := certificateAuthority("test-pair")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		role  string
		usage x509.ExtKeyUsage
	}{
		{role: "edge", usage: x509.ExtKeyUsageServerAuth},
		{role: "connector", usage: x509.ExtKeyUsageClientAuth},
	}
	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			raw, _, err := leaf(ca, caKey, test.role, "test-pair", test.usage)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := x509.ParseCertificate(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(certificate.ExtKeyUsage, []x509.ExtKeyUsage{test.usage}) {
				t.Fatalf("expected only EKU %v, got %v", test.usage, certificate.ExtKeyUsage)
			}
			wantIdentity := "spiffe://tailbridge.local/" + test.role + "/test-pair"
			if len(certificate.URIs) != 1 || certificate.URIs[0].String() != wantIdentity {
				t.Fatalf("expected identity %q, got %v", wantIdentity, certificate.URIs)
			}
		})
	}
}

func TestCertificateRandomnessErrorsPropagate(t *testing.T) {
	original := cryptographicRandom
	cryptographicRandom = errorReader{}
	t.Cleanup(func() { cryptographicRandom = original })

	if _, _, err := certificateAuthority("test-pair"); !errors.Is(err, errRandomness) {
		t.Fatalf("expected the randomness error, got %v", err)
	}
	if _, err := serial(); !errors.Is(err, errRandomness) {
		t.Fatalf("expected the serial randomness error, got %v", err)
	}
}

func TestInitializeCreatesSecretFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "output")
	if err := initialize(testArguments(directory)); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("output directory mode = %o, want 0700", directoryInfo.Mode().Perm())
	}
	for _, name := range generatedFileNames() {
		path := filepath.Join(directory, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected %s to use mode 0600, got %o", name, info.Mode().Perm())
		}
	}

	edge := readEnvironment(t, filepath.Join(directory, "edge.env"))
	connector := readEnvironment(t, filepath.Join(directory, "connector.env"))
	if edge["TB_CONNECTOR_ID"] != "test-pair" || connector["TB_CONNECTOR_ID"] != "test-pair" {
		t.Fatal("expected both files to contain the connector ID")
	}
	if connector["TB_EDGE_ENDPOINT"] != "127.0.0.1:4433" {
		t.Fatalf("unexpected edge endpoint %q", connector["TB_EDGE_ENDPOINT"])
	}
	assertCertificateEKU(t, edge["TB_MTLS_CERT_B64"], x509.ExtKeyUsageServerAuth)
	assertCertificateEKU(t, connector["TB_MTLS_CERT_B64"], x509.ExtKeyUsageClientAuth)
}

func TestInitializePreservesExistingDirectoryMode(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := initialize(testArguments(directory)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("existing output directory mode = %o, want 0755", info.Mode().Perm())
	}
}

func TestInitializeProtectsAllExistingFiles(t *testing.T) {
	directory := t.TempDir()
	if err := initialize(testArguments(directory)); err != nil {
		t.Fatal(err)
	}
	original := readGeneratedFiles(t, directory)
	if err := os.WriteFile(filepath.Join(directory, "connector.env"), []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	original["connector.env"] = []byte("keep-me")

	if err := initialize(testArguments(directory)); err == nil {
		t.Fatal("initialize() replaced an existing file.")
	}
	assertGeneratedFiles(t, directory, original)
}

func TestInitializeForceReplacesAllFiles(t *testing.T) {
	directory := t.TempDir()
	for _, name := range generatedFileNames() {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("old-"+name), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	arguments := append(testArguments(directory), "--force")
	if err := initialize(arguments); err != nil {
		t.Fatal(err)
	}
	for _, name := range generatedFileNames() {
		path := filepath.Join(directory, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(content, []byte("old-"+name)) {
			t.Fatalf("expected %s to be replaced", name)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected %s to use mode 0600, got %o", name, info.Mode().Perm())
		}
	}
	assertNoWorkFiles(t, directory)
}

func TestInitializeRollsBackWithoutForce(t *testing.T) {
	directory := t.TempDir()
	originalLink := linkFile
	links := 0
	linkFile = func(oldPath, newPath string) error {
		links++
		if links == 2 {
			return errors.New("injected link failure")
		}
		return os.Link(oldPath, newPath)
	}
	t.Cleanup(func() { linkFile = originalLink })

	if err := initialize(testArguments(directory)); err == nil {
		t.Fatal("expected initialization to fail")
	}
	for _, name := range generatedFileNames() {
		if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be absent, got %v", name, err)
		}
	}
	assertNoWorkFiles(t, directory)
}

func TestInitializeForceRestoresAllFilesAfterFailure(t *testing.T) {
	directory := t.TempDir()
	original := make(map[string][]byte)
	for _, name := range generatedFileNames() {
		original[name] = []byte("old-" + name)
		if err := os.WriteFile(filepath.Join(directory, name), original[name], 0o600); err != nil {
			t.Fatal(err)
		}
	}

	originalRename := renameFile
	renames := 0
	renameFile = func(oldPath, newPath string) error {
		renames++
		if renames == 5 {
			return errors.New("injected rename failure")
		}
		return os.Rename(oldPath, newPath)
	}
	t.Cleanup(func() { renameFile = originalRename })

	arguments := append(testArguments(directory), "--force")
	if err := initialize(arguments); err == nil {
		t.Fatal("expected initialization to fail")
	}
	assertGeneratedFiles(t, directory, original)
	assertNoWorkFiles(t, directory)
}

func TestCleanupTempsReportsRemovalFailure(t *testing.T) {
	originalRemove := removeFile
	removeErr := errors.New("injected remove failure")
	removeFile = func(string) error { return removeErr }
	t.Cleanup(func() { removeFile = originalRemove })

	err := cleanupTemps([]secretFile{{path: "edge.env", temp: ".edge.env.tmp-test"}})
	if !errors.Is(err, removeErr) {
		t.Fatalf("cleanupTemps() error = %v, want the removal error", err)
	}
}

var errRandomness = errors.New("randomness failed")

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errRandomness }

func testArguments(directory string) []string {
	return []string{"--output", directory, "--connector-id", "test-pair", "--environment", "test", "--edge-endpoint", "127.0.0.1:4433"}
}

func generatedFileNames() []string {
	return []string{"edge.env", "connector.env", "tailscale-policy.hujson"}
}

func readGeneratedFiles(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	for _, name := range generatedFileNames() {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = content
	}
	return files
}

func assertGeneratedFiles(t *testing.T, directory string, want map[string][]byte) {
	t.Helper()
	for name, expected := range want {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(content, expected) {
			t.Fatalf("expected %s to keep its original content", name)
		}
	}
}

func assertNoWorkFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") || strings.Contains(entry.Name(), ".backup-") {
			t.Fatalf("found stale work file %s", entry.Name())
		}
	}
}

func readEnvironment(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, found := strings.Cut(line, "=")
		if found {
			values[name] = value
		}
	}
	return values
}

func assertCertificateEKU(t *testing.T, encoded string, usage x509.ExtKeyUsage) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("expected a PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(certificate.ExtKeyUsage, []x509.ExtKeyUsage{usage}) {
		t.Fatalf("expected only EKU %v, got %v", usage, certificate.ExtKeyUsage)
	}
}
