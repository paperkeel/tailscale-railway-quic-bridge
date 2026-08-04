package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var version = "dev"

var (
	cryptographicRandom = io.Reader(rand.Reader)
	createTempFile      = os.CreateTemp
	linkFile            = os.Link
	renameFile          = os.Rename
	removeFile          = os.Remove
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

var errCommandLine = errors.New("The command line is not valid.")

func main() {
	os.Exit(run(os.Args))
}

func run(arguments []string) int {
	if len(arguments) < 2 {
		usage()
		return 2
	}
	switch arguments[1] {
	case "init":
		if err := initialize(arguments[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			if errors.Is(err, errCommandLine) {
				return 2
			}
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "version":
		if len(arguments) != 2 {
			usage()
			return 2
		}
		fmt.Println(version)
	default:
		usage()
		return 2
	}
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tailbridge <init|version>")
}

func initialize(arguments []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	output := flags.String("output", ".", "write the generated environment files to this directory")
	connectorID := flags.String("connector-id", "railway-production", "use this stable connector identity")
	environment := flags.String("environment", "production", "use this Railway environment name")
	edgeEndpoint := flags.String("edge-endpoint", "edge.example.com:4433", "connect to this public edge QUIC endpoint")
	force := flags.Bool("force", false, "replace existing generated files")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return flag.ErrHelp
		}
		return errCommandLine
	}
	if flags.NArg() != 0 {
		return errors.Join(errCommandLine, fmt.Errorf("The init command does not accept argument %q.", flags.Arg(0)))
	}
	if err := validateName("connector ID", *connectorID); err != nil {
		return err
	}
	if err := validateName("environment", *environment); err != nil {
		return err
	}
	if err := validateEndpoint(*edgeEndpoint); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("output directory must not be empty")
	}

	caCert, caKey, err := certificateAuthority(*connectorID)
	if err != nil {
		return err
	}
	edgeCert, edgeKey, err := leaf(caCert, caKey, "edge", *connectorID, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return err
	}
	connectorCert, connectorKey, err := leaf(caCert, caKey, "connector", *connectorID, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(*output)
	createdDirectory := os.IsNotExist(statErr)
	if statErr != nil && !createdDirectory {
		return fmt.Errorf("inspect output directory: %w", statErr)
	}
	if err := os.MkdirAll(*output, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if createdDirectory {
		if err := os.Chmod(*output, 0o700); err != nil {
			return fmt.Errorf("set permissions on output directory: %w", err)
		}
	}

	common := func(cert, key []byte) string {
		return fmt.Sprintf("TB_CONNECTOR_ID=%s\nTB_ENVIRONMENT=%s\nTB_MTLS_CA_B64=%s\nTB_MTLS_CERT_B64=%s\nTB_MTLS_KEY_B64=%s\n", *connectorID, *environment, b64(caCert.Raw), b64PEM("CERTIFICATE", cert), b64PEM("PRIVATE KEY", key))
	}
	edge := common(edgeCert, edgeKey) + "TB_QUIC_LISTEN_ADDR=:4433\nTS_AUTHKEY=replace-me\nTS_HOSTNAME=tailbridge-" + *environment + "\nTS_STATE_DIR=/var/lib/tailscale\nTS_AUTH_ONCE=true\nTS_USERSPACE=false\nTS_EXTRA_ARGS=--advertise-routes=fd12::/16 --advertise-tags=tag:tailbridge\n"
	connector := common(connectorCert, connectorKey) + "TB_EDGE_ENDPOINT=" + *edgeEndpoint + "\nTB_ALLOWED_DESTINATIONS=fd12::/16\n"
	policy := "{\n\t\"tagOwners\": { \"tag:tailbridge\": [\"autogroup:admin\"] },\n\t\"autoApprovers\": { \"routes\": { \"fd12::/16\": [\"tag:tailbridge\"] } }\n}\n"
	files := []secretFile{
		{path: filepath.Join(*output, "edge.env"), content: edge},
		{path: filepath.Join(*output, "connector.env"), content: connector},
		{path: filepath.Join(*output, "tailscale-policy.hujson"), content: policy},
	}
	if err := writeSecretBundle(files, *force); err != nil {
		return err
	}
	fmt.Printf("Wrote the Tailbridge configuration to %s.\n", *output)
	return nil
}

func validateName(label, value string) error {
	if !namePattern.MatchString(value) {
		return fmt.Errorf("%s must match %s", label, namePattern.String())
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	if strings.IndexFunc(endpoint, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) >= 0 {
		return errors.New("edge endpoint must not contain whitespace or control characters")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("edge endpoint must use host:port format: %w", err)
	}
	if host == "" {
		return errors.New("edge endpoint host must not be empty")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("edge endpoint port must be an integer from 1 through 65535, got %q", portText)
	}
	return nil
}

func certificateAuthority(name string) (*x509.Certificate, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptographicRandom)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate authority key: %w", err)
	}
	serialNumber, err := serial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate authority serial number: %w", err)
	}
	template := &x509.Certificate{SerialNumber: serialNumber, Subject: pkix.Name{CommonName: "Tailbridge " + name + " CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(cryptographicRandom, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate authority: %w", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate authority: %w", err)
	}
	return certificate, privateKey, nil
}

func leaf(ca *x509.Certificate, caKey ed25519.PrivateKey, role, id string, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptographicRandom)
	if err != nil {
		return nil, nil, fmt.Errorf("generate %s certificate key: %w", role, err)
	}
	identity, err := url.Parse("spiffe://tailbridge.local/" + role + "/" + id)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s certificate identity: %w", role, err)
	}
	serialNumber, err := serial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate %s certificate serial number: %w", role, err)
	}
	template := &x509.Certificate{SerialNumber: serialNumber, Subject: pkix.Name{CommonName: "tailbridge-" + role + "-" + id}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 3, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{identity}}
	raw, err := x509.CreateCertificate(cryptographicRandom, template, ca, publicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s certificate: %w", role, err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode %s private key: %w", role, err)
	}
	return raw, key, nil
}

func serial() (*big.Int, error) {
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	value, err := rand.Int(cryptographicRandom, limit)
	if err != nil {
		return nil, err
	}
	return value.Add(value, big.NewInt(1)), nil
}

func b64(raw []byte) string { return b64PEM("CERTIFICATE", raw) }

func b64PEM(kind string, raw []byte) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: raw}))
}

type secretFile struct {
	path    string
	content string
	temp    string
	backup  string
	created bool
}

func writeSecretBundle(files []secretFile, force bool) error {
	if !force {
		for _, file := range files {
			if _, err := os.Lstat(file.path); err == nil {
				return fmt.Errorf("Tailbridge will not replace %s without --force", file.path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("inspect %s: %w", file.path, err)
			}
		}
	}

	for index := range files {
		temp, err := stageSecret(files[index].path, files[index].content)
		if err != nil {
			return errors.Join(err, cleanupTemps(files))
		}
		files[index].temp = temp
	}
	if force {
		if err := preserveSecrets(files); err != nil {
			return errors.Join(err, cleanupTemps(files))
		}
	}

	for index := range files {
		var err error
		if force {
			err = renameFile(files[index].temp, files[index].path)
		} else {
			err = linkFile(files[index].temp, files[index].path)
		}
		if err != nil {
			rollbackErr := rollbackSecrets(files, force)
			return errors.Join(fmt.Errorf("install %s: %w", files[index].path, err), rollbackErr)
		}
		files[index].created = true
		if !force {
			if err := removeFile(files[index].temp); err != nil && !os.IsNotExist(err) {
				rollbackErr := rollbackSecrets(files, false)
				return errors.Join(fmt.Errorf("remove temporary file for %s: %w", files[index].path, err), rollbackErr)
			}
		}
		files[index].temp = ""
	}

	var cleanupErr error
	for index := range files {
		if files[index].backup != "" {
			if err := removeFile(files[index].backup); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove backup for %s: %w", files[index].path, err))
			}
			files[index].backup = ""
		}
	}
	if cleanupErr != nil {
		fmt.Fprintf(os.Stderr, "Tailbridge installed the configuration, but it could not remove a backup: %v\n", cleanupErr)
	}
	return nil
}

func stageSecret(path, content string) (temp string, resultErr error) {
	file, err := createTempFile(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tempPath := file.Name()
	temp = tempPath
	closed := false
	defer func() {
		if resultErr != nil {
			if !closed {
				resultErr = errors.Join(resultErr, closeWorkFile(file, path))
			}
			resultErr = errors.Join(resultErr, removeWorkFile(tempPath, path))
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("set permissions on temporary file for %s: %w", path, err)
	}
	if _, err := io.WriteString(file, content); err != nil {
		return "", fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	closed = true
	return temp, nil
}

func closeWorkFile(file *os.File, target string) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("close work file for %s: %w", target, err)
	}
	return nil
}

func removeWorkFile(path, target string) error {
	if err := removeFile(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove work file for %s: %w", target, err)
	}
	return nil
}

func preserveSecrets(files []secretFile) error {
	for index := range files {
		if _, err := os.Lstat(files[index].path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return errors.Join(fmt.Errorf("inspect %s: %w", files[index].path, err), restoreBackups(files))
		}
		placeholder, err := createTempFile(filepath.Dir(files[index].path), "."+filepath.Base(files[index].path)+".backup-*")
		if err != nil {
			return errors.Join(fmt.Errorf("create backup for %s: %w", files[index].path, err), restoreBackups(files))
		}
		backup := placeholder.Name()
		if err := placeholder.Close(); err != nil {
			return errors.Join(fmt.Errorf("close backup for %s: %w", files[index].path, err), removeWorkFile(backup, files[index].path), restoreBackups(files))
		}
		if err := renameFile(files[index].path, backup); err != nil {
			return errors.Join(fmt.Errorf("preserve %s: %w", files[index].path, err), removeWorkFile(backup, files[index].path), restoreBackups(files))
		}
		files[index].backup = backup
	}
	return nil
}

func rollbackSecrets(files []secretFile, force bool) error {
	var rollbackErr error
	for index := range files {
		if files[index].created {
			if err := removeFile(files[index].path); err != nil && !os.IsNotExist(err) {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove new %s: %w", files[index].path, err))
			}
		}
	}
	if force {
		rollbackErr = errors.Join(rollbackErr, restoreBackups(files))
	}
	rollbackErr = errors.Join(rollbackErr, cleanupTemps(files))
	return rollbackErr
}

func restoreBackups(files []secretFile) error {
	var restoreErr error
	for index := range files {
		if files[index].backup == "" {
			continue
		}
		if err := renameFile(files[index].backup, files[index].path); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore %s: %w", files[index].path, err))
			continue
		}
		files[index].backup = ""
	}
	return restoreErr
}

func cleanupTemps(files []secretFile) error {
	var cleanupErr error
	for _, file := range files {
		if file.temp != "" {
			cleanupErr = errors.Join(cleanupErr, removeWorkFile(file.temp, file.path))
		}
	}
	return cleanupErr
}
