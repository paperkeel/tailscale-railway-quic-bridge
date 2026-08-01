//go:build linux

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/connector"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/edge"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
)

const (
	edgeNamespace    = "tailbridge-edge-test"
	backendNamespace = "tailbridge-backend-test"
	clientInterface  = "tbclient0"
	backendInterface = "tbbackend0"
	edgeAddress      = "fd42:100::2"
	clientAddress    = "fd42:100::1"
	backendLink      = "fd42:300::2"
	hostBackendLink  = "fd42:300::1"
	serviceAddress   = "fd42:200::2"
	servicePort      = 18080
)

func TestBridgeIntegration(t *testing.T) {
	if os.Getenv("TB_RUN_INTEGRATION") != "1" {
		t.Skip("set TB_RUN_INTEGRATION=1 to run the privileged integration test")
	}
	requireCommands(t, "ip", "nft", "sysctl")
	baselineGoroutines := runtime.NumGoroutine()
	baselineDescriptors := fileDescriptorCount(t)
	setupNetwork(t)

	edgeCommon, connectorCommon := credentials(t)
	// Docker gives this test a disposable client network namespace. The test
	// adds separate edge and backend namespaces inside that container.
	edgeConfig := config.Edge{
		Common:          edgeCommon,
		QUICListenAddr:  "[" + edgeAddress + "]:4433",
		TCPListenAddr:   "[::]:15001",
		UDPListenAddr:   "[::]:15002",
		AllowedRoutes:   []netip.Prefix{netip.MustParsePrefix("fd42:200::/64")},
		MaxTCPFlows:     128,
		MaxUDPFlows:     32,
		UDPIdleTimeout:  2 * time.Second,
		ManageTailscale: false,
	}
	connectorConfig := config.Connector{
		Common:              connectorCommon,
		EdgeEndpoint:        "[" + edgeAddress + "]:4433",
		AllowedDestinations: []netip.Prefix{netip.MustParsePrefix(serviceAddress + "/128")},
		MaxTCPFlows:         128,
		MaxUDPFlows:         32,
		DialTimeout:         2 * time.Second,
		ReconnectMin:        50 * time.Millisecond,
		ReconnectMax:        500 * time.Millisecond,
		UDPIdleTimeout:      2 * time.Second,
	}

	edgeProcess := startHelper(t, edgeNamespace, "edge", edgeConfig, "edge")
	echoProcess := startHelper(t, backendNamespace, "echo", nil, "echo")
	waitForOutput(t, echoProcess.output, "ECHO_READY", 5*time.Second)
	connectorOne := startHelper(t, backendNamespace, "connector", connectorConfig, "connector-one")
	waitForOutput(t, connectorOne.output, "edge session ready", 20*time.Second)

	tcpPayload := bytes.Repeat([]byte("tailbridge-tcp-"), 160)
	waitForTCP(t, tcpPayload, 20*time.Second)
	udpPayload := make([]byte, 1200)
	if _, err := rand.Read(udpPayload); err != nil {
		t.Fatal(err)
	}
	waitForUDP(t, udpPayload, 10*time.Second)
	assertOversizedUDPRejected(t)
	if err := exchangeTCPAt("fd42:200::3", []byte("denied route")); err == nil {
		t.Fatal("TCP reached a route that the connector did not advertise")
	}

	persistent, err := net.DialTimeout("tcp6", net.JoinHostPort(serviceAddress, fmt.Sprint(servicePort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	if err := exchangeTCPConnection(persistent, []byte("before replacement")); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Millisecond)
	connectorTwo := startHelper(t, backendNamespace, "connector", connectorConfig, "connector-two")
	waitForOutput(t, connectorTwo.output, "edge session ready", 20*time.Second)
	if err := exchangeTCPConnection(persistent, []byte("after replacement")); err != nil {
		t.Fatalf("existing TCP connection failed after replacement: %v", err)
	}
	_ = persistent.Close()
	connectorOne.stop(t)
	waitForTCP(t, []byte("replacement connector"), 10*time.Second)
	waitForUDP(t, udpPayload, 10*time.Second)
	stressTCP(t, 1000, 30*time.Second)
	stressUDP(t, 10000, 30*time.Second)

	connectorTwo.stop(t)
	edgeProcess.stop(t)
	assertPolicyCleanup(t)
	echoProcess.stop(t)
	assertResourceCleanup(t, baselineGoroutines, baselineDescriptors)
}

func TestIntegrationHelper(t *testing.T) {
	mode := os.Getenv("TB_INTEGRATION_HELPER")
	if mode == "" {
		t.Skip("integration helper")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	switch mode {
	case "edge":
		var cfg config.Edge
		decodeConfig(t, &cfg)
		if err := edge.New(cfg, logger, status.New("integration")).Run(ctx); err != nil {
			t.Fatal(err)
		}
	case "connector":
		var cfg config.Connector
		decodeConfig(t, &cfg)
		err := connector.New(cfg, logger, status.New("integration"), "integration").Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case "echo":
		runEchoServers(t, ctx)
	default:
		t.Fatalf("unknown integration helper %q", mode)
	}
}

type helperProcess struct {
	command *exec.Cmd
	cancel  context.CancelFunc
	output  *lockedBuffer
	done    chan error
	mu      sync.Mutex
	stopped bool
}

func startHelper(t *testing.T, namespace, mode string, cfg any, profile string) *helperProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"netns", "exec", namespace, executable, "-test.run=^TestIntegrationHelper$", "-test.count=1"}
	if directory := os.Getenv("TB_COVERAGE_DIR"); directory != "" {
		args = append(args, "-test.coverprofile="+filepath.Join(directory, "coverage."+profile+".out"))
	}
	commandContext, cancelCommand := context.WithTimeout(context.Background(), 2*time.Minute)
	command := exec.CommandContext(commandContext, "ip", args...)
	command.Env = append(os.Environ(), "TB_INTEGRATION_HELPER="+mode)
	if cfg != nil {
		encoded, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		command.Env = append(command.Env, "TB_INTEGRATION_CONFIG="+base64.StdEncoding.EncodeToString(encoded))
	}
	output := &lockedBuffer{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		cancelCommand()
		t.Fatal(err)
	}
	process := &helperProcess{command: command, cancel: cancelCommand, output: output, done: make(chan error, 1)}
	go func() { process.done <- command.Wait() }()
	t.Cleanup(func() { process.stop(t) })
	return process
}

func (p *helperProcess) stop(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	p.mu.Unlock()
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("signal helper: %v", err)
	}
	select {
	case err := <-p.done:
		p.cancel()
		if err != nil {
			t.Errorf("helper failed: %v\n%s", err, p.output.String())
		}
	case <-time.After(10 * time.Second):
		p.cancel()
		_ = p.command.Process.Kill()
		t.Errorf("helper did not stop\n%s", p.output.String())
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func setupNetwork(t *testing.T) {
	t.Helper()
	run(t, "ip", "netns", "add", edgeNamespace)
	run(t, "ip", "netns", "add", backendNamespace)
	t.Cleanup(func() {
		_ = runError("ip", "netns", "delete", backendNamespace)
		_ = runError("ip", "netns", "delete", edgeNamespace)
	})
	run(t, "ip", "link", "add", clientInterface, "type", "veth", "peer", "name", "tbedgepeer0")
	run(t, "ip", "link", "set", "tbedgepeer0", "netns", edgeNamespace)
	run(t, "ip", "-n", edgeNamespace, "link", "set", "tbedgepeer0", "name", "tailscale0")
	run(t, "ip", "link", "add", backendInterface, "type", "veth", "peer", "name", "tbbackpeer0")
	run(t, "ip", "link", "set", "tbbackpeer0", "netns", backendNamespace)
	run(t, "ip", "-n", backendNamespace, "link", "set", "tbbackpeer0", "name", "uplink0")

	run(t, "ip", "address", "add", clientAddress+"/64", "dev", clientInterface, "nodad")
	run(t, "ip", "link", "set", clientInterface, "up")
	run(t, "ip", "-n", edgeNamespace, "link", "set", "lo", "up")
	run(t, "ip", "-n", edgeNamespace, "address", "add", edgeAddress+"/64", "dev", "tailscale0", "nodad")
	run(t, "ip", "-n", edgeNamespace, "link", "set", "tailscale0", "up")
	run(t, "ip", "address", "add", hostBackendLink+"/64", "dev", backendInterface, "nodad")
	run(t, "ip", "link", "set", backendInterface, "up")
	run(t, "ip", "-n", backendNamespace, "link", "set", "lo", "up")
	run(t, "ip", "-n", backendNamespace, "address", "add", backendLink+"/64", "dev", "uplink0", "nodad")
	run(t, "ip", "-n", backendNamespace, "address", "add", serviceAddress+"/128", "dev", "lo", "nodad")
	run(t, "ip", "-n", backendNamespace, "link", "set", "uplink0", "up")

	run(t, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
	run(t, "ip", "-6", "route", "add", "fd42:200::/64", "via", edgeAddress, "dev", clientInterface)
	run(t, "ip", "-n", edgeNamespace, "-6", "route", "add", "fd42:300::/64", "via", clientAddress, "dev", "tailscale0")
	run(t, "ip", "-n", backendNamespace, "-6", "route", "add", "default", "via", hostBackendLink, "dev", "uplink0")
}

func assertPolicyCleanup(t *testing.T) {
	t.Helper()
	if err := runError("ip", "netns", "exec", edgeNamespace, "nft", "list", "table", "inet", "tailbridge"); err == nil {
		t.Error("the tailbridge nftables table remains after shutdown")
	}
	rules := output(t, "ip", "netns", "exec", edgeNamespace, "ip", "-6", "rule", "show")
	if strings.Contains(rules, "lookup 100") && strings.Contains(rules, "fwmark") {
		t.Errorf("the Tailbridge policy rule remains after shutdown:\n%s", rules)
	}
	routes := output(t, "ip", "netns", "exec", edgeNamespace, "ip", "-6", "route", "show", "table", "100")
	if strings.TrimSpace(routes) != "" {
		t.Errorf("the Tailbridge policy route remains after shutdown:\n%s", routes)
	}
}

func runEchoServers(t *testing.T, ctx context.Context) {
	t.Helper()
	address := net.JoinHostPort(serviceAddress, fmt.Sprint(servicePort))
	tcpListener, err := net.Listen("tcp6", address)
	if err != nil {
		t.Fatal(err)
	}
	udpAddress, err := net.ResolveUDPAddr("udp6", address)
	if err != nil {
		t.Fatal(err)
	}
	udpConnection, err := net.ListenUDP("udp6", udpAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	defer udpConnection.Close()
	fmt.Println("ECHO_READY")
	go func() {
		<-ctx.Done()
		_ = tcpListener.Close()
		_ = udpConnection.Close()
	}()
	go func() {
		for {
			connection, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	buffer := make([]byte, 64*1024)
	for {
		n, peer, err := udpConnection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if _, err := udpConnection.WriteToUDP(buffer[:n], peer); err != nil {
			fmt.Fprintf(os.Stderr, "UDP echo write to %s failed: %v\n", peer, err)
		}
	}
}

func waitForTCP(t *testing.T, payload []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = exchangeTCP(payload)
		if lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TCP exchange failed: %v", lastErr)
}

func exchangeTCP(payload []byte) error {
	return exchangeTCPAt(serviceAddress, payload)
}

func exchangeTCPAt(address string, payload []byte) error {
	connection, err := net.DialTimeout("tcp6", net.JoinHostPort(address, fmt.Sprint(servicePort)), time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	return exchangeTCPConnection(connection, payload)
}

func exchangeTCPConnection(connection net.Conn, payload []byte) error {
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write(payload); err != nil {
		return err
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil {
		return err
	}
	if !bytes.Equal(received, payload) {
		return errors.New("the TCP echo payload changed")
	}
	return nil
}

func stressTCP(t *testing.T, exchanges int, timeout time.Duration) {
	t.Helper()
	started := time.Now()
	jobs := make(chan int, exchanges)
	for index := range exchanges {
		jobs <- index
	}
	close(jobs)
	errors := make(chan error, 32)
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if err := exchangeTCP([]byte("stress")); err != nil {
					errors <- fmt.Errorf("TCP stress exchange %d failed: %w", index, err)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
		select {
		case err := <-errors:
			t.Fatal(err)
		default:
		}
	case <-time.After(timeout):
		t.Fatalf("TCP stress test exceeded %s", timeout)
	}
	t.Logf("completed %d TCP exchanges in %s", exchanges, time.Since(started))
}

func waitForUDP(t *testing.T, payload []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = exchangeUDP(payload)
		if lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("UDP exchange failed: %v", lastErr)
}

func exchangeUDP(payload []byte) error {
	address, err := net.ResolveUDPAddr("udp6", net.JoinHostPort(serviceAddress, fmt.Sprint(servicePort)))
	if err != nil {
		return err
	}
	connection, err := net.DialUDP("udp6", nil, address)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write(payload); err != nil {
		return err
	}
	received := make([]byte, len(payload)+1)
	n, err := connection.Read(received)
	if err != nil {
		return err
	}
	if n != len(payload) || !bytes.Equal(received[:n], payload) {
		return errors.New("the UDP echo payload changed")
	}
	return nil
}

func assertOversizedUDPRejected(t *testing.T) {
	t.Helper()
	address, err := net.ResolveUDPAddr("udp6", net.JoinHostPort(serviceAddress, fmt.Sprint(servicePort)))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP("udp6", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write(make([]byte, 1<<16)); err == nil {
		t.Fatal("the UDP socket accepted a 65,536-byte datagram")
	}
}

func stressUDP(t *testing.T, datagrams int, timeout time.Duration) {
	t.Helper()
	address, err := net.ResolveUDPAddr("udp6", net.JoinHostPort(serviceAddress, fmt.Sprint(servicePort)))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	jobs := make(chan int, datagrams)
	for index := range datagrams {
		jobs <- index
	}
	close(jobs)
	errors := make(chan error, 16)
	var lost atomic.Int64
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			connection, err := net.DialUDP("udp6", nil, address)
			if err != nil {
				errors <- err
				return
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 1200)
			received := make([]byte, len(payload)+1)
			for index := range jobs {
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := connection.Write(payload); err != nil {
					lost.Add(1)
					continue
				}
				n, err := connection.Read(received)
				if err != nil {
					lost.Add(1)
					continue
				}
				if n != len(payload) || !bytes.Equal(received[:n], payload) {
					errors <- fmt.Errorf("UDP stress payload %d changed", index)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
		select {
		case err := <-errors:
			t.Fatal(err)
		default:
		}
	case <-time.After(timeout):
		t.Fatalf("UDP stress test exceeded %s", timeout)
	}
	maximumLoss := int64(datagrams / 100)
	if lost.Load() > maximumLoss {
		t.Fatalf("UDP stress test lost %d of %d datagrams, maximum %d", lost.Load(), datagrams, maximumLoss)
	}
	t.Logf("completed %d UDP datagrams with %d losses in %s", datagrams, lost.Load(), time.Since(started))
}

func credentials(t *testing.T) (config.Common, config.Common) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tailbridge integration CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	edgeCertificate, edgeKey := leafCertificate(t, ca, caKey, "edge", x509.ExtKeyUsageServerAuth, 2)
	connectorCertificate, connectorKey := leafCertificate(t, ca, caKey, "connector", x509.ExtKeyUsageClientAuth, 3)
	common := func(certificate, key []byte) config.Common {
		return config.Common{ConnectorID: "integration", Environment: "test", CABundle: caPEM, Certificate: certificate, PrivateKey: key, LogLevel: "debug"}
	}
	return common(edgeCertificate, edgeKey), common(connectorCertificate, connectorKey)
}

func leafCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, role string, usage x509.ExtKeyUsage, serial int64) ([]byte, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := url.Parse("spiffe://tailbridge.local/" + role + "/integration")
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: role},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		URIs:         []*url.URL{identity},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func decodeConfig(t *testing.T, target any) {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(os.Getenv("TB_INTEGRATION_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func waitForOutput(t *testing.T, output *lockedBuffer, text string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(output.String(), text) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("helper output does not contain %q:\n%s", text, output.String())
}

func requireCommands(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("%s is required: %v", name, err)
		}
	}
}

func fileDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func assertResourceCleanup(t *testing.T, baselineGoroutines, baselineDescriptors int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		goroutines := runtime.NumGoroutine()
		descriptors := fileDescriptorCount(t)
		if goroutines <= baselineGoroutines+10 && descriptors <= baselineDescriptors+5 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cleanup left %d extra goroutines and %d extra file descriptors", goroutines-baselineGoroutines, descriptors-baselineDescriptors)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if data, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s failed: %v: %s", name, err, bytes.TrimSpace(data))
	}
}

func runError(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

func output(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", name, err, bytes.TrimSpace(data))
	}
	return string(data)
}
