package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
	"github.com/quic-go/quic-go"
)

func TestWaitReturnsWhenTheContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if wait(ctx, time.Hour) {
		t.Fatal("wait() = true, want false")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("wait() took %v after cancellation", elapsed)
	}
}

func TestWaitReturnsAfterTheDuration(t *testing.T) {
	if !wait(context.Background(), time.Millisecond) {
		t.Fatal("wait() = false, want true")
	}
}

func TestJitterStaysWithinBounds(t *testing.T) {
	const duration = 10 * time.Second
	const minimum = 8 * time.Second
	const maximum = 12 * time.Second
	for range 10_000 {
		got := jitter(duration)
		if got < minimum || got > maximum {
			t.Fatalf("jitter(%v) = %v, want a value from %v through %v", duration, got, minimum, maximum)
		}
	}
	if got := jitter(0); got != 0 {
		t.Fatalf("jitter(0) = %v, want 0", got)
	}
}

func TestUDPFlowsAreScopedToTheirSession(t *testing.T) {
	destination := listenUDP(t)
	packet := testDatagram(destination.LocalAddr().(*net.UDPAddr).AddrPort())
	first := testUDPSession(2)
	second := testUDPSession(2)
	t.Cleanup(first.close)
	t.Cleanup(second.close)

	firstFlow, err := first.flow(packet)
	if err != nil {
		t.Fatal(err)
	}
	secondFlow, err := second.flow(packet)
	if err != nil {
		t.Fatal(err)
	}
	if firstFlow == secondFlow || firstFlow.connection == secondFlow.connection {
		t.Fatal("separate sessions shared a UDP flow")
	}
	first.mu.Lock()
	firstStored := first.flows[packet.FlowID]
	first.mu.Unlock()
	second.mu.Lock()
	secondStored := second.flows[packet.FlowID]
	second.mu.Unlock()
	if firstStored != firstFlow || secondStored != secondFlow {
		t.Fatal("a session did not store its own UDP flow")
	}
}

func TestUDPFlowRejectsEndpointCollisions(t *testing.T) {
	destination := listenUDP(t)
	session := testUDPSession(2)
	t.Cleanup(session.close)
	packet := testDatagram(destination.LocalAddr().(*net.UDPAddr).AddrPort())

	flow, err := session.flow(packet)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := session.flow(packet)
	if err != nil {
		t.Fatal(err)
	}
	if reused != flow {
		t.Fatal("matching endpoints did not reuse the UDP flow")
	}

	changedSource := packet
	changedSource.Source = netip.MustParseAddrPort("192.0.2.2:2000")
	if _, err := session.flow(changedSource); err == nil || !strings.Contains(err.Error(), "endpoints changed") {
		t.Fatalf("flow() error = %v, want an endpoint collision error", err)
	}

	changedDestination := packet
	changedDestination.Destination = netip.MustParseAddrPort("127.0.0.1:9")
	if _, err := session.flow(changedDestination); err == nil || !strings.Contains(err.Error(), "endpoints changed") {
		t.Fatalf("flow() error = %v, want an endpoint collision error", err)
	}
}

func TestUDPFlowEnforcesTheSessionLimit(t *testing.T) {
	destination := listenUDP(t)
	session := testUDPSession(1)
	t.Cleanup(session.close)
	packet := testDatagram(destination.LocalAddr().(*net.UDPAddr).AddrPort())
	if _, err := session.flow(packet); err != nil {
		t.Fatal(err)
	}

	packet.FlowID++
	if _, err := session.flow(packet); err == nil || !strings.Contains(err.Error(), "flow limit is full") {
		t.Fatalf("flow() error = %v, want a flow limit error", err)
	}
}

func TestUDPResponseCleanupDeletesOnlyTheExactFlow(t *testing.T) {
	destination := listenUDP(t)
	t.Run("matching flow", func(t *testing.T) {
		session := testUDPSession(1)
		flow := closedUDPFlow(t, destination.LocalAddr().(*net.UDPAddr))
		session.flows[1] = flow
		session.readResponses(1, flow)
		if _, ok := session.flows[1]; ok {
			t.Fatal("response cleanup kept the matching UDP flow")
		}
	})

	t.Run("replacement flow", func(t *testing.T) {
		session := testUDPSession(1)
		old := closedUDPFlow(t, destination.LocalAddr().(*net.UDPAddr))
		replacement := &udpFlow{source: netip.MustParseAddrPort("192.0.2.3:3000")}
		session.flows[1] = replacement
		session.readResponses(1, old)
		if session.flows[1] != replacement {
			t.Fatal("response cleanup deleted a replacement UDP flow")
		}
	})
}

func TestUDPResponseContinuesAfterAnOversizedDatagram(t *testing.T) {
	edge, connector := testConnectorQUICPair(t)
	backend := listenUDP(t)
	connection := dialUDP(t, backend.LocalAddr().(*net.UDPAddr))
	flow := &udpFlow{
		connection:  connection,
		source:      netip.MustParseAddrPort("192.0.2.1:1000"),
		destination: backend.LocalAddr().(*net.UDPAddr).AddrPort(),
	}
	session := testUDPSession(1)
	session.connection = connector
	session.flows[1] = flow
	done := make(chan struct{})
	go func() {
		session.readResponses(1, flow)
		close(done)
	}()
	peer := connection.LocalAddr().(*net.UDPAddr)
	if _, err := backend.WriteToUDP(make([]byte, 60*1024), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.WriteToUDP([]byte("accepted"), peer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	data, err := edge.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := protocol.DecodeUDP(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet.Payload) != "accepted" {
		t.Fatalf("response payload = %q, want accepted", packet.Payload)
	}
	_ = connection.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the UDP response reader did not stop")
	}
}

func TestUDPReceiveDropsMalformedDatagrams(t *testing.T) {
	edge, connector := testConnectorQUICPair(t)
	session := testUDPSession(1)
	session.connection = connector
	done := make(chan struct{})
	go func() {
		session.receive()
		close(done)
	}()
	if err := edge.SendDatagram([]byte("malformed")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	_ = edge.CloseWithError(0, "test complete")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the UDP receiver did not stop")
	}
}

func TestUDPSessionCloseClosesAndRejectsFlows(t *testing.T) {
	destination := listenUDP(t)
	session := testUDPSession(2)
	first := dialUDP(t, destination.LocalAddr().(*net.UDPAddr))
	second := dialUDP(t, destination.LocalAddr().(*net.UDPAddr))
	session.flows[1] = &udpFlow{connection: first}
	session.flows[2] = &udpFlow{connection: second}

	session.close()
	session.close()
	if !session.closed {
		t.Fatal("close() did not mark the session closed")
	}
	if len(session.flows) != 0 {
		t.Fatalf("close() kept %d UDP flows", len(session.flows))
	}
	for _, connection := range []*net.UDPConn{first, second} {
		if _, err := connection.Write([]byte("test")); err == nil {
			t.Fatal("close() left a UDP connection open")
		}
	}
	packet := testDatagram(destination.LocalAddr().(*net.UDPAddr).AddrPort())
	if _, err := session.flow(packet); err == nil || !strings.Contains(err.Error(), "session is closed") {
		t.Fatalf("flow() error = %v, want a closed session error", err)
	}
}

func TestHandleTCPRejectsInvalidRequests(t *testing.T) {
	edge, connector := testConnectorQUICPair(t)
	client := testClient(config.Connector{DialTimeout: time.Second})
	routes := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	tests := []struct {
		name    string
		request protocol.OpenTCP
		code    string
	}{
		{
			name: "invalid destination",
			request: protocol.OpenTCP{
				Destination:    "not-an-address",
				DeadlineUnixMS: time.Now().Add(time.Second).UnixMilli(),
			},
			code: "DESTINATION_DENIED",
		},
		{
			name: "destination outside policy",
			request: protocol.OpenTCP{
				Destination:    "192.0.2.1:443",
				DeadlineUnixMS: time.Now().Add(time.Second).UnixMilli(),
			},
			code: "DESTINATION_DENIED",
		},
		{
			name: "expired deadline",
			request: protocol.OpenTCP{
				Destination:    "127.0.0.1:443",
				DeadlineUnixMS: time.Now().Add(-time.Second).UnixMilli(),
			},
			code: "DEADLINE_EXCEEDED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runTCPRequest(t, edge, connector, client, routes, test.request)
			if result.Accepted || result.Code != test.code {
				t.Fatalf("handleTCP() result = %+v, want rejected code %q", result, test.code)
			}
		})
	}
}

func TestHandleTCPReportsAnUnreachableDestination(t *testing.T) {
	edge, connector := testConnectorQUICPair(t)
	client := testClient(config.Connector{DialTimeout: time.Second})
	address := unusedTCPAddress(t)
	request := protocol.OpenTCP{
		Destination:    address,
		DeadlineUnixMS: time.Now().Add(time.Second).UnixMilli(),
	}
	result := runTCPRequest(t, edge, connector, client, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, request)
	if result.Accepted || result.Code != "DESTINATION_UNREACHABLE" {
		t.Fatalf("handleTCP() result = %+v, want rejected code DESTINATION_UNREACHABLE", result)
	}
}

func TestHandleTCPProxiesBytes(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	upstreamError := make(chan error, 1)
	go func() {
		connection, err := upstream.Accept()
		if err != nil {
			upstreamError <- err
			return
		}
		defer connection.Close()
		request, err := io.ReadAll(connection)
		if err != nil {
			upstreamError <- err
			return
		}
		_, err = connection.Write(append([]byte("reply:"), request...))
		upstreamError <- err
	}()

	edge, connector := testConnectorQUICPair(t)
	client := testClient(config.Connector{DialTimeout: time.Second})
	stream, handled := startTCPRequest(t, edge, connector, client, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, protocol.OpenTCP{
		FlowID:         7,
		Destination:    upstream.Addr().String(),
		DeadlineUnixMS: time.Now().Add(2 * time.Second).UnixMilli(),
	})
	var result protocol.OpenTCPResult
	if err := protocol.ReadFrame(stream, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Code != "" {
		t.Fatalf("handleTCP() result = %+v, want an accepted result", result)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(response), "reply:hello"; got != want {
		t.Fatalf("proxy response = %q, want %q", got, want)
	}
	select {
	case err := <-upstreamError:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream TCP handler did not return")
	}
	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("handleTCP() did not return")
	}
}

func testUDPSession(maxFlows int64) *udpSession {
	client := testClient(config.Connector{MaxUDPFlows: maxFlows, UDPIdleTimeout: time.Hour})
	return &udpSession{client: client, flows: make(map[uint64]*udpFlow)}
}

func testClient(cfg config.Connector) *Client {
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), status.New("test"), "test")
}

func runTCPRequest(t *testing.T, edge, connector *quic.Conn, client *Client, routes []netip.Prefix, request protocol.OpenTCP) protocol.OpenTCPResult {
	t.Helper()
	stream, handled := startTCPRequest(t, edge, connector, client, routes, request)
	var result protocol.OpenTCPResult
	if err := protocol.ReadFrame(stream, &result); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("handleTCP() did not return")
	}
	return result
}

func startTCPRequest(t *testing.T, edge, connector *quic.Conn, client *Client, routes []netip.Prefix, request protocol.OpenTCP) (*quic.Stream, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	edgeStream, err := edge.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(edgeStream, request); err != nil {
		t.Fatal(err)
	}
	connectorStream, err := connector.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	handled := make(chan struct{})
	go func() {
		client.handleTCP(connectorStream, "test-session", routes)
		close(handled)
	}()
	if err := edgeStream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return edgeStream, handled
}

func testConnectorQUICPair(t *testing.T) (*quic.Conn, *quic.Conn) {
	t.Helper()
	serverTLS := &tls.Config{Certificates: []tls.Certificate{testConnectorTLSCertificate(t)}, NextProtos: []string{protocol.ALPN}}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *quic.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(context.Background())
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- connection
	}()
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{protocol.ALPN}}
	edge, err := quic.DialAddr(context.Background(), listener.Addr().String(), clientTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var connector *quic.Conn
	select {
	case connector = <-accepted:
	case err := <-acceptError:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("the QUIC listener did not accept the connection")
	}
	t.Cleanup(func() {
		_ = edge.CloseWithError(0, "test complete")
		_ = connector.CloseWithError(0, "test complete")
		_ = listener.Close()
	})
	return edge, connector
}

func testConnectorTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func testDatagram(destination netip.AddrPort) protocol.UDPDatagram {
	return protocol.UDPDatagram{
		FlowID:      1,
		Source:      netip.MustParseAddrPort("192.0.2.1:1000"),
		Destination: destination,
		Payload:     []byte("test"),
	}
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close UDP listener: %v", err)
		}
	})
	return connection
}

func dialUDP(t *testing.T, destination *net.UDPAddr) *net.UDPConn {
	t.Helper()
	connection, err := net.DialUDP("udp4", nil, destination)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func closedUDPFlow(t *testing.T, destination *net.UDPAddr) *udpFlow {
	t.Helper()
	connection := dialUDP(t, destination)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return &udpFlow{connection: connection}
}
