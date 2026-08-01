//go:build linux

package edge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/netpolicy"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/proxy"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/transport"
	"github.com/quic-go/quic-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"golang.org/x/sys/unix"
)

type Server struct {
	config    config.Edge
	logger    *slog.Logger
	status    *status.Server
	session   atomic.Pointer[session]
	sessionMu sync.Mutex
	flowID    atomic.Uint64
	limit     chan struct{}
	udpMu     sync.Mutex
	udpByKey  map[string]*edgeUDPFlow
	udpByID   map[uint64]*edgeUDPFlow
}

type edgeUDPFlow struct {
	id          uint64
	source      *net.UDPAddr
	destination netip.AddrPort
	reply       *net.UDPConn
	lastUsed    time.Time
}

type session struct {
	id         string
	started    int64
	connection *quic.Conn
	draining   atomic.Bool
}

func New(cfg config.Edge, logger *slog.Logger, state *status.Server) *Server {
	return &Server{config: cfg, logger: logger, status: state, limit: make(chan struct{}, cfg.MaxTCPFlows), udpByKey: make(map[string]*edgeUDPFlow), udpByID: make(map[uint64]*edgeUDPFlow)}
}

func (s *Server) Run(ctx context.Context) error {
	if s.config.ManageTailscale {
		command := exec.CommandContext(ctx, "/usr/local/bin/containerboot")
		command.Stdout = slog.NewLogLogger(s.logger.Handler(), slog.LevelInfo).Writer()
		command.Stderr = slog.NewLogLogger(s.logger.Handler(), slog.LevelError).Writer()
		if err := command.Start(); err != nil {
			return fmt.Errorf("start Tailscale: %w", err)
		}
		defer func() { _ = command.Process.Kill(); _, _ = command.Process.Wait() }()
	}
	readyContext, cancelReady := context.WithTimeout(ctx, 60*time.Second)
	defer cancelReady()
	if err := netpolicy.WaitForTailscale(readyContext); err != nil {
		return fmt.Errorf("wait for tailscale0: %w", err)
	}
	policy, err := netpolicy.New(s.config.AllowedRoutes, s.config.TCPListenAddr, s.config.UDPListenAddr)
	if err != nil {
		return err
	}
	if err := policy.Apply(ctx); err != nil {
		return err
	}
	defer policy.Close(context.Background())
	tlsConfig, err := transport.ServerTLS(s.config.Common)
	if err != nil {
		return fmt.Errorf("configure TLS: %w", err)
	}
	listener, err := quic.ListenAddr(s.config.QUICListenAddr, tlsConfig, transport.QUICConfig(s.config.MaxTCPFlows))
	if err != nil {
		return fmt.Errorf("listen for QUIC: %w", err)
	}
	defer listener.Close()

	tcpListener, err := transparentTCPListener(s.config.TCPListenAddr)
	if err != nil {
		return fmt.Errorf("listen for transparent TCP: %w", err)
	}
	defer tcpListener.Close()
	udpListener, err := transparentUDPListener(s.config.UDPListenAddr)
	if err != nil {
		return fmt.Errorf("listen for transparent UDP: %w", err)
	}
	defer udpListener.Close()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); s.acceptConnectors(ctx, listener) }()
	go func() { defer wg.Done(); s.acceptTCP(ctx, tcpListener) }()
	go func() { defer wg.Done(); s.acceptUDP(ctx, udpListener) }()
	<-ctx.Done()
	_ = tcpListener.Close()
	_ = udpListener.Close()
	if active := s.session.Load(); active != nil {
		_ = active.connection.CloseWithError(0, "edge shutting down")
	}
	wg.Wait()
	return nil
}

func (s *Server) acceptConnectors(ctx context.Context, listener *quic.Listener) {
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Error("connector accept failed", "error", err)
			}
			return
		}
		go s.authenticate(ctx, conn)
	}
}

func (s *Server) authenticate(ctx context.Context, conn *quic.Conn) {
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "missing control stream")
		return
	}
	var hello protocol.ConnectorHello
	if err := protocol.ReadFrame(control, &hello); err != nil {
		_ = conn.CloseWithError(2, "invalid hello")
		return
	}
	if hello.ProtocolVersion != protocol.ProtocolVersion || hello.ConnectorID != s.config.ConnectorID || hello.Environment != s.config.Environment {
		s.status.Denied()
		_ = conn.CloseWithError(3, "connector identity rejected")
		return
	}
	id := randomID()
	routes := make([]string, 0, len(s.config.AllowedRoutes))
	for _, route := range s.config.AllowedRoutes {
		routes = append(routes, route.String())
	}
	next := &session{id: id, started: hello.StartedUnixNano, connection: conn}
	s.sessionMu.Lock()
	previous := s.session.Load()
	if previous != nil && !connectionClosed(previous.connection) && next.started <= previous.started {
		s.sessionMu.Unlock()
		_ = conn.CloseWithError(5, "newer connector session is active")
		s.logger.Info("connector session superseded", "event.name", "connector.session", "connector.id", hello.ConnectorID, "version", hello.SoftwareVersion)
		return
	}
	if err := protocol.WriteFrame(control, protocol.ConnectorAccepted{SessionID: id, Routes: routes, MaxTCPFlows: s.config.MaxTCPFlows}); err != nil {
		s.sessionMu.Unlock()
		_ = conn.CloseWithError(4, "hello response failed")
		return
	}
	s.session.Store(next)
	s.sessionMu.Unlock()
	s.status.SetReady(true)
	go s.status.ObserveQUIC(conn.Context().Done(), conn)
	s.logger.Info("connector session ready", "event.name", "connector.session", "session_id", id, "connector.id", hello.ConnectorID, "version", hello.SoftwareVersion)
	go s.receiveUDP(next)
	if previous != nil {
		previous.draining.Store(true)
		go func() {
			time.Sleep(15 * time.Second)
			_ = previous.connection.CloseWithError(0, "deployment drain complete")
		}()
	}
	<-conn.Context().Done()
	if s.session.CompareAndSwap(next, nil) {
		s.status.SetReady(false)
	}
	s.logger.Info("connector session closed", "event.name", "connector.session", "session_id", id, "outcome", "closed")
}

func (s *Server) acceptUDP(ctx context.Context, listener *net.UDPConn) {
	buffer := make([]byte, 64*1024)
	oob := make([]byte, 256)
	for {
		n, oobn, _, source, err := listener.ReadMsgUDP(buffer, oob)
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Error("UDP receive failed", "error", err)
			}
			return
		}
		destination, err := originalUDPDestination(oob[:oobn])
		if err != nil || !config.Allowed(s.config.AllowedRoutes, destination.Addr().Unmap()) {
			s.status.Denied()
			continue
		}
		active := s.session.Load()
		if active == nil || active.draining.Load() {
			continue
		}
		sourceAddr := source.AddrPort()
		key := sourceAddr.String() + "|" + destination.String()
		flow, err := s.edgeUDPFlow(key, source, destination)
		if err != nil {
			continue
		}
		packet, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: flow.id, Source: sourceAddr, Destination: destination, Payload: buffer[:n]})
		if err == nil {
			_ = active.connection.SendDatagram(packet)
		}
	}
}

func (s *Server) edgeUDPFlow(key string, source *net.UDPAddr, destination netip.AddrPort) (*edgeUDPFlow, error) {
	s.udpMu.Lock()
	if flow := s.udpByKey[key]; flow != nil {
		flow.lastUsed = time.Now()
		s.udpMu.Unlock()
		return flow, nil
	}
	s.udpMu.Unlock()
	reply, err := transparentUDPResponse(destination)
	if err != nil {
		return nil, err
	}
	flow := &edgeUDPFlow{id: s.flowID.Add(1), source: source, destination: destination, reply: reply, lastUsed: time.Now()}
	s.udpMu.Lock()
	s.udpByKey[key] = flow
	s.udpByID[flow.id] = flow
	s.udpMu.Unlock()
	go func() {
		ticker := time.NewTicker(s.config.UDPIdleTimeout)
		defer ticker.Stop()
		for range ticker.C {
			s.udpMu.Lock()
			if time.Since(flow.lastUsed) >= s.config.UDPIdleTimeout {
				delete(s.udpByKey, key)
				delete(s.udpByID, flow.id)
				_ = flow.reply.Close()
				s.udpMu.Unlock()
				return
			}
			s.udpMu.Unlock()
		}
	}()
	return flow, nil
}

func (s *Server) receiveUDP(active *session) {
	for {
		data, err := active.connection.ReceiveDatagram(active.connection.Context())
		if err != nil {
			return
		}
		packet, err := protocol.DecodeUDP(data)
		if err != nil || !packet.Response {
			continue
		}
		s.udpMu.Lock()
		flow := s.udpByID[packet.FlowID]
		if flow != nil {
			flow.lastUsed = time.Now()
		}
		s.udpMu.Unlock()
		if flow != nil {
			_, _ = flow.reply.WriteToUDP(packet.Payload, flow.source)
		}
	}
}

func (s *Server) acceptTCP(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Error("TCP accept failed", "error", err)
			}
			return
		}
		select {
		case s.limit <- struct{}{}:
			go func() { defer func() { <-s.limit }(); s.handleTCP(ctx, conn) }()
		default:
			s.status.Denied()
			_ = conn.Close()
		}
	}
}

func (s *Server) handleTCP(ctx context.Context, client net.Conn) {
	started := time.Now()
	source, destination := proxy.Address(client)
	ctx, span := otel.Tracer("tailbridge/edge").Start(ctx, "tcp.flow")
	defer span.End()
	span.SetAttributes(attribute.String("network.peer.address", source), attribute.String("server.address", destination))
	addressPort, err := netip.ParseAddrPort(destination)
	if err != nil || !config.Allowed(s.config.AllowedRoutes, addressPort.Addr().Unmap()) {
		s.status.Denied()
		s.logger.Warn("flow denied", "event.name", "tcp.flow", "destination", destination, "error.code", "DESTINATION_DENIED")
		_ = client.Close()
		return
	}
	active := s.session.Load()
	if active == nil || active.draining.Load() {
		_ = client.Close()
		return
	}
	stream, err := active.connection.OpenStreamSync(ctx)
	if err != nil {
		_ = client.Close()
		return
	}
	flowID := s.flowID.Add(1)
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	request := protocol.OpenTCP{FlowID: flowID, Source: source, Destination: destination, DeadlineUnixMS: time.Now().Add(10 * time.Second).UnixMilli(), TraceParent: carrier.Get("traceparent"), TraceState: carrier.Get("tracestate")}
	if err := protocol.WriteFrame(stream, request); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		_ = client.Close()
		return
	}
	var result protocol.OpenTCPResult
	if err := protocol.ReadFrame(stream, &result); err != nil || !result.Accepted {
		stream.CancelRead(2)
		stream.CancelWrite(2)
		_ = client.Close()
		return
	}
	s.status.FlowStarted()
	sent, received := proxy.Bidirectional(client, stream)
	span.SetAttributes(attribute.Int64("network.io.sent", sent), attribute.Int64("network.io.received", received))
	s.status.FlowEnded()
	s.logger.Info("TCP flow complete", "event.name", "tcp.flow", "flow_id", flowID, "session_id", active.id, "destination", destination, "bytes.sent", sent, "bytes.received", received, "duration_ms", time.Since(started).Milliseconds(), "outcome", "success")
}

func transparentTCPListener(address string) (net.Listener, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
				controlErr = err
				return
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		}); err != nil {
			return err
		}
		return controlErr
	}}
	return config.Listen(context.Background(), "tcp", address)
}

func transparentUDPListener(address string) (*net.UDPConn, error) {
	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
				controlErr = err
				return
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
				controlErr = err
				return
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
				controlErr = err
			}
		}); err != nil {
			return err
		}
		return controlErr
	}}
	packet, err := listenConfig.ListenPacket(context.Background(), "udp6", address)
	if err != nil {
		return nil, err
	}
	connection, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return nil, errors.New("transparent UDP listener has unexpected type")
	}
	return connection, nil
}

func transparentUDPResponse(destination netip.AddrPort) (*net.UDPConn, error) {
	network := "udp6"
	if destination.Addr().Is4() || destination.Addr().Is4In6() {
		network = "udp4"
		destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	}
	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			if network == "udp4" {
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			} else {
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return controlErr
	}}
	packet, err := listenConfig.ListenPacket(context.Background(), network, destination.String())
	if err != nil {
		return nil, err
	}
	connection, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return nil, errors.New("transparent UDP response socket has unexpected type")
	}
	return connection, nil
}

func originalUDPDestination(oob []byte) (netip.AddrPort, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, message := range messages {
		if message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR && len(message.Data) >= 8 {
			var address [4]byte
			copy(address[:], message.Data[4:8])
			return netip.AddrPortFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(message.Data[2:4])), nil
		}
		if message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_ORIGDSTADDR && len(message.Data) >= 24 {
			var address [16]byte
			copy(address[:], message.Data[8:24])
			return netip.AddrPortFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(message.Data[2:4])), nil
		}
	}
	return netip.AddrPort{}, errors.New("original UDP destination is missing")
}

func randomID() string {
	var value [12]byte
	_, _ = rand.Read(value[:])
	return hex.EncodeToString(value[:])
}

func connectionClosed(connection *quic.Conn) bool {
	select {
	case <-connection.Context().Done():
		return true
	default:
		return false
	}
}
