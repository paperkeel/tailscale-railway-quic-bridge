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
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type Server struct {
	config      config.Edge
	logger      *slog.Logger
	status      *status.Server
	session     atomic.Pointer[session]
	sessionMu   sync.Mutex
	connections sync.Map
	flowID      atomic.Uint64
	limit       chan struct{}
	udpMu       sync.Mutex
	udpByKey    map[string]*edgeUDPFlow
	udpByID     map[uint64]*edgeUDPFlow
}

type edgeUDPFlow struct {
	id          uint64
	session     *session
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
	routes     []netip.Prefix
}

type networkPolicy interface {
	Apply(context.Context) error
	Close(context.Context) error
}

type managedProcess struct {
	done <-chan error
	kill func() error
}

var (
	waitForNetwork  = netpolicy.WaitForTailscale
	listenQUIC      = quic.ListenAddr
	listenTCP       = transparentTCPListener
	listenUDP       = transparentUDPListener
	openUDPResponse = transparentUDPResponse
	createPolicy    = func(routes []netip.Prefix, tcpAddress, udpAddress string) (networkPolicy, error) {
		return netpolicy.New(routes, tcpAddress, udpAddress)
	}
	startTailscale = func(ctx context.Context, logger *slog.Logger) (*managedProcess, error) {
		command := exec.CommandContext(ctx, "/usr/local/bin/containerboot")
		command.Stdout = slog.NewLogLogger(logger.Handler(), slog.LevelInfo).Writer()
		command.Stderr = slog.NewLogLogger(logger.Handler(), slog.LevelError).Writer()
		if err := command.Start(); err != nil {
			return nil, err
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		return &managedProcess{done: done, kill: command.Process.Kill}, nil
	}
)

func New(cfg config.Edge, logger *slog.Logger, state *status.Server) *Server {
	return &Server{config: cfg, logger: logger, status: state, limit: make(chan struct{}, cfg.MaxTCPFlows), udpByKey: make(map[string]*edgeUDPFlow), udpByID: make(map[uint64]*edgeUDPFlow)}
}

func (s *Server) Run(ctx context.Context) error {
	runContext, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	var bootDone <-chan error
	var bootProcess *managedProcess
	if s.config.ManageTailscale {
		process, err := startTailscale(ctx, s.logger)
		if err != nil {
			return fmt.Errorf("start Tailscale: %w", err)
		}
		bootProcess = process
		bootDone = process.done
		defer func() { _ = process.kill() }()
	}
	readyContext, cancelReady := context.WithTimeout(runContext, 60*time.Second)
	defer cancelReady()
	ready := make(chan error, 1)
	wait := waitForNetwork
	go func() { ready <- wait(readyContext) }()
	select {
	case err := <-ready:
		if err != nil {
			return fmt.Errorf("wait for tailscale0: %w", err)
		}
	case err := <-bootDone:
		return processStoppedError("Tailscale stopped before it became ready", err)
	}
	policy, err := createPolicy(s.config.AllowedRoutes, s.config.TCPListenAddr, s.config.UDPListenAddr)
	if err != nil {
		return err
	}
	if err := policy.Apply(runContext); err != nil {
		return err
	}
	defer func() {
		if err := policy.Close(context.Background()); err != nil {
			s.logger.Error("network policy cleanup failed", "error", err)
		}
	}()
	tlsConfig, err := transport.ServerTLS(s.config.Common)
	if err != nil {
		return fmt.Errorf("configure TLS: %w", err)
	}
	listener, err := listenQUIC(s.config.QUICListenAddr, tlsConfig, transport.QUICConfig(s.config.MaxTCPFlows))
	if err != nil {
		return fmt.Errorf("listen for QUIC: %w", err)
	}
	defer listener.Close()

	tcpListener, err := listenTCP(s.config.TCPListenAddr)
	if err != nil {
		return fmt.Errorf("listen for transparent TCP: %w", err)
	}
	defer tcpListener.Close()
	udpListener, err := listenUDP(s.config.UDPListenAddr)
	if err != nil {
		return fmt.Errorf("listen for transparent UDP: %w", err)
	}
	defer udpListener.Close()

	group, groupContext := errgroup.WithContext(runContext)
	group.Go(func() error { return s.acceptConnectors(groupContext, listener) })
	group.Go(func() error { return s.acceptTCP(groupContext, tcpListener) })
	group.Go(func() error { return s.acceptUDP(groupContext, udpListener) })
	if bootDone != nil {
		group.Go(func() error {
			select {
			case err := <-bootDone:
				if groupContext.Err() != nil {
					return nil
				}
				return processStoppedError("Tailscale stopped", err)
			case <-groupContext.Done():
				if bootProcess != nil {
					_ = bootProcess.kill()
				}
				return nil
			}
		})
	}
	group.Go(func() error {
		<-groupContext.Done()
		_ = listener.Close()
		_ = tcpListener.Close()
		_ = udpListener.Close()
		if active := s.session.Load(); active != nil {
			_ = active.connection.CloseWithError(0, "edge shutting down")
		}
		s.connections.Range(func(key, _ any) bool {
			_ = key.(*quic.Conn).CloseWithError(0, "edge shutting down")
			return true
		})
		s.closeUDPFlows()
		return nil
	})
	err = group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) acceptConnectors(ctx context.Context, listener *quic.Listener) error {
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Error("connector accept failed", "error", err)
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept connector: %w", err)
		}
		s.connections.Store(conn, struct{}{})
		go s.authenticate(ctx, conn)
	}
}

func (s *Server) authenticate(ctx context.Context, conn *quic.Conn) {
	defer s.connections.Delete(conn)
	handshakeContext, cancelHandshake := context.WithTimeout(ctx, 10*time.Second)
	defer cancelHandshake()
	control, err := conn.AcceptStream(handshakeContext)
	if err != nil {
		_ = conn.CloseWithError(1, "The control stream is missing.")
		return
	}
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	var hello protocol.ConnectorHello
	if err := protocol.ReadFrame(control, &hello); err != nil {
		_ = conn.CloseWithError(2, "The hello frame is not valid.")
		return
	}
	if hello.ProtocolVersion != protocol.ProtocolVersion || hello.ConnectorID != s.config.ConnectorID || hello.Environment != s.config.Environment {
		s.status.Denied()
		_ = conn.CloseWithError(3, "The edge rejected the connector identity.")
		return
	}
	if hello.StartedUnixNano <= 0 || hello.StartedUnixNano > time.Now().Add(5*time.Minute).UnixNano() {
		s.status.Denied()
		_ = conn.CloseWithError(3, "The connector start time is not valid.")
		return
	}
	advertised := make([]netip.Prefix, 0, len(hello.Routes))
	for _, raw := range hello.Routes {
		route, err := netip.ParsePrefix(raw)
		if err != nil {
			s.status.Denied()
			_ = conn.CloseWithError(3, "The connector routes are not valid.")
			return
		}
		advertised = append(advertised, route.Masked())
	}
	acceptedRoutes := config.IntersectPrefixes(s.config.AllowedRoutes, advertised)
	if len(acceptedRoutes) == 0 {
		s.status.Denied()
		_ = conn.CloseWithError(3, "The edge and connector have no shared routes.")
		return
	}
	id, err := randomID()
	if err != nil {
		_ = conn.CloseWithError(4, "The edge could not create a session identifier.")
		return
	}
	routes := make([]string, 0, len(acceptedRoutes))
	for _, route := range acceptedRoutes {
		routes = append(routes, route.String())
	}
	next := &session{id: id, started: hello.StartedUnixNano, connection: conn, routes: acceptedRoutes}
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
		_ = conn.CloseWithError(4, "The edge could not send the hello response.")
		return
	}
	_ = control.SetDeadline(time.Time{})
	s.session.Store(next)
	s.sessionMu.Unlock()
	s.status.SetReady(true)
	go s.status.ObserveQUIC(conn.Context().Done(), conn)
	s.logger.Info("connector session ready", "event.name", "connector.session", "session_id", id, "connector.id", hello.ConnectorID, "version", hello.SoftwareVersion)
	go s.receiveUDP(next)
	if previous != nil {
		previous.draining.Store(true)
		go func() {
			timer := time.NewTimer(15 * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
				_ = previous.connection.CloseWithError(0, "The deployment drain is complete.")
			}
		}()
	}
	<-conn.Context().Done()
	if s.session.CompareAndSwap(next, nil) {
		s.status.SetReady(false)
	}
	s.logger.Info("connector session closed", "event.name", "connector.session", "session_id", id, "outcome", "closed")
}

func (s *Server) acceptUDP(ctx context.Context, listener *net.UDPConn) error {
	buffer := make([]byte, 64*1024)
	oob := make([]byte, 256)
	for {
		n, oobn, _, source, err := listener.ReadMsgUDP(buffer, oob)
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Error("UDP receive failed", "error", err)
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("receive UDP: %w", err)
		}
		destination, err := originalUDPDestination(oob[:oobn])
		if err != nil || !config.Allowed(s.config.AllowedRoutes, destination.Addr().Unmap()) {
			s.status.Denied()
			s.status.DatagramDropped()
			continue
		}
		active := s.session.Load()
		if active == nil || active.draining.Load() || !config.Allowed(active.routes, destination.Addr().Unmap()) {
			s.status.DatagramDropped()
			continue
		}
		sourceAddr := source.AddrPort()
		key := active.id + "|" + sourceAddr.String() + "|" + destination.String()
		flow, err := s.edgeUDPFlow(active, key, source, destination)
		if err != nil {
			s.status.DatagramDropped()
			continue
		}
		packet, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: flow.id, Source: sourceAddr, Destination: destination, Payload: buffer[:n]})
		if err == nil {
			if err := active.connection.SendDatagram(packet); err != nil {
				s.status.DatagramDropped()
			}
		} else {
			s.status.DatagramDropped()
		}
	}
}

func (s *Server) edgeUDPFlow(active *session, key string, source *net.UDPAddr, destination netip.AddrPort) (*edgeUDPFlow, error) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if flow := s.udpByKey[key]; flow != nil {
		flow.lastUsed = time.Now()
		return flow, nil
	}
	if int64(len(s.udpByID)) >= s.config.MaxUDPFlows {
		return nil, errors.New("the UDP flow limit is full")
	}
	reply, err := openUDPResponse(destination)
	if err != nil {
		return nil, err
	}
	flow := &edgeUDPFlow{id: s.flowID.Add(1), session: active, source: source, destination: destination, reply: reply, lastUsed: time.Now()}
	s.udpByKey[key] = flow
	s.udpByID[flow.id] = flow
	s.status.UDPFlowStarted()
	go func() {
		ticker := time.NewTicker(s.config.UDPIdleTimeout)
		defer ticker.Stop()
		for range ticker.C {
			s.udpMu.Lock()
			if s.udpByID[flow.id] != flow {
				s.udpMu.Unlock()
				return
			}
			if time.Since(flow.lastUsed) >= s.config.UDPIdleTimeout {
				delete(s.udpByKey, key)
				delete(s.udpByID, flow.id)
				_ = flow.reply.Close()
				s.status.UDPFlowEnded()
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
			s.status.DatagramDropped()
			continue
		}
		s.udpMu.Lock()
		flow := s.udpByID[packet.FlowID]
		if flow != nil && flow.session == active && packet.Source == flow.destination && packet.Destination == flow.source.AddrPort() {
			flow.lastUsed = time.Now()
		} else {
			flow = nil
			s.status.DatagramDropped()
		}
		s.udpMu.Unlock()
		if flow != nil {
			if _, err := flow.reply.WriteToUDP(packet.Payload, flow.source); err != nil {
				s.status.DatagramDropped()
			}
		}
	}
}

func (s *Server) acceptTCP(ctx context.Context, listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Error("TCP accept failed", "error", err)
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept TCP: %w", err)
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
	flowID := s.flowID.Add(1)
	outcome := "failed"
	errorCode := "INTERNAL_ERROR"
	sessionID := ""
	var sent, received int64
	defer func() {
		s.logger.Info("The TCP flow completed.", "event.name", "tcp.flow", "flow_id", flowID, "session_id", sessionID, "destination", destination, "bytes.sent", sent, "bytes.received", received, "duration_ms", time.Since(started).Milliseconds(), "outcome", outcome, "error.code", errorCode)
	}()
	ctx, span := otel.Tracer("tailbridge/edge").Start(ctx, "tcp.flow")
	defer span.End()
	span.SetAttributes(attribute.String("network.peer.address", source), attribute.String("server.address", destination))
	addressPort, err := netip.ParseAddrPort(destination)
	if err != nil || !config.Allowed(s.config.AllowedRoutes, addressPort.Addr().Unmap()) {
		errorCode = "DESTINATION_DENIED"
		s.status.Denied()
		_ = client.Close()
		return
	}
	active := s.session.Load()
	if active == nil || active.draining.Load() || !config.Allowed(active.routes, addressPort.Addr().Unmap()) {
		errorCode = "SESSION_UNAVAILABLE"
		_ = client.Close()
		return
	}
	sessionID = active.id
	openContext, cancelOpen := context.WithTimeout(ctx, 10*time.Second)
	defer cancelOpen()
	stream, err := active.connection.OpenStreamSync(openContext)
	if err != nil {
		errorCode = "STREAM_UNAVAILABLE"
		_ = client.Close()
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	_ = stream.SetDeadline(deadline)
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	request := protocol.OpenTCP{FlowID: flowID, Source: source, Destination: destination, DeadlineUnixMS: deadline.UnixMilli(), TraceParent: carrier.Get("traceparent"), TraceState: carrier.Get("tracestate")}
	if err := protocol.WriteFrame(stream, request); err != nil {
		errorCode = "CONTROL_WRITE_FAILED"
		stream.CancelRead(1)
		stream.CancelWrite(1)
		_ = client.Close()
		return
	}
	var result protocol.OpenTCPResult
	err = protocol.ReadFrame(stream, &result)
	if err != nil || !result.Accepted {
		errorCode = "CONTROL_READ_FAILED"
		if err == nil && result.Code != "" {
			errorCode = result.Code
		}
		stream.CancelRead(2)
		stream.CancelWrite(2)
		_ = client.Close()
		return
	}
	_ = stream.SetDeadline(time.Time{})
	s.status.FlowStarted()
	var copyErr error
	sent, received, copyErr = proxy.Bidirectional(client, stream)
	span.SetAttributes(attribute.Int64("network.io.sent", sent), attribute.Int64("network.io.received", received))
	s.status.FlowEnded()
	if copyErr == nil {
		outcome = "success"
		errorCode = ""
	} else {
		errorCode = "COPY_FAILED"
		span.RecordError(copyErr)
	}
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

func randomID() (string, error) {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func (s *Server) closeUDPFlows() {
	s.udpMu.Lock()
	flows := s.udpByID
	s.udpByID = make(map[uint64]*edgeUDPFlow)
	s.udpByKey = make(map[string]*edgeUDPFlow)
	for _, flow := range flows {
		_ = flow.reply.Close()
		s.status.UDPFlowEnded()
	}
	s.udpMu.Unlock()
}

func connectionClosed(connection *quic.Conn) bool {
	select {
	case <-connection.Context().Done():
		return true
	default:
		return false
	}
}

func processStoppedError(message string, err error) error {
	if err == nil {
		return errors.New(message)
	}
	return fmt.Errorf("%s: %w", message, err)
}
