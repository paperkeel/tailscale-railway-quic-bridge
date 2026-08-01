package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/config"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/proxy"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/status"
	"github.com/bearfire-dev/tailscale-railway-quic-bridge/internal/transport"
	"github.com/quic-go/quic-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

type Client struct {
	config  config.Connector
	logger  *slog.Logger
	status  *status.Server
	version string
	started int64
}

type udpFlow struct {
	connection  *net.UDPConn
	source      netip.AddrPort
	destination netip.AddrPort
}

type udpSession struct {
	client     *Client
	connection *quic.Conn
	routes     []netip.Prefix
	mu         sync.Mutex
	flows      map[uint64]*udpFlow
	closed     bool
}

const maxUDPPayload = 8 * 1024

func New(cfg config.Connector, logger *slog.Logger, state *status.Server, version string) *Client {
	return &Client{config: cfg, logger: logger, status: state, version: version, started: time.Now().UnixNano()}
}

func (c *Client) Run(ctx context.Context) error {
	tlsConfig, err := transport.ClientTLS(c.config.Common)
	if err != nil {
		return fmt.Errorf("configure TLS: %w", err)
	}
	delay := c.config.ReconnectMin
	for ctx.Err() == nil {
		conn, err := quic.DialAddr(ctx, c.config.EdgeEndpoint, tlsConfig, transport.QUICConfig(c.config.MaxTCPFlows))
		if err != nil {
			c.logger.Error("The connector could not connect to the edge.", "event.name", "connector.connect", "error", err, "retry_ms", delay.Milliseconds())
			if !wait(ctx, jitter(delay)) {
				break
			}
			delay = min(time.Duration(float64(delay)*1.7), c.config.ReconnectMax)
			continue
		}
		sessionStarted := time.Now()
		serveErr := c.serve(ctx, conn)
		_ = conn.CloseWithError(0, "The connector session ended.")
		if serveErr != nil && ctx.Err() == nil {
			c.logger.Error("connector session failed", "event.name", "connector.session", "error", serveErr)
		}
		c.status.SetReady(false)
		if time.Since(sessionStarted) >= c.config.ReconnectMax {
			delay = c.config.ReconnectMin
			continue
		}
		if !wait(ctx, jitter(delay)) {
			break
		}
		delay = min(time.Duration(float64(delay)*1.7), c.config.ReconnectMax)
	}
	return ctx.Err()
}

func (c *Client) serve(ctx context.Context, conn *quic.Conn) error {
	handshakeContext, cancelHandshake := context.WithTimeout(ctx, 10*time.Second)
	defer cancelHandshake()
	control, err := conn.OpenStreamSync(handshakeContext)
	if err != nil {
		return err
	}
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	routes := make([]string, 0, len(c.config.AllowedDestinations))
	for _, route := range c.config.AllowedDestinations {
		routes = append(routes, route.String())
	}
	hello := protocol.ConnectorHello{ProtocolVersion: protocol.ProtocolVersion, ConnectorID: c.config.ConnectorID, Environment: c.config.Environment, Routes: routes, SoftwareVersion: c.version, StartedUnixNano: c.started}
	if err := protocol.WriteFrame(control, hello); err != nil {
		return err
	}
	var accepted protocol.ConnectorAccepted
	if err := protocol.ReadFrame(control, &accepted); err != nil {
		return err
	}
	_ = control.SetDeadline(time.Time{})
	if accepted.SessionID == "" || accepted.MaxTCPFlows < 1 {
		return errors.New("the edge returned an invalid session response")
	}
	acceptedRoutes, err := config.ValidateAcceptedRoutes(accepted.Routes, c.config.AllowedDestinations)
	if err != nil {
		return fmt.Errorf("validate accepted routes: %w", err)
	}
	c.status.SetReady(true)
	go c.status.ObserveQUIC(conn.Context().Done(), conn)
	c.logger.Info("edge session ready", "event.name", "connector.session", "session_id", accepted.SessionID, "connector.id", c.config.ConnectorID)
	udp := &udpSession{client: c, connection: conn, routes: acceptedRoutes, flows: make(map[uint64]*udpFlow)}
	defer udp.close()
	go udp.receive()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go c.handleTCP(stream, accepted.SessionID, acceptedRoutes)
	}
}

func (s *udpSession) receive() {
	for {
		data, err := s.connection.ReceiveDatagram(s.connection.Context())
		if err != nil {
			return
		}
		packet, err := protocol.DecodeUDP(data)
		if err != nil || packet.Response {
			s.client.status.DatagramDropped()
			continue
		}
		if !config.Allowed(s.routes, packet.Destination.Addr().Unmap()) {
			s.client.status.Denied()
			s.client.status.DatagramDropped()
			continue
		}
		flow, err := s.flow(packet)
		if err != nil {
			s.client.status.DatagramDropped()
			continue
		}
		_ = flow.connection.SetReadDeadline(time.Now().Add(s.client.config.UDPIdleTimeout))
		if _, err := flow.connection.Write(packet.Payload); err != nil {
			s.client.status.DatagramDropped()
		}
	}
}

func (s *udpSession) flow(packet protocol.UDPDatagram) (*udpFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("the UDP session is closed")
	}
	if flow := s.flows[packet.FlowID]; flow != nil {
		if flow.source != packet.Source || flow.destination != packet.Destination {
			return nil, errors.New("the UDP flow endpoints changed")
		}
		return flow, nil
	}
	if int64(len(s.flows)) >= s.client.config.MaxUDPFlows {
		return nil, errors.New("the UDP flow limit is full")
	}
	destination := net.UDPAddrFromAddrPort(packet.Destination)
	connection, err := net.DialUDP("udp", nil, destination)
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{connection: connection, source: packet.Source, destination: packet.Destination}
	s.flows[packet.FlowID] = flow
	s.client.status.UDPFlowStarted()
	go s.readResponses(packet.FlowID, flow)
	return flow, nil
}

func (s *udpSession) readResponses(flowID uint64, flow *udpFlow) {
	defer func() {
		_ = flow.connection.Close()
		s.mu.Lock()
		if s.flows[flowID] == flow {
			delete(s.flows, flowID)
			s.client.status.UDPFlowEnded()
		}
		s.mu.Unlock()
	}()
	buffer := make([]byte, maxUDPPayload)
	for {
		_ = flow.connection.SetReadDeadline(time.Now().Add(s.client.config.UDPIdleTimeout))
		n, err := flow.connection.Read(buffer)
		if err != nil {
			return
		}
		packet, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: flowID, Response: true, Source: flow.destination, Destination: flow.source, Payload: buffer[:n]})
		if err != nil {
			s.client.status.DatagramDropped()
			return
		}
		if err := s.connection.SendDatagram(packet); err != nil {
			s.client.status.DatagramDropped()
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				continue
			}
			return
		}
	}
}

func (s *udpSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	flows := s.flows
	s.flows = make(map[uint64]*udpFlow)
	for _, flow := range flows {
		_ = flow.connection.Close()
		s.client.status.UDPFlowEnded()
	}
	s.mu.Unlock()
}

func (c *Client) handleTCP(stream *quic.Stream, sessionID string, routes []netip.Prefix) {
	started := time.Now()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	var request protocol.OpenTCP
	if err := protocol.ReadFrame(stream, &request); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return
	}
	outcome := "failed"
	errorCode := "INTERNAL_ERROR"
	var sent, received int64
	defer func() {
		c.logger.Info("The TCP flow completed.", "event.name", "tcp.flow", "flow_id", request.FlowID, "session_id", sessionID, "destination", request.Destination, "bytes.sent", sent, "bytes.received", received, "duration_ms", time.Since(started).Milliseconds(), "outcome", outcome, "error.code", errorCode)
	}()
	carrier := propagation.MapCarrier{"traceparent": request.TraceParent, "tracestate": request.TraceState}
	ctx := otel.GetTextMapPropagator().Extract(context.Background(), carrier)
	ctx, span := otel.Tracer("tailbridge/connector").Start(ctx, "tcp.connect")
	defer span.End()
	span.SetAttributes(attribute.String("server.address", request.Destination), attribute.String("tailbridge.session.id", sessionID))
	destination, err := netip.ParseAddrPort(request.Destination)
	if err != nil || !config.Allowed(routes, destination.Addr().Unmap()) {
		errorCode = "DESTINATION_DENIED"
		c.status.Denied()
		_ = protocol.WriteFrame(stream, protocol.OpenTCPResult{Accepted: false, Code: "DESTINATION_DENIED"})
		_ = stream.Close()
		return
	}
	deadline := time.UnixMilli(request.DeadlineUnixMS)
	if request.DeadlineUnixMS <= 0 || !deadline.After(time.Now()) {
		errorCode = "DEADLINE_EXCEEDED"
		_ = protocol.WriteFrame(stream, protocol.OpenTCPResult{Accepted: false, Code: "DEADLINE_EXCEEDED"})
		_ = stream.Close()
		return
	}
	if maximum := time.Now().Add(c.config.DialTimeout); deadline.After(maximum) {
		deadline = maximum
	}
	_ = stream.SetDeadline(deadline)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	dialer := net.Dialer{Timeout: c.config.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", request.Destination)
	if err != nil {
		code := "DESTINATION_UNREACHABLE"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "DEADLINE_EXCEEDED"
		}
		errorCode = code
		_ = stream.SetWriteDeadline(time.Now().Add(time.Second))
		_ = protocol.WriteFrame(stream, protocol.OpenTCPResult{Accepted: false, Code: code})
		_ = stream.Close()
		return
	}
	if err := protocol.WriteFrame(stream, protocol.OpenTCPResult{Accepted: true}); err != nil {
		_ = upstream.Close()
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return
	}
	_ = stream.SetDeadline(time.Time{})
	c.status.FlowStarted()
	var copyErr error
	sent, received, copyErr = proxy.Bidirectional(stream, upstream)
	span.SetAttributes(attribute.Int64("network.io.sent", sent), attribute.Int64("network.io.received", received))
	c.status.FlowEnded()
	if copyErr == nil {
		outcome = "success"
		errorCode = ""
	} else {
		errorCode = "COPY_FAILED"
		span.RecordError(copyErr)
	}
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func jitter(duration time.Duration) time.Duration {
	factor := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(duration) * factor)
}
