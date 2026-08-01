package connector

import (
	"context"
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
	udpMu   sync.Mutex
	udp     map[uint64]*udpFlow
}

type udpFlow struct {
	connection  *net.UDPConn
	source      netip.AddrPort
	destination netip.AddrPort
	lastUsed    time.Time
}

func New(cfg config.Connector, logger *slog.Logger, state *status.Server, version string) *Client {
	return &Client{config: cfg, logger: logger, status: state, version: version, started: time.Now().UnixNano(), udp: make(map[uint64]*udpFlow)}
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
			c.logger.Error("edge connection failed", "event.name", "connector.connect", "error", err, "retry_ms", delay.Milliseconds())
			if !wait(ctx, jitter(delay)) {
				break
			}
			delay = min(time.Duration(float64(delay)*1.7), c.config.ReconnectMax)
			continue
		}
		sessionStarted := time.Now()
		if err := c.serve(ctx, conn); err != nil && ctx.Err() == nil {
			c.logger.Error("connector session failed", "event.name", "connector.session", "error", err)
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
	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
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
	c.status.SetReady(true)
	go c.status.ObserveQUIC(conn.Context().Done(), conn)
	c.logger.Info("edge session ready", "event.name", "connector.session", "session_id", accepted.SessionID, "connector.id", c.config.ConnectorID)
	go c.receiveUDP(conn)
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go c.handleTCP(stream, accepted.SessionID)
	}
}

func (c *Client) receiveUDP(conn *quic.Conn) {
	for {
		data, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		packet, err := protocol.DecodeUDP(data)
		if err != nil || packet.Response || !config.Allowed(c.config.AllowedDestinations, packet.Destination.Addr().Unmap()) {
			c.status.Denied()
			continue
		}
		flow, err := c.udpFlow(conn, packet)
		if err != nil {
			continue
		}
		c.udpMu.Lock()
		flow.lastUsed = time.Now()
		c.udpMu.Unlock()
		_, _ = flow.connection.Write(packet.Payload)
	}
}

func (c *Client) udpFlow(session *quic.Conn, packet protocol.UDPDatagram) (*udpFlow, error) {
	c.udpMu.Lock()
	if flow := c.udp[packet.FlowID]; flow != nil {
		c.udpMu.Unlock()
		return flow, nil
	}
	c.udpMu.Unlock()
	destination := net.UDPAddrFromAddrPort(packet.Destination)
	connection, err := net.DialUDP("udp", nil, destination)
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{connection: connection, source: packet.Source, destination: packet.Destination, lastUsed: time.Now()}
	c.udpMu.Lock()
	c.udp[packet.FlowID] = flow
	c.udpMu.Unlock()
	go c.readUDPResponses(session, packet.FlowID, flow)
	return flow, nil
}

func (c *Client) readUDPResponses(session *quic.Conn, flowID uint64, flow *udpFlow) {
	defer func() {
		_ = flow.connection.Close()
		c.udpMu.Lock()
		delete(c.udp, flowID)
		c.udpMu.Unlock()
	}()
	buffer := make([]byte, 64*1024)
	for {
		_ = flow.connection.SetReadDeadline(time.Now().Add(c.config.UDPIdleTimeout))
		n, err := flow.connection.Read(buffer)
		if err != nil {
			return
		}
		packet, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: flowID, Response: true, Source: flow.destination, Destination: flow.source, Payload: buffer[:n]})
		if err != nil || session.SendDatagram(packet) != nil {
			return
		}
	}
}

func (c *Client) handleTCP(stream *quic.Stream, sessionID string) {
	started := time.Now()
	var request protocol.OpenTCP
	if err := protocol.ReadFrame(stream, &request); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return
	}
	carrier := propagation.MapCarrier{"traceparent": request.TraceParent, "tracestate": request.TraceState}
	ctx := otel.GetTextMapPropagator().Extract(context.Background(), carrier)
	ctx, span := otel.Tracer("tailbridge/connector").Start(ctx, "tcp.connect")
	defer span.End()
	span.SetAttributes(attribute.String("server.address", request.Destination), attribute.String("tailbridge.session.id", sessionID))
	destination, err := netip.ParseAddrPort(request.Destination)
	if err != nil || !config.Allowed(c.config.AllowedDestinations, destination.Addr().Unmap()) {
		c.status.Denied()
		_ = protocol.WriteFrame(stream, protocol.OpenTCPResult{Accepted: false, Code: "DESTINATION_DENIED"})
		_ = stream.Close()
		return
	}
	dialer := net.Dialer{Timeout: c.config.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", request.Destination)
	if err != nil {
		_ = protocol.WriteFrame(stream, protocol.OpenTCPResult{Accepted: false, Code: "DESTINATION_UNREACHABLE"})
		_ = stream.Close()
		return
	}
	if err := protocol.WriteFrame(stream, protocol.OpenTCPResult{Accepted: true}); err != nil {
		_ = upstream.Close()
		return
	}
	c.status.FlowStarted()
	sent, received := proxy.Bidirectional(stream, upstream)
	span.SetAttributes(attribute.Int64("network.io.sent", sent), attribute.Int64("network.io.received", received))
	c.status.FlowEnded()
	c.logger.Info("TCP flow complete", "event.name", "tcp.flow", "flow_id", request.FlowID, "session_id", sessionID, "destination", request.Destination, "bytes.sent", sent, "bytes.received", received, "duration_ms", time.Since(started).Milliseconds(), "outcome", "success")
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
