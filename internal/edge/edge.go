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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/config"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/netpolicy"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/protocol"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/proxy"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/reconcile"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/registry"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/status"
	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/transport"
	"github.com/quic-go/quic-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type Server struct {
	config     config.Edge
	logger     *slog.Logger
	status     *status.Server
	registry   map[string]*connectorEntry
	routes     []*connectorEntry
	registryMu sync.RWMutex
	store      *registry.Store
	// session keeps the single-connector test and API surface compatible.
	session     atomic.Pointer[session]
	connections sync.Map
	flowID      atomic.Uint64
	limit       chan struct{}
	udpMu       sync.Mutex
	udpByKey    map[string]*edgeUDPFlow
	udpByID     map[uint64]*edgeUDPFlow
	dnsFlows    int64
	dnsFlowMax  int64
}

type connectorEntry struct {
	target   config.ConnectorTarget
	mu       sync.Mutex
	active   atomic.Pointer[session]
	draining *session
}

type edgeUDPFlow struct {
	id          uint64
	key         string
	session     *session
	source      *net.UDPAddr
	destination netip.AddrPort
	translated  netip.AddrPort
	reply       *net.UDPConn
	lastUsed    time.Time
	sharedReply bool
}

type session struct {
	id            string
	connectorID   string
	slot          int
	started       int64
	connection    *quic.Conn
	draining      atomic.Bool
	routes        []netip.Prefix
	virtualPrefix netip.Prefix
	realPrefix    netip.Prefix
}

type networkPolicy interface {
	Apply(context.Context) error
	Replace(context.Context, []netip.Prefix) error
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
	dnsFlowMax := max(cfg.MaxUDPFlows/8, 64)
	dnsFlowMax = min(dnsFlowMax, cfg.MaxUDPFlows)
	server := &Server{config: cfg, logger: logger, status: state, registry: make(map[string]*connectorEntry), limit: make(chan struct{}, cfg.MaxTCPFlows), udpByKey: make(map[string]*edgeUDPFlow), udpByID: make(map[uint64]*edgeUDPFlow), dnsFlowMax: dnsFlowMax}
	configured := make([]status.Connector, 0, len(cfg.Connectors))
	for _, target := range cfg.Connectors {
		entry := &connectorEntry{target: target}
		server.registry[target.ConnectorID] = entry
		server.routes = append(server.routes, entry)
		configured = append(configured, status.Connector{ConnectorID: target.ConnectorID, Slot: target.Slot, VirtualPrefix: target.VirtualPrefix.String(), RealPrefix: target.RealPrefix.String()})
	}
	state.ConfigureConnectors(configured)
	return server
}

func NewWithStore(ctx context.Context, cfg config.Edge, store *registry.Store, logger *slog.Logger, state *status.Server) (*Server, error) {
	server := New(cfg, logger, state)
	server.store = store
	if err := server.refreshDynamic(ctx); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) refreshDynamic(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	registrations, err := s.store.Active(ctx)
	if err != nil {
		return err
	}
	stats, err := s.store.Stats(ctx)
	if err != nil {
		return err
	}
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	activeKeys := make(map[string]struct{}, len(s.config.Connectors)+len(registrations))
	routes := make([]*connectorEntry, 0, len(s.config.Connectors)+len(registrations))
	for _, target := range s.config.Connectors {
		activeKeys[target.ConnectorID] = struct{}{}
		if entry := s.registry[target.ConnectorID]; entry != nil {
			routes = append(routes, entry)
		}
	}
	for _, registration := range registrations {
		if registration.IdentityType != "dynamic-v3" {
			continue
		}
		routes = slices.DeleteFunc(routes, func(entry *connectorEntry) bool {
			return entry.target.VirtualPrefix == registration.VirtualPrefix
		})
		key := registration.ProjectID + "/" + registration.EnvironmentID
		activeKeys[key] = struct{}{}
		virtualBytes := registration.VirtualPrefix.Addr().As16()
		baseBytes := s.config.VirtualNetwork.Addr().As16()
		target := config.ConnectorTarget{ConnectorID: key, Environment: registration.EnvironmentID, EnvironmentName: registration.EnvironmentName, Slot: int(virtualBytes[1] - baseBytes[1]), VirtualPrefix: registration.VirtualPrefix, RealPrefix: registration.RealPrefix, DNSSuffix: registration.ProjectAlias + "." + registration.EnvironmentAlias + ".railway.internal"}
		entry := s.registry[key]
		if entry == nil || entry.target != target {
			if entry != nil {
				if active := entry.active.Load(); active != nil {
					_ = active.connection.CloseWithError(0, "connector assignment changed")
				}
			}
			entry = &connectorEntry{target: target}
			s.registry[key] = entry
		}
		routes = append(routes, entry)
	}
	for key, entry := range s.registry {
		if _, keep := activeKeys[key]; keep {
			continue
		}
		if active := entry.active.Load(); active != nil {
			_ = active.connection.CloseWithError(0, "connector registration is inactive")
		}
		delete(s.registry, key)
	}
	s.routes = routes
	configured := make([]status.Connector, 0, len(routes))
	for _, entry := range routes {
		configured = append(configured, status.Connector{ConnectorID: entry.target.ConnectorID, Slot: entry.target.Slot, VirtualPrefix: entry.target.VirtualPrefix.String(), RealPrefix: entry.target.RealPrefix.String()})
	}
	s.status.ReconcileConnectors(configured)
	s.status.SetRegistryMetrics(stats)
	return nil
}

type reconciledPolicy struct {
	policy networkPolicy
	server *Server
}

func (p reconciledPolicy) Replace(ctx context.Context, routes []netip.Prefix) error {
	if err := p.policy.Replace(ctx, routes); err != nil {
		return err
	}
	return p.server.refreshDynamic(ctx)
}

func (s *Server) Run(ctx context.Context) error {
	s.status.SetHealthy(false)
	defer s.status.SetHealthy(false)
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
	policyRoutes := s.config.AllowedRoutes
	if len(s.routes) > 0 {
		policyRoutes = make([]netip.Prefix, 0, len(s.routes))
		for _, entry := range s.routes {
			policyRoutes = append(policyRoutes, entry.target.VirtualPrefix)
		}
	}
	policy, err := createPolicy(policyRoutes, s.config.TCPListenAddr, s.config.UDPListenAddr)
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
	var dnsListener *net.UDPConn
	if s.store != nil {
		dnsAddress, err := listenerInterfaceAddress(s.config.DNSListenAddr)
		if err != nil {
			return err
		}
		dnsListener, err = net.ListenUDP("udp", dnsAddress)
		if err != nil {
			return fmt.Errorf("listen for DNS: %w", err)
		}
		defer dnsListener.Close()
	}
	s.status.SetHealthy(true)

	group, groupContext := errgroup.WithContext(runContext)
	group.Go(func() error { return s.acceptConnectors(groupContext, listener) })
	group.Go(func() error { return s.acceptTCP(groupContext, tcpListener) })
	group.Go(func() error { return s.acceptUDP(groupContext, udpListener) })
	if dnsListener != nil {
		group.Go(func() error { return s.acceptDNS(groupContext, dnsListener) })
	}
	if s.store != nil {
		staticRoutes := make([]netip.Prefix, 0, len(s.config.Connectors))
		for _, connector := range s.config.Connectors {
			staticRoutes = append(staticRoutes, connector.VirtualPrefix)
		}
		group.Go(func() error {
			return reconcile.NewRoutes(s.store, reconciledPolicy{policy: policy, server: s}, staticRoutes, s.config.ReconcileInterval, s.config.SlotQuarantine, s.logger, s.status).Run(groupContext)
		})
	}
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
		if dnsListener != nil {
			_ = dnsListener.Close()
		}
		s.registryMu.RLock()
		routes := append([]*connectorEntry(nil), s.routes...)
		s.registryMu.RUnlock()
		for _, entry := range routes {
			if active := entry.active.Load(); active != nil {
				_ = active.connection.CloseWithError(0, "edge shutting down")
			}
			entry.mu.Lock()
			if draining := entry.draining; draining != nil {
				_ = draining.connection.CloseWithError(0, "edge shutting down")
			}
			entry.mu.Unlock()
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
	var connectorID, environment, identityKeyID, softwareVersion string
	var started int64
	var rawRoutes []string
	validProtocol := true
	dynamic := conn.ConnectionState().TLS.NegotiatedProtocol == protocol.ALPNV3
	if dynamic {
		var hello protocol.ConnectorHelloV3
		if err := protocol.ReadFrame(control, &hello); err != nil {
			_ = conn.CloseWithError(2, "The hello frame is not valid.")
			return
		}
		validProtocol = hello.ProtocolVersion == protocol.ProtocolVersionV3
		connectorID = hello.ProjectID + "/" + hello.EnvironmentID
		environment = hello.EnvironmentID
		identityKeyID = hello.IdentityKeyID
		softwareVersion = hello.SoftwareVersion
		started = hello.StartedUnixNano
		rawRoutes = hello.Routes
	} else {
		var hello protocol.ConnectorHello
		if err := protocol.ReadFrame(control, &hello); err != nil {
			_ = conn.CloseWithError(2, "The hello frame is not valid.")
			return
		}
		validProtocol = hello.ProtocolVersion == protocol.ProtocolVersion
		connectorID = hello.ConnectorID
		environment = hello.Environment
		softwareVersion = hello.SoftwareVersion
		started = hello.StartedUnixNano
		rawRoutes = hello.Routes
	}
	s.registryMu.RLock()
	entry := s.registry[connectorID]
	registryCount := len(s.registry)
	s.registryMu.RUnlock()
	if entry == nil && registryCount == 0 && connectorID == s.config.ConnectorID {
		realPrefix := firstIPv6Prefix(s.config.AllowedRoutes)
		entry = &connectorEntry{target: config.ConnectorTarget{ConnectorID: s.config.ConnectorID, Environment: s.config.Environment, VirtualPrefix: realPrefix, RealPrefix: realPrefix}}
	}
	identityErr := error(nil)
	if dynamic {
		projectID, environmentID, certificateKeyID, err := transport.PeerConnectorIdentityV3(conn.ConnectionState().TLS)
		identityErr = err
		if err == nil && (connectorID != projectID+"/"+environmentID || certificateKeyID != identityKeyID) {
			identityErr = errors.New("certificate identity does not match the connector hello")
		}
		if err == nil && s.store != nil && entry != nil {
			registration, lookupErr := s.store.Registration(ctx, projectID, environmentID)
			if lookupErr == nil {
				_, keyErr := s.store.ActiveIdentityKey(ctx, registration.ID, identityKeyID)
				if keyErr != nil {
					identityErr = errors.New("connector identity key is not active")
				}
			} else {
				identityErr = lookupErr
			}
		}
	} else {
		certificateID, err := connectorIdentity(conn)
		identityErr = err
		if err == nil && connectorID != certificateID {
			identityErr = errors.New("certificate identity does not match the connector hello")
		}
	}
	if !validProtocol || entry == nil || identityErr != nil || environment != entry.target.Environment {
		s.status.Denied()
		_ = conn.CloseWithError(3, "The edge rejected the connector identity.")
		return
	}
	if started <= 0 || started > time.Now().Add(5*time.Minute).UnixNano() {
		s.status.Denied()
		_ = conn.CloseWithError(3, "The connector start time is not valid.")
		return
	}
	advertised := make([]netip.Prefix, 0, len(rawRoutes))
	for _, raw := range rawRoutes {
		route, err := netip.ParsePrefix(raw)
		if err != nil {
			s.status.Denied()
			_ = conn.CloseWithError(3, "The connector routes are not valid.")
			return
		}
		advertised = append(advertised, route.Masked())
	}
	realRoutes := []netip.Prefix{entry.target.RealPrefix}
	if registryCount == 0 {
		realRoutes = s.config.AllowedRoutes
	}
	acceptedRoutes := config.IntersectPrefixes(realRoutes, advertised)
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
	next := &session{id: id, connectorID: entry.target.ConnectorID, slot: entry.target.Slot, started: started, connection: conn, routes: acceptedRoutes, virtualPrefix: entry.target.VirtualPrefix, realPrefix: entry.target.RealPrefix}
	entry.mu.Lock()
	previous := entry.active.Load()
	if previous == nil && registryCount == 0 {
		previous = s.session.Load()
	}
	if previous != nil && !connectionClosed(previous.connection) && next.started <= previous.started {
		entry.mu.Unlock()
		_ = conn.CloseWithError(5, "newer connector session is active")
		s.logger.Info("connector session superseded", "event.name", "connector.session", "connector_id", connectorID, "slot", entry.target.Slot, "version", softwareVersion)
		return
	}
	if err := protocol.WriteFrame(control, protocol.ConnectorAccepted{SessionID: id, ConnectorID: connectorID, Slot: entry.target.Slot, VirtualPrefix: entry.target.VirtualPrefix.String(), RealPrefix: entry.target.RealPrefix.String(), Routes: routes, MaxTCPFlows: s.config.MaxTCPFlows}); err != nil {
		entry.mu.Unlock()
		_ = conn.CloseWithError(4, "The edge could not send the hello response.")
		return
	}
	_ = control.SetDeadline(time.Time{})
	entry.active.Store(next)
	staleDraining := entry.draining
	if previous != nil {
		previous.draining.Store(true)
		entry.draining = previous
	}
	if registryCount == 0 || registryCount == 1 {
		s.session.Store(next)
	}
	entry.mu.Unlock()
	if staleDraining != nil && staleDraining != previous {
		_ = staleDraining.connection.CloseWithError(0, "A newer draining session replaced this session.")
	}
	s.status.ConnectorReady(connectorID, id)
	if registryCount == 0 {
		s.status.SetReady(true)
	}
	if registryCount == 0 {
		go s.status.ObserveQUIC(conn.Context().Done(), conn)
	} else {
		go s.status.ObserveConnectorQUIC(connectorID, conn.Context().Done(), conn)
	}
	s.logger.Info("connector session ready", "event.name", "connector.session", "session_id", id, "connector_id", connectorID, "slot", entry.target.Slot, "version", softwareVersion)
	if dynamic && s.store != nil {
		projectID := strings.SplitN(connectorID, "/", 2)[0]
		_ = s.store.MarkReady(ctx, projectID, environment)
		if registration, err := s.store.Registration(ctx, projectID, environment); err == nil {
			_ = s.store.CompleteIdentityRotation(ctx, registration.ID, identityKeyID, 24*time.Hour)
		}
	}
	go s.receiveUDP(next)
	if previous != nil {
		go func() {
			timer := time.NewTimer(15 * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
				_ = previous.connection.CloseWithError(0, "The deployment drain is complete.")
			}
			entry.mu.Lock()
			if entry.draining == previous {
				entry.draining = nil
			}
			entry.mu.Unlock()
		}()
	}
	<-conn.Context().Done()
	if entry.active.CompareAndSwap(next, nil) {
		s.session.CompareAndSwap(next, nil)
		s.status.ConnectorClosed(connectorID, id)
		if registryCount == 0 {
			s.status.SetReady(false)
		}
	}
	s.logger.Info("connector session closed", "event.name", "connector.session", "session_id", id, "connector_id", connectorID, "slot", entry.target.Slot, "outcome", "closed")
}

func connectorIdentity(conn *quic.Conn) (string, error) {
	return transport.PeerIdentity(conn.ConnectionState().TLS, "connector")
}

func firstIPv6Prefix(prefixes []netip.Prefix) netip.Prefix {
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() {
			return prefix.Masked()
		}
	}
	return netip.Prefix{}
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
		if err != nil {
			s.status.Denied()
			s.status.DatagramDropped()
			continue
		}
		active, translated, ok := s.route(destination)
		if !ok {
			s.status.Denied()
			s.status.DatagramDropped()
			continue
		}
		sourceAddr := source.AddrPort()
		key := active.id + "|" + sourceAddr.String() + "|" + destination.String()
		flow, err := s.edgeUDPFlowTranslated(active, key, source, destination, translated)
		if err != nil {
			s.status.DatagramDropped()
			continue
		}
		packet, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: flow.id, Source: sourceAddr, Destination: translated, Payload: buffer[:n]})
		if err == nil {
			if err := active.connection.SendDatagram(packet); err != nil {
				s.status.DatagramDropped()
			}
		} else {
			s.status.DatagramDropped()
		}
	}
}

func (s *Server) acceptDNS(ctx context.Context, listener *net.UDPConn) error {
	buffer := make([]byte, 64*1024)
	for {
		n, source, err := listener.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("receive DNS query: %w", err)
		}
		payload := append([]byte(nil), buffer[:n]...)
		go s.forwardDNS(ctx, listener, source, payload)
	}
}

func (s *Server) forwardDNS(ctx context.Context, listener *net.UDPConn, source *net.UDPAddr, payload []byte) {
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil || len(message.Question) == 0 {
		return
	}
	labels := dns.SplitDomainName(message.Question[0].Name)
	if len(labels) < 5 || !strings.EqualFold(labels[len(labels)-2], "railway") || !strings.EqualFold(labels[len(labels)-1], "internal") {
		s.writeDNSError(listener, source, message, dns.RcodeNameError)
		return
	}
	projectAlias := strings.ToLower(labels[len(labels)-4])
	environmentAlias := strings.ToLower(labels[len(labels)-3])
	registration, err := s.store.RegistrationByAlias(ctx, projectAlias, environmentAlias)
	if errors.Is(err, registry.ErrNotFound) {
		s.writeDNSError(listener, source, message, dns.RcodeNameError)
		return
	}
	if err != nil {
		s.writeDNSError(listener, source, message, dns.RcodeServerFailure)
		return
	}
	address := registration.VirtualPrefix.Addr().As16()
	address[15] = 0x10
	destination := netip.AddrPortFrom(netip.AddrFrom16(address), 53)
	active, translated, ok := s.route(destination)
	if !ok {
		s.writeDNSError(listener, source, message, dns.RcodeServerFailure)
		return
	}
	key := active.id + "|dns|" + source.AddrPort().String() + "|" + destination.String()
	flow, err := s.edgeUDPFlowWithReply(active, key, source, destination, translated, listener, true)
	if err != nil {
		s.writeDNSError(listener, source, message, dns.RcodeServerFailure)
		return
	}
	packet, err := protocol.EncodeUDP(protocol.UDPDatagram{FlowID: flow.id, Source: source.AddrPort(), Destination: translated, Payload: payload})
	if err != nil || active.connection.SendDatagram(packet) != nil {
		s.writeDNSError(listener, source, message, dns.RcodeServerFailure)
	}
}

func (s *Server) writeDNSError(listener *net.UDPConn, source *net.UDPAddr, query *dns.Msg, code int) {
	response := new(dns.Msg)
	response.SetRcode(query, code)
	payload, err := response.Pack()
	if err == nil {
		_, _ = listener.WriteToUDP(payload, source)
	}
}

func listenerInterfaceAddress(value string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return nil, fmt.Errorf("listener address %q is not valid: %w", value, err)
	}
	if host == "" || strings.Contains(host, ".") || strings.Contains(host, ":") {
		return net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	}
	device, err := net.InterfaceByName(host)
	if err != nil {
		return nil, fmt.Errorf("find listener interface %q: %w", host, err)
	}
	addresses, err := device.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() {
			return net.ResolveUDPAddr("udp", net.JoinHostPort(prefix.Addr().String(), port))
		}
	}
	return nil, fmt.Errorf("interface %q has no IPv4 address", host)
}

func (s *Server) edgeUDPFlow(active *session, key string, source *net.UDPAddr, destination netip.AddrPort) (*edgeUDPFlow, error) {
	return s.edgeUDPFlowTranslated(active, key, source, destination, destination)
}

func (s *Server) edgeUDPFlowTranslated(active *session, key string, source *net.UDPAddr, destination, translated netip.AddrPort) (*edgeUDPFlow, error) {
	return s.edgeUDPFlowWithReply(active, key, source, destination, translated, nil, false)
}

func (s *Server) edgeUDPFlowWithReply(active *session, key string, source *net.UDPAddr, destination, translated netip.AddrPort, reply *net.UDPConn, shared bool) (*edgeUDPFlow, error) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if flow := s.udpByKey[key]; flow != nil {
		flow.lastUsed = time.Now()
		return flow, nil
	}
	if int64(len(s.udpByID)) >= s.config.MaxUDPFlows {
		return nil, errors.New("the UDP flow limit is full")
	}
	if shared && s.dnsFlows >= s.dnsFlowMax {
		return nil, errors.New("the DNS flow limit is full")
	}
	if reply == nil {
		var err error
		reply, err = openUDPResponse(destination)
		if err != nil {
			return nil, err
		}
	}
	flow := &edgeUDPFlow{id: s.flowID.Add(1), key: key, session: active, source: source, destination: destination, translated: translated, reply: reply, sharedReply: shared, lastUsed: time.Now()}
	s.udpByKey[key] = flow
	s.udpByID[flow.id] = flow
	if shared {
		s.dnsFlows++
	}
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
				if flow.sharedReply {
					s.dnsFlows--
				}
				if !flow.sharedReply {
					_ = flow.reply.Close()
				}
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
	defer s.closeUDPSession(active)
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
		wantSource := netip.AddrPort{}
		if flow != nil {
			wantSource = flow.translated
			if !wantSource.IsValid() {
				wantSource = flow.destination
			}
		}
		if flow != nil && flow.session == active && packet.Source == wantSource && packet.Destination == flow.source.AddrPort() {
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

func (s *Server) closeUDPSession(active *session) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	for id, flow := range s.udpByID {
		if flow.session != active {
			continue
		}
		delete(s.udpByID, id)
		delete(s.udpByKey, flow.key)
		if flow.sharedReply {
			s.dnsFlows--
		}
		if !flow.sharedReply {
			_ = flow.reply.Close()
		}
		s.status.UDPFlowEnded()
	}
}

func (s *Server) route(destination netip.AddrPort) (*session, netip.AddrPort, bool) {
	s.registryMu.RLock()
	routes := append([]*connectorEntry(nil), s.routes...)
	s.registryMu.RUnlock()
	for _, entry := range routes {
		if !entry.target.VirtualPrefix.Contains(destination.Addr().Unmap()) {
			continue
		}
		active := entry.active.Load()
		if active == nil || active.draining.Load() {
			return nil, netip.AddrPort{}, false
		}
		translated, err := translateAddrPort(destination, entry.target.VirtualPrefix, entry.target.RealPrefix)
		if err != nil || !config.Allowed(active.routes, translated.Addr()) {
			return nil, netip.AddrPort{}, false
		}
		return active, translated, true
	}
	if len(routes) != 0 {
		return nil, netip.AddrPort{}, false
	}
	active := s.session.Load()
	if active == nil || active.draining.Load() || !config.Allowed(active.routes, destination.Addr().Unmap()) {
		return nil, netip.AddrPort{}, false
	}
	return active, destination, true
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
	connectorID := ""
	slot := -1
	translatedDestination := ""
	var sent, received int64
	defer func() {
		s.logger.Info("The TCP flow completed.", "event.name", "tcp.flow", "flow_id", flowID, "connector_id", connectorID, "slot", slot, "session_id", sessionID, "virtual_destination", destination, "translated_destination", translatedDestination, "bytes_sent", sent, "bytes_received", received, "duration_ms", time.Since(started).Milliseconds(), "outcome", outcome, "error_code", errorCode)
	}()
	ctx, span := otel.Tracer("tailbridge/edge").Start(ctx, "tcp.flow")
	defer span.End()
	span.SetAttributes(attribute.String("network.peer.address", source), attribute.String("server.address", destination))
	addressPort, err := netip.ParseAddrPort(destination)
	if err != nil {
		errorCode = "DESTINATION_DENIED"
		s.status.Denied()
		_ = client.Close()
		return
	}
	active, translated, ok := s.route(addressPort)
	if !ok {
		errorCode = "SESSION_UNAVAILABLE"
		s.status.Denied()
		_ = client.Close()
		return
	}
	sessionID = active.id
	connectorID = active.connectorID
	slot = active.slot
	translatedDestination = translated.String()
	span.SetAttributes(
		attribute.String("tailbridge.connector.id", connectorID),
		attribute.Int("tailbridge.connector.slot", slot),
		attribute.String("tailbridge.session.id", sessionID),
		attribute.String("tailbridge.destination.virtual", destination),
		attribute.String("tailbridge.destination.translated", translatedDestination),
	)
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
	request := protocol.OpenTCP{FlowID: flowID, Source: source, Destination: translated.String(), DeadlineUnixMS: deadline.UnixMilli(), TraceParent: carrier.Get("traceparent"), TraceState: carrier.Get("tracestate")}
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
	s.dnsFlows = 0
	for _, flow := range flows {
		if !flow.sharedReply {
			_ = flow.reply.Close()
		}
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
