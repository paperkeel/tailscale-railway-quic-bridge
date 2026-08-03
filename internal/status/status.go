package status

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type Server struct {
	healthy      atomic.Bool
	ready        atomic.Bool
	connectorsMu sync.RWMutex
	connectors   map[string]Connector
	active       atomic.Int64
	flows        atomic.Uint64
	udpActive    atomic.Int64
	udpFlows     atomic.Uint64
	udpDropped   atomic.Uint64
	denied       atomic.Uint64
	quicRTT      atomic.Int64
	quicSent     atomic.Uint64
	quicReceived atomic.Uint64
	quicLost     atomic.Uint64
	quicSendRate atomic.Uint64
	quicRecvRate atomic.Uint64
	quicMu       sync.Mutex
	quicObserver uint64
	version      string
}

type Connector struct {
	ConnectorID   string `json:"connector_id"`
	Slot          int    `json:"slot"`
	VirtualPrefix string `json:"virtual_prefix"`
	RealPrefix    string `json:"real_prefix"`
	Ready         bool   `json:"ready"`
	SessionID     string `json:"session_id,omitempty"`
}

type Snapshot struct {
	Version              string      `json:"version"`
	Healthy              bool        `json:"healthy"`
	Ready                bool        `json:"ready"`
	ConfiguredConnectors int         `json:"configured_connectors"`
	ReadyConnectors      int         `json:"ready_connectors"`
	Connectors           []Connector `json:"connectors"`
}

func New(version string) *Server {
	server := &Server{version: version, connectors: make(map[string]Connector)}
	server.healthy.Store(true)
	return server
}
func (s *Server) SetHealthy(value bool) { s.healthy.Store(value) }
func (s *Server) SetReady(value bool)   { s.ready.Store(value) }
func (s *Server) FlowStarted()          { s.active.Add(1); s.flows.Add(1) }
func (s *Server) FlowEnded()            { s.active.Add(-1) }
func (s *Server) UDPFlowStarted()       { s.udpActive.Add(1); s.udpFlows.Add(1) }
func (s *Server) UDPFlowEnded()         { s.udpActive.Add(-1) }
func (s *Server) DatagramDropped()      { s.udpDropped.Add(1) }
func (s *Server) Denied()               { s.denied.Add(1) }

func (s *Server) ConfigureConnectors(connectors []Connector) {
	s.connectorsMu.Lock()
	s.connectors = make(map[string]Connector, len(connectors))
	for _, connector := range connectors {
		connector.Ready = false
		connector.SessionID = ""
		s.connectors[connector.ConnectorID] = connector
	}
	s.connectorsMu.Unlock()
	s.updateReady()
}

func (s *Server) ConnectorReady(connectorID, sessionID string) {
	s.connectorsMu.Lock()
	connector, ok := s.connectors[connectorID]
	if ok {
		connector.Ready = true
		connector.SessionID = sessionID
		s.connectors[connectorID] = connector
	}
	s.connectorsMu.Unlock()
	s.updateReady()
}

func (s *Server) ConnectorClosed(connectorID, sessionID string) {
	s.connectorsMu.Lock()
	connector, ok := s.connectors[connectorID]
	if ok && connector.SessionID == sessionID {
		connector.Ready = false
		connector.SessionID = ""
		s.connectors[connectorID] = connector
	}
	s.connectorsMu.Unlock()
	s.updateReady()
}

func (s *Server) Snapshot() Snapshot {
	s.connectorsMu.RLock()
	connectors := make([]Connector, 0, len(s.connectors))
	ready := 0
	for _, connector := range s.connectors {
		connectors = append(connectors, connector)
		if connector.Ready {
			ready++
		}
	}
	s.connectorsMu.RUnlock()
	slices.SortFunc(connectors, func(left, right Connector) int { return cmp.Compare(left.Slot, right.Slot) })
	allReady := s.ready.Load()
	if len(connectors) > 0 {
		allReady = ready == len(connectors)
	}
	return Snapshot{Version: s.version, Healthy: s.healthy.Load(), Ready: allReady, ConfiguredConnectors: len(connectors), ReadyConnectors: ready, Connectors: connectors}
}

func (s *Server) updateReady() {
	if snapshot := s.Snapshot(); snapshot.ConfiguredConnectors > 0 {
		s.ready.Store(snapshot.Ready)
	}
}

type Listener struct {
	listener net.Listener
	server   *http.Server
}

func (l *Listener) Close() error {
	return l.listener.Close()
}

func (s *Server) ObserveQUIC(ctxDone <-chan struct{}, connection *quic.Conn) {
	s.quicMu.Lock()
	s.quicObserver++
	observer := s.quicObserver
	s.resetQUICMetrics()
	s.quicMu.Unlock()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var previous quic.ConnectionStats
	var previousAt time.Time
	defer func() {
		s.quicMu.Lock()
		if s.quicObserver == observer {
			s.quicObserver++
			s.resetQUICMetrics()
		}
		s.quicMu.Unlock()
	}()
	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			stats := connection.ConnectionStats()
			now := time.Now()
			var sendRate, receiveRate uint64
			if !previousAt.IsZero() {
				sendRate = bitsPerSecond(stats.BytesSent, previous.BytesSent, now.Sub(previousAt))
				receiveRate = bitsPerSecond(stats.BytesReceived, previous.BytesReceived, now.Sub(previousAt))
			}
			if !s.storeQUICSample(observer, stats, sendRate, receiveRate) {
				return
			}
			previous = stats
			previousAt = now
		}
	}
}

func (s *Server) storeQUICStats(observer uint64, stats quic.ConnectionStats) bool {
	return s.storeQUICSample(observer, stats, 0, 0)
}

func (s *Server) storeQUICSample(observer uint64, stats quic.ConnectionStats, sendRate, receiveRate uint64) bool {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()
	if s.quicObserver != observer {
		return false
	}
	s.quicRTT.Store(stats.SmoothedRTT.Microseconds())
	s.quicSent.Store(stats.BytesSent)
	s.quicReceived.Store(stats.BytesReceived)
	s.quicLost.Store(stats.BytesLost)
	s.quicSendRate.Store(sendRate)
	s.quicRecvRate.Store(receiveRate)
	return true
}

func bitsPerSecond(current, previous uint64, elapsed time.Duration) uint64 {
	if current < previous || elapsed <= 0 {
		return 0
	}
	return uint64(float64(current-previous) * 8 / elapsed.Seconds())
}

func (s *Server) resetQUICMetrics() {
	s.quicRTT.Store(0)
	s.quicSent.Store(0)
	s.quicReceived.Store(0)
	s.quicLost.Store(0)
	s.quicSendRate.Store(0)
	s.quicRecvRate.Store(0)
}

func (s *Server) Listen(addr string) (*Listener, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		if !s.healthy.Load() {
			http.Error(w, "Tailbridge is not healthy.", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/readyz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "Tailbridge is not ready.", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/version", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": s.version})
	}))
	mux.HandleFunc("/status", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Snapshot())
	}))
	mux.HandleFunc("/metrics", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		ready := 0
		if s.ready.Load() {
			ready = 1
		}
		snapshot := s.Snapshot()
		_, _ = fmt.Fprintf(w, `# HELP tailbridge_ready Whether Tailbridge is ready to serve traffic.
# TYPE tailbridge_ready gauge
tailbridge_ready %d
# HELP tailbridge_connectors_configured Configured connector count.
# TYPE tailbridge_connectors_configured gauge
tailbridge_connectors_configured %d
# HELP tailbridge_connectors_ready Ready connector count.
# TYPE tailbridge_connectors_ready gauge
tailbridge_connectors_ready %d
# HELP tailbridge_connector_ready Whether a configured connector is ready.
# TYPE tailbridge_connector_ready gauge
# HELP tailbridge_tcp_flows_active Current active TCP flows.
# TYPE tailbridge_tcp_flows_active gauge
tailbridge_tcp_flows_active %d
# HELP tailbridge_tcp_flows_total Total TCP flows.
# TYPE tailbridge_tcp_flows_total counter
tailbridge_tcp_flows_total %d
# HELP tailbridge_udp_flows_active Current active UDP flows.
# TYPE tailbridge_udp_flows_active gauge
tailbridge_udp_flows_active %d
# HELP tailbridge_udp_flows_total Total UDP flows.
# TYPE tailbridge_udp_flows_total counter
tailbridge_udp_flows_total %d
# HELP tailbridge_udp_datagrams_dropped_total Total UDP datagrams that Tailbridge dropped.
# TYPE tailbridge_udp_datagrams_dropped_total counter
tailbridge_udp_datagrams_dropped_total %d
# HELP tailbridge_policy_denials_total Total flows that the network policy denied.
# TYPE tailbridge_policy_denials_total counter
tailbridge_policy_denials_total %d
# HELP tailbridge_quic_smoothed_rtt_microseconds Smoothed QUIC round-trip time in microseconds.
# TYPE tailbridge_quic_smoothed_rtt_microseconds gauge
tailbridge_quic_smoothed_rtt_microseconds %d
# HELP tailbridge_quic_bytes_sent Total bytes sent by the current QUIC connection.
# TYPE tailbridge_quic_bytes_sent gauge
tailbridge_quic_bytes_sent %d
# HELP tailbridge_quic_bytes_received Total bytes received by the current QUIC connection.
# TYPE tailbridge_quic_bytes_received gauge
tailbridge_quic_bytes_received %d
# HELP tailbridge_quic_bytes_lost Total bytes lost by the current QUIC connection.
# TYPE tailbridge_quic_bytes_lost gauge
tailbridge_quic_bytes_lost %d
# HELP tailbridge_quic_send_bits_per_second Current QUIC send throughput in bits per second.
# TYPE tailbridge_quic_send_bits_per_second gauge
tailbridge_quic_send_bits_per_second %d
# HELP tailbridge_quic_receive_bits_per_second Current QUIC receive throughput in bits per second.
# TYPE tailbridge_quic_receive_bits_per_second gauge
tailbridge_quic_receive_bits_per_second %d
`, ready, snapshot.ConfiguredConnectors, snapshot.ReadyConnectors, s.active.Load(), s.flows.Load(), s.udpActive.Load(), s.udpFlows.Load(), s.udpDropped.Load(), s.denied.Load(), s.quicRTT.Load(), s.quicSent.Load(), s.quicReceived.Load(), s.quicLost.Load(), s.quicSendRate.Load(), s.quicRecvRate.Load())
		for _, connector := range snapshot.Connectors {
			connectorReady := 0
			if connector.Ready {
				connectorReady = 1
			}
			_, _ = fmt.Fprintf(w, "tailbridge_connector_ready{connector_id=%q,slot=%q} %d\n", connector.ConnectorID, fmt.Sprint(connector.Slot), connectorReady)
		}
	}))
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		listener: listener,
		server: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 * 1024,
		},
	}, nil
}

func getOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "This method is not allowed.", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

func (l *Listener) Serve(ctx context.Context) error {
	result := make(chan error, 1)
	go func() {
		result <- l.server.Serve(l.listener)
	}()

	select {
	case err := <-result:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := l.server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-result
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
