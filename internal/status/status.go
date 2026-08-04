package status

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type Server struct {
	healthy               atomic.Bool
	ready                 atomic.Bool
	connectorsMu          sync.RWMutex
	connectors            map[string]Connector
	active                atomic.Int64
	flows                 atomic.Uint64
	udpActive             atomic.Int64
	udpFlows              atomic.Uint64
	udpDropped            atomic.Uint64
	denied                atomic.Uint64
	quicRTT               atomic.Int64
	quicSent              atomic.Uint64
	quicReceived          atomic.Uint64
	quicLost              atomic.Uint64
	quicSendRate          atomic.Uint64
	quicRecvRate          atomic.Uint64
	quicMu                sync.Mutex
	quicObserver          uint64
	connectorQUIC         map[string]*quicMetrics
	registrations         atomic.Int64
	routesActive          atomic.Int64
	poolAllocated         atomic.Int64
	poolAvailable         atomic.Int64
	poolQuarantine        atomic.Int64
	pendingRequests       atomic.Int64
	routesPending         atomic.Int64
	certificatesSoon      atomic.Int64
	leasesSoon            atomic.Int64
	metricMu              sync.RWMutex
	registrationState     map[string]int64
	registrationAttempts  map[metricLabels]uint64
	oidcValidations       map[metricLabels]uint64
	registrationLatency   metricHistogram
	routeReconcile        metricHistogram
	routeReconcileResults map[string]uint64
	version               string
}

type metricLabels struct{ result, reason string }

type metricHistogram struct {
	count   uint64
	sum     float64
	buckets [8]uint64
}

var metricBuckets = [...]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 5, 30}

type quicMetrics struct {
	observer    uint64
	rtt         int64
	sent        uint64
	received    uint64
	lost        uint64
	sendRate    uint64
	receiveRate uint64
}

type Connector struct {
	ConnectorID                 string `json:"connector_id"`
	Slot                        int    `json:"slot"`
	VirtualPrefix               string `json:"virtual_prefix"`
	RealPrefix                  string `json:"real_prefix"`
	Ready                       bool   `json:"ready"`
	SessionID                   string `json:"session_id,omitempty"`
	SessionAgeSeconds           int64  `json:"session_age_seconds,omitempty"`
	QUICSmoothedRTTMicroseconds int64  `json:"quic_smoothed_rtt_microseconds,omitempty"`
	QUICBytesSent               uint64 `json:"quic_bytes_sent,omitempty"`
	QUICBytesReceived           uint64 `json:"quic_bytes_received,omitempty"`
	QUICBytesLost               uint64 `json:"quic_bytes_lost,omitempty"`
	sessionStartedAt            time.Time
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
	server := &Server{version: version, connectors: make(map[string]Connector), connectorQUIC: make(map[string]*quicMetrics), registrationState: make(map[string]int64), registrationAttempts: make(map[metricLabels]uint64), oidcValidations: make(map[metricLabels]uint64), routeReconcileResults: make(map[string]uint64)}
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
		connector.sessionStartedAt = time.Time{}
		s.connectors[connector.ConnectorID] = connector
	}
	s.setConnectorReadinessLocked()
	s.connectorsMu.Unlock()
	s.quicMu.Lock()
	s.connectorQUIC = make(map[string]*quicMetrics, len(connectors))
	for _, connector := range connectors {
		s.connectorQUIC[connector.ConnectorID] = &quicMetrics{}
	}
	s.quicMu.Unlock()
}

// ReconcileConnectors changes the configured set without clearing sessions
// for connector identities that remain active.
func (s *Server) ReconcileConnectors(connectors []Connector) {
	s.connectorsMu.Lock()
	next := make(map[string]Connector, len(connectors))
	for _, connector := range connectors {
		if current, ok := s.connectors[connector.ConnectorID]; ok {
			connector.Ready = current.Ready
			connector.SessionID = current.SessionID
			connector.sessionStartedAt = current.sessionStartedAt
		}
		next[connector.ConnectorID] = connector
	}
	s.connectors = next
	s.setConnectorReadinessLocked()
	s.connectorsMu.Unlock()
	s.quicMu.Lock()
	nextQUIC := make(map[string]*quicMetrics, len(connectors))
	for _, connector := range connectors {
		if current := s.connectorQUIC[connector.ConnectorID]; current != nil {
			nextQUIC[connector.ConnectorID] = current
		} else {
			nextQUIC[connector.ConnectorID] = &quicMetrics{}
		}
	}
	s.connectorQUIC = nextQUIC
	s.quicMu.Unlock()
}

func (s *Server) SetRegistryMetrics(registrations, active, allocated, available, quarantined, pending, routesPending, certificatesSoon, leasesSoon int64, states map[string]int64) {
	s.registrations.Store(registrations)
	s.routesActive.Store(active)
	s.poolAllocated.Store(allocated)
	s.poolAvailable.Store(available)
	s.poolQuarantine.Store(quarantined)
	s.pendingRequests.Store(pending)
	s.routesPending.Store(routesPending)
	s.certificatesSoon.Store(certificatesSoon)
	s.leasesSoon.Store(leasesSoon)
	s.metricMu.Lock()
	s.registrationState = make(map[string]int64, len(states))
	for key, value := range states {
		s.registrationState[key] = value
	}
	s.metricMu.Unlock()
}

func (s *Server) ObserveRegistration(result, reason string, elapsed time.Duration) {
	s.metricMu.Lock()
	s.registrationAttempts[metricLabels{result: result, reason: reason}]++
	observeHistogram(&s.registrationLatency, elapsed)
	s.metricMu.Unlock()
}

func (s *Server) ObserveOIDC(result, reason string) {
	s.metricMu.Lock()
	s.oidcValidations[metricLabels{result: result, reason: reason}]++
	s.metricMu.Unlock()
}

func (s *Server) ObserveRouteReconcile(result string, elapsed time.Duration) {
	s.metricMu.Lock()
	s.routeReconcileResults[result]++
	observeHistogram(&s.routeReconcile, elapsed)
	s.metricMu.Unlock()
}

func observeHistogram(histogram *metricHistogram, elapsed time.Duration) {
	seconds := elapsed.Seconds()
	histogram.count++
	histogram.sum += seconds
	for index, bound := range metricBuckets {
		if seconds <= bound {
			histogram.buckets[index]++
		}
	}
}

func (s *Server) ConnectorReady(connectorID, sessionID string) {
	s.connectorsMu.Lock()
	connector, ok := s.connectors[connectorID]
	if ok {
		connector.Ready = true
		connector.SessionID = sessionID
		connector.sessionStartedAt = time.Now()
		s.connectors[connectorID] = connector
	}
	s.setConnectorReadinessLocked()
	s.connectorsMu.Unlock()
}

func (s *Server) ConnectorClosed(connectorID, sessionID string) {
	s.connectorsMu.Lock()
	connector, ok := s.connectors[connectorID]
	if ok && connector.SessionID == sessionID {
		connector.Ready = false
		connector.SessionID = ""
		connector.sessionStartedAt = time.Time{}
		s.connectors[connectorID] = connector
	}
	s.setConnectorReadinessLocked()
	s.connectorsMu.Unlock()
}

func (s *Server) Snapshot() Snapshot {
	s.connectorsMu.RLock()
	connectors := make([]Connector, 0, len(s.connectors))
	ready := 0
	for _, connector := range s.connectors {
		if connector.Ready && !connector.sessionStartedAt.IsZero() {
			connector.SessionAgeSeconds = max(0, int64(time.Since(connector.sessionStartedAt).Seconds()))
		}
		connectors = append(connectors, connector)
		if connector.Ready {
			ready++
		}
	}
	s.connectorsMu.RUnlock()
	s.quicMu.Lock()
	for index := range connectors {
		metrics := s.connectorQUIC[connectors[index].ConnectorID]
		if metrics != nil {
			connectors[index].QUICSmoothedRTTMicroseconds = metrics.rtt
			connectors[index].QUICBytesSent = metrics.sent
			connectors[index].QUICBytesReceived = metrics.received
			connectors[index].QUICBytesLost = metrics.lost
		}
	}
	s.quicMu.Unlock()
	slices.SortFunc(connectors, func(left, right Connector) int { return cmp.Compare(left.Slot, right.Slot) })
	allReady := s.ready.Load()
	if len(connectors) > 0 {
		allReady = ready == len(connectors)
	}
	return Snapshot{Version: s.version, Healthy: s.healthy.Load(), Ready: allReady, ConfiguredConnectors: len(connectors), ReadyConnectors: ready, Connectors: connectors}
}

func (s *Server) setConnectorReadinessLocked() {
	if len(s.connectors) == 0 {
		s.ready.Store(false)
		return
	}
	for _, connector := range s.connectors {
		if !connector.Ready {
			s.ready.Store(false)
			return
		}
	}
	s.ready.Store(true)
}

type Listener struct {
	listener net.Listener
	server   *http.Server
}

func (l *Listener) Close() error {
	return l.listener.Close()
}

func (s *Server) ObserveQUIC(ctxDone <-chan struct{}, connection *quic.Conn) {
	s.observeQUIC("", ctxDone, connection)
}

// ObserveConnectorQUIC records an independent bounded metric set for a connector.
func (s *Server) ObserveConnectorQUIC(connectorID string, ctxDone <-chan struct{}, connection *quic.Conn) {
	s.observeQUIC(connectorID, ctxDone, connection)
}

func (s *Server) observeQUIC(connectorID string, ctxDone <-chan struct{}, connection *quic.Conn) {
	s.quicMu.Lock()
	observer, ok := s.startQUICObserverLocked(connectorID)
	s.quicMu.Unlock()
	if !ok {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var previous quic.ConnectionStats
	var previousAt time.Time
	defer func() {
		s.quicMu.Lock()
		s.stopQUICObserverLocked(connectorID, observer)
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
			if !s.storeConnectorQUICSample(connectorID, observer, stats, sendRate, receiveRate) {
				return
			}
			previous = stats
			previousAt = now
		}
	}
}

func (s *Server) startQUICObserverLocked(connectorID string) (uint64, bool) {
	if connectorID == "" {
		s.quicObserver++
		s.resetQUICMetrics()
		return s.quicObserver, true
	}
	metrics, ok := s.connectorQUIC[connectorID]
	if !ok {
		return 0, false
	}
	metrics.observer++
	observer := metrics.observer
	*metrics = quicMetrics{observer: observer}
	return observer, true
}

func (s *Server) stopQUICObserverLocked(connectorID string, observer uint64) {
	if connectorID == "" {
		if s.quicObserver == observer {
			s.quicObserver++
			s.resetQUICMetrics()
		}
		return
	}
	metrics := s.connectorQUIC[connectorID]
	if metrics != nil && metrics.observer == observer {
		*metrics = quicMetrics{observer: observer + 1}
	}
}

func (s *Server) storeQUICStats(observer uint64, stats quic.ConnectionStats) bool {
	return s.storeQUICSample(observer, stats, 0, 0)
}

func (s *Server) storeQUICSample(observer uint64, stats quic.ConnectionStats, sendRate, receiveRate uint64) bool {
	return s.storeConnectorQUICSample("", observer, stats, sendRate, receiveRate)
}

func (s *Server) storeConnectorQUICSample(connectorID string, observer uint64, stats quic.ConnectionStats, sendRate, receiveRate uint64) bool {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()
	if connectorID != "" {
		metrics := s.connectorQUIC[connectorID]
		if metrics == nil || metrics.observer != observer {
			return false
		}
		metrics.rtt = stats.SmoothedRTT.Microseconds()
		metrics.sent = stats.BytesSent
		metrics.received = stats.BytesReceived
		metrics.lost = stats.BytesLost
		metrics.sendRate = sendRate
		metrics.receiveRate = receiveRate
		return true
	}
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
# HELP tailbridge_connector_ready Whether a configured connector is ready.
# TYPE tailbridge_connector_ready gauge
# HELP tailbridge_connector_session_age_seconds Age of the active connector session in seconds.
# TYPE tailbridge_connector_session_age_seconds gauge
# HELP tailbridge_connector_quic_smoothed_rtt_microseconds Smoothed connector QUIC round-trip time in microseconds.
# TYPE tailbridge_connector_quic_smoothed_rtt_microseconds gauge
# HELP tailbridge_connector_quic_bytes_sent Total bytes sent by the connector QUIC connection.
# TYPE tailbridge_connector_quic_bytes_sent gauge
# HELP tailbridge_connector_quic_bytes_received Total bytes received by the connector QUIC connection.
# TYPE tailbridge_connector_quic_bytes_received gauge
# HELP tailbridge_connector_quic_bytes_lost Total bytes lost by the connector QUIC connection.
# TYPE tailbridge_connector_quic_bytes_lost gauge
# HELP tailbridge_registrations Registration records grouped by bounded state and lease class.
# TYPE tailbridge_registrations gauge
tailbridge_registrations{state="all",lease_class="all"} %d
# HELP tailbridge_routes_active Active, non-expired dynamic routes.
# TYPE tailbridge_routes_active gauge
tailbridge_routes_active %d
# HELP tailbridge_virtual_pool_allocated Allocated virtual routes.
# TYPE tailbridge_virtual_pool_allocated gauge
tailbridge_virtual_pool_allocated %d
# HELP tailbridge_virtual_pool_available Available virtual routes.
# TYPE tailbridge_virtual_pool_available gauge
tailbridge_virtual_pool_available %d
# HELP tailbridge_virtual_pool_quarantined Quarantined virtual routes.
# TYPE tailbridge_virtual_pool_quarantined gauge
tailbridge_virtual_pool_quarantined %d
# HELP tailbridge_pending_requests Unexpired pending registration requests.
# TYPE tailbridge_pending_requests gauge
tailbridge_pending_requests %d
`, ready, snapshot.ConfiguredConnectors, snapshot.ReadyConnectors, s.active.Load(), s.flows.Load(), s.udpActive.Load(), s.udpFlows.Load(), s.udpDropped.Load(), s.denied.Load(), s.quicRTT.Load(), s.quicSent.Load(), s.quicReceived.Load(), s.quicLost.Load(), s.quicSendRate.Load(), s.quicRecvRate.Load(), s.registrations.Load(), s.routesActive.Load(), s.poolAllocated.Load(), s.poolAvailable.Load(), s.poolQuarantine.Load(), s.pendingRequests.Load())
		s.writeRegistryMetrics(w)
		for _, connector := range snapshot.Connectors {
			connectorReady := 0
			if connector.Ready {
				connectorReady = 1
			}
			_, _ = fmt.Fprintf(w, "tailbridge_connector_ready{slot=%q} %d\n", fmt.Sprint(connector.Slot), connectorReady)
			_, _ = fmt.Fprintf(w, "tailbridge_connector_session_age_seconds{slot=%q} %d\n", fmt.Sprint(connector.Slot), connector.SessionAgeSeconds)
			_, _ = fmt.Fprintf(w, "tailbridge_connector_quic_smoothed_rtt_microseconds{slot=%q} %d\n", fmt.Sprint(connector.Slot), connector.QUICSmoothedRTTMicroseconds)
			_, _ = fmt.Fprintf(w, "tailbridge_connector_quic_bytes_sent{slot=%q} %d\n", fmt.Sprint(connector.Slot), connector.QUICBytesSent)
			_, _ = fmt.Fprintf(w, "tailbridge_connector_quic_bytes_received{slot=%q} %d\n", fmt.Sprint(connector.Slot), connector.QUICBytesReceived)
			_, _ = fmt.Fprintf(w, "tailbridge_connector_quic_bytes_lost{slot=%q} %d\n", fmt.Sprint(connector.Slot), connector.QUICBytesLost)
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

func (s *Server) writeRegistryMetrics(w io.Writer) {
	_, _ = fmt.Fprintf(w, `# HELP tailbridge_routes_pending Route generations that have not been applied.
# TYPE tailbridge_routes_pending gauge
tailbridge_routes_pending %d
# HELP tailbridge_certificates_expiring Active certificates that expire within seven days.
# TYPE tailbridge_certificates_expiring gauge
tailbridge_certificates_expiring %d
# HELP tailbridge_leases_expiring Active registration leases that expire within seven days.
# TYPE tailbridge_leases_expiring gauge
tailbridge_leases_expiring %d
# HELP tailbridge_registration_attempts_total Registration attempts grouped by bounded result and reason.
# TYPE tailbridge_registration_attempts_total counter
# HELP tailbridge_registration_latency_seconds Registration request processing duration.
# TYPE tailbridge_registration_latency_seconds histogram
# HELP tailbridge_oidc_validation_total OIDC validations grouped by bounded result and reason.
# TYPE tailbridge_oidc_validation_total counter
# HELP tailbridge_route_reconcile_seconds Route reconciliation duration.
# TYPE tailbridge_route_reconcile_seconds histogram
# HELP tailbridge_route_reconcile_total Route reconciliations grouped by result.
# TYPE tailbridge_route_reconcile_total counter
`, s.routesPending.Load(), s.certificatesSoon.Load(), s.leasesSoon.Load())
	s.metricMu.RLock()
	defer s.metricMu.RUnlock()
	for key, value := range s.registrationState {
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) == 2 {
			_, _ = fmt.Fprintf(w, "tailbridge_registrations{state=%q,lease_class=%q} %d\n", parts[0], parts[1], value)
		}
	}
	for labels, value := range s.registrationAttempts {
		_, _ = fmt.Fprintf(w, "tailbridge_registration_attempts_total{result=%q,reason=%q} %d\n", labels.result, labels.reason, value)
	}
	writeHistogram(w, "tailbridge_registration_latency_seconds", s.registrationLatency)
	for labels, value := range s.oidcValidations {
		_, _ = fmt.Fprintf(w, "tailbridge_oidc_validation_total{result=%q,reason=%q} %d\n", labels.result, labels.reason, value)
	}
	writeHistogram(w, "tailbridge_route_reconcile_seconds", s.routeReconcile)
	for result, value := range s.routeReconcileResults {
		_, _ = fmt.Fprintf(w, "tailbridge_route_reconcile_total{result=%q} %d\n", result, value)
	}
}

func writeHistogram(w io.Writer, name string, histogram metricHistogram) {
	for index, bound := range metricBuckets {
		_, _ = fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, fmt.Sprint(bound), histogram.buckets[index])
	}
	_, _ = fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %g\n%s_count %d\n", name, histogram.count, name, histogram.sum, name, histogram.count)
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
