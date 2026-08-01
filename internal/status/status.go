package status

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type Server struct {
	ready        atomic.Bool
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
	quicMu       sync.Mutex
	quicObserver uint64
	version      string
}

func New(version string) *Server      { return &Server{version: version} }
func (s *Server) SetReady(value bool) { s.ready.Store(value) }
func (s *Server) FlowStarted()        { s.active.Add(1); s.flows.Add(1) }
func (s *Server) FlowEnded()          { s.active.Add(-1) }
func (s *Server) UDPFlowStarted()     { s.udpActive.Add(1); s.udpFlows.Add(1) }
func (s *Server) UDPFlowEnded()       { s.udpActive.Add(-1) }
func (s *Server) DatagramDropped()    { s.udpDropped.Add(1) }
func (s *Server) Denied()             { s.denied.Add(1) }

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
			if !s.storeQUICStats(observer, stats) {
				return
			}
		}
	}
}

func (s *Server) storeQUICStats(observer uint64, stats quic.ConnectionStats) bool {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()
	if s.quicObserver != observer {
		return false
	}
	s.quicRTT.Store(stats.SmoothedRTT.Microseconds())
	s.quicSent.Store(stats.BytesSent)
	s.quicReceived.Store(stats.BytesReceived)
	s.quicLost.Store(stats.BytesLost)
	return true
}

func (s *Server) resetQUICMetrics() {
	s.quicRTT.Store(0)
	s.quicSent.Store(0)
	s.quicReceived.Store(0)
	s.quicLost.Store(0)
}

func (s *Server) Listen(addr string) (*Listener, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", getOnly(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
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
	mux.HandleFunc("/metrics", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		ready := 0
		if s.ready.Load() {
			ready = 1
		}
		_, _ = fmt.Fprintf(w, `# HELP tailbridge_ready Whether Tailbridge is ready to serve traffic.
# TYPE tailbridge_ready gauge
tailbridge_ready %d
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
`, ready, s.active.Load(), s.flows.Load(), s.udpActive.Load(), s.udpFlows.Load(), s.udpDropped.Load(), s.denied.Load(), s.quicRTT.Load(), s.quicSent.Load(), s.quicReceived.Load(), s.quicLost.Load())
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
