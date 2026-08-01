package status

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type Server struct {
	ready        atomic.Bool
	active       atomic.Int64
	flows        atomic.Uint64
	denied       atomic.Uint64
	quicRTT      atomic.Int64
	quicSent     atomic.Uint64
	quicReceived atomic.Uint64
	quicLost     atomic.Uint64
	version      string
}

func New(version string) *Server      { return &Server{version: version} }
func (s *Server) SetReady(value bool) { s.ready.Store(value) }
func (s *Server) FlowStarted()        { s.active.Add(1); s.flows.Add(1) }
func (s *Server) FlowEnded()          { s.active.Add(-1) }
func (s *Server) Denied()             { s.denied.Add(1) }

func (s *Server) ObserveQUIC(ctxDone <-chan struct{}, connection *quic.Conn) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			stats := connection.ConnectionStats()
			s.quicRTT.Store(stats.SmoothedRTT.Microseconds())
			s.quicSent.Store(stats.BytesSent)
			s.quicReceived.Store(stats.BytesReceived)
			s.quicLost.Store(stats.BytesLost)
		}
	}
}

func (s *Server) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": s.version})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		ready := 0
		if s.ready.Load() {
			ready = 1
		}
		_, _ = fmt.Fprintf(w, "tailbridge_ready %d\ntailbridge_tcp_flows_active %d\ntailbridge_tcp_flows_total %d\ntailbridge_policy_denials_total %d\ntailbridge_quic_smoothed_rtt_microseconds %d\ntailbridge_quic_bytes_sent %d\ntailbridge_quic_bytes_received %d\ntailbridge_quic_bytes_lost %d\n", ready, s.active.Load(), s.flows.Load(), s.denied.Load(), s.quicRTT.Load(), s.quicSent.Load(), s.quicReceived.Load(), s.quicLost.Load())
	})
	server := http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return server.ListenAndServe()
}
