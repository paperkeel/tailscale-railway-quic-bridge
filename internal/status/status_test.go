package status

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestListenerServesStatusAndStopsWithContext(t *testing.T) {
	state := New("v1.2.3")
	state.SetReady(true)
	state.FlowStarted()
	state.FlowEnded()
	state.UDPFlowStarted()
	state.UDPFlowEnded()
	state.DatagramDropped()
	state.Denied()
	state.quicSendRate.Store(123)
	state.quicRecvRate.Store(456)

	listener, err := state.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- listener.Serve(ctx) }()

	baseURL := "http://" + listener.listener.Addr().String()
	for path, wantStatus := range map[string]int{
		"/healthz": http.StatusOK,
		"/readyz":  http.StatusOK,
		"/metrics": http.StatusOK,
		"/version": http.StatusOK,
	} {
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+path, nil)
		if requestErr != nil {
			t.Fatalf("create GET %s: %v", path, requestErr)
		}
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatalf("GET %s: %v", path, requestErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != wantStatus {
			t.Errorf("GET %s status = %d, want %d", path, response.StatusCode, wantStatus)
		}
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	metrics := string(body)
	for _, want := range []string{
		"# HELP tailbridge_ready ",
		"# TYPE tailbridge_ready gauge",
		"tailbridge_tcp_flows_total 1",
		"tailbridge_udp_flows_active 0",
		"tailbridge_udp_flows_total 1",
		"tailbridge_udp_datagrams_dropped_total 1",
		"tailbridge_policy_denials_total 1",
		"# TYPE tailbridge_quic_send_bits_per_second gauge",
		"tailbridge_quic_send_bits_per_second 123",
		"# TYPE tailbridge_quic_receive_bits_per_second gauge",
		"tailbridge_quic_receive_bits_per_second 456",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics do not contain %q\n%s", want, metrics)
		}
	}
	for _, name := range []string{
		"tailbridge_ready",
		"tailbridge_tcp_flows_active",
		"tailbridge_tcp_flows_total",
		"tailbridge_udp_flows_active",
		"tailbridge_udp_flows_total",
		"tailbridge_udp_datagrams_dropped_total",
		"tailbridge_policy_denials_total",
		"tailbridge_quic_smoothed_rtt_microseconds",
		"tailbridge_quic_bytes_sent",
		"tailbridge_quic_bytes_received",
		"tailbridge_quic_bytes_lost",
		"tailbridge_quic_send_bits_per_second",
		"tailbridge_quic_receive_bits_per_second",
	} {
		if !strings.Contains(metrics, "# HELP "+name+" ") {
			t.Errorf("metrics do not contain HELP for %s", name)
		}
		if !strings.Contains(metrics, "# TYPE "+name+" ") {
			t.Errorf("metrics do not contain TYPE for %s", name)
		}
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestListenerBindsBeforeServe(t *testing.T) {
	first, err := New("test").Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	if _, err := New("test").Listen(first.listener.Addr().String()); err == nil {
		t.Fatal("Listen succeeded for an address that is in use")
	}
}

func TestListenerReturnsUnexpectedServeError(t *testing.T) {
	listener, err := New("test").Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Serve(context.Background()); err == nil {
		t.Fatal("Serve returned nil after the network listener closed")
	}
}

func TestReadyReportsUnavailable(t *testing.T) {
	listener, err := New("test").Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = listener.Serve(ctx) }()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listener.listener.Addr().String()+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestStatusRejectsUnsupportedMethods(t *testing.T) {
	listener, err := New("test").Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = listener.Serve(ctx) }()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+listener.listener.Addr().String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusMethodNotAllowed)
	}
	if response.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", response.Header.Get("Allow"))
	}
}

func TestObserveQUICClearsMetricsAfterDisconnect(t *testing.T) {
	state := New("test")
	state.quicRTT.Store(10)
	state.quicSent.Store(20)
	state.quicReceived.Store(30)
	state.quicLost.Store(40)
	state.quicSendRate.Store(50)
	state.quicRecvRate.Store(60)
	done := make(chan struct{})
	close(done)
	state.ObserveQUIC(done, nil)
	if state.quicRTT.Load() != 0 || state.quicSent.Load() != 0 || state.quicReceived.Load() != 0 || state.quicLost.Load() != 0 || state.quicSendRate.Load() != 0 || state.quicRecvRate.Load() != 0 {
		t.Fatal("ObserveQUIC() kept metrics after the current connection closed")
	}
}

func TestOlderQUICObserverDoesNotClearCurrentMetrics(t *testing.T) {
	state := New("test")
	olderDone := make(chan struct{})
	olderStopped := make(chan struct{})
	go func() {
		state.ObserveQUIC(olderDone, nil)
		close(olderStopped)
	}()
	waitForObserver(t, state, 1)

	currentDone := make(chan struct{})
	currentStopped := make(chan struct{})
	go func() {
		state.ObserveQUIC(currentDone, nil)
		close(currentStopped)
	}()
	waitForObserver(t, state, 2)
	state.quicRTT.Store(10)
	state.quicSent.Store(20)
	state.quicReceived.Store(30)
	state.quicLost.Store(40)
	state.quicSendRate.Store(50)
	state.quicRecvRate.Store(60)

	close(olderDone)
	select {
	case <-olderStopped:
	case <-time.After(time.Second):
		t.Fatal("the older QUIC observer did not stop")
	}
	if state.quicRTT.Load() != 10 || state.quicSent.Load() != 20 || state.quicReceived.Load() != 30 || state.quicLost.Load() != 40 || state.quicSendRate.Load() != 50 || state.quicRecvRate.Load() != 60 {
		t.Fatal("the older QUIC observer cleared the current metrics")
	}

	close(currentDone)
	select {
	case <-currentStopped:
	case <-time.After(time.Second):
		t.Fatal("the current QUIC observer did not stop")
	}
	if state.quicRTT.Load() != 0 || state.quicSent.Load() != 0 || state.quicReceived.Load() != 0 || state.quicLost.Load() != 0 || state.quicSendRate.Load() != 0 || state.quicRecvRate.Load() != 0 {
		t.Fatal("the current QUIC observer kept metrics after it stopped")
	}
}

func TestStoreQUICSampleStoresRates(t *testing.T) {
	state := New("test")
	state.quicObserver = 1
	stats := quic.ConnectionStats{BytesSent: 20, BytesReceived: 30}
	if !state.storeQUICSample(1, stats, 40, 50) {
		t.Fatal("storeQUICSample() rejected the current observer")
	}
	if state.quicSendRate.Load() != 40 || state.quicRecvRate.Load() != 50 {
		t.Fatal("storeQUICSample() did not store the throughput rates")
	}
}

func TestBitsPerSecond(t *testing.T) {
	if got := bitsPerSecond(1_100, 100, time.Second); got != 8_000 {
		t.Fatalf("bitsPerSecond() = %d, want 8000", got)
	}
	if got := bitsPerSecond(100, 1_100, time.Second); got != 0 {
		t.Fatalf("bitsPerSecond() after reset = %d, want 0", got)
	}
	if got := bitsPerSecond(1_100, 100, 0); got != 0 {
		t.Fatalf("bitsPerSecond() without elapsed time = %d, want 0", got)
	}
}

func TestStoreQUICStatsRejectsASupersededObserver(t *testing.T) {
	state := New("test")
	state.quicObserver = 2
	stats := quic.ConnectionStats{
		SmoothedRTT:   10 * time.Millisecond,
		BytesSent:     20,
		BytesReceived: 30,
		BytesLost:     40,
	}
	if state.storeQUICStats(1, stats) {
		t.Fatal("storeQUICStats() accepted a superseded observer")
	}
	if !state.storeQUICStats(2, stats) {
		t.Fatal("storeQUICStats() rejected the current observer")
	}
	if state.quicRTT.Load() != 10_000 || state.quicSent.Load() != 20 || state.quicReceived.Load() != 30 || state.quicLost.Load() != 40 {
		t.Fatal("storeQUICStats() did not store the current connection statistics")
	}
}

func waitForObserver(t *testing.T, state *Server, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state.quicMu.Lock()
		got := state.quicObserver
		state.quicMu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("QUIC observer generation did not reach %d", want)
}
