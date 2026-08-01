package status

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
		response, requestErr := http.Get(baseURL + path)
		if requestErr != nil {
			t.Fatalf("GET %s: %v", path, requestErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != wantStatus {
			t.Errorf("GET %s status = %d, want %d", path, response.StatusCode, wantStatus)
		}
	}

	response, err := http.Get(baseURL + "/metrics")
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
	defer func() { _ = first.listener.Close() }()

	if _, err := New("test").Listen(first.listener.Addr().String()); err == nil {
		t.Fatal("Listen succeeded for an address that is in use")
	}
}

func TestListenerReturnsUnexpectedServeError(t *testing.T) {
	listener, err := New("test").Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.listener.Close(); err != nil {
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

	response, err := http.Get("http://" + listener.listener.Addr().String() + "/readyz")
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

	request, err := http.NewRequest(http.MethodPost, "http://"+listener.listener.Addr().String()+"/healthz", nil)
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
	done := make(chan struct{})
	close(done)
	state.ObserveQUIC(done, nil)
	if state.quicRTT.Load() != 0 || state.quicSent.Load() != 0 || state.quicReceived.Load() != 0 || state.quicLost.Load() != 0 {
		t.Fatal("ObserveQUIC() kept metrics after the current connection closed")
	}
}
