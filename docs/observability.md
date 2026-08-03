# Observability

Tailbridge emits JSON logs to standard output. It emits one completion event for each TCP flow.

The event contains flow identity, duration, byte counts, destination, session, and outcome.

Tailbridge never records packet payloads. Protect logs because destination addresses can identify private services.

Limit log and trace retention to 30 days unless an incident requires a documented exception. Give telemetry access only to operators who can access the private network.

Redact destination metadata before export when the telemetry system is outside the private trust boundary. Limit each exporter to the approved OTLP or Sentry endpoint. Verify retention, access, redaction, and exporter scope before release.

## Health

Both components provide:

```text
/healthz
/readyz
/metrics
/version
```

The edge is ready after Tailscale and one connector become ready.

The connector is ready after the edge accepts its authenticated session.

## Metrics

The Prometheus endpoint reports these metrics:

| Metric | Type | Description |
|---|---|---|
| `tailbridge_ready` | Gauge | Reports whether the component is ready. |
| `tailbridge_tcp_flows_active` | Gauge | Reports the current active TCP flows. |
| `tailbridge_tcp_flows_total` | Counter | Counts all TCP flows. |
| `tailbridge_udp_flows_active` | Gauge | Reports the current active UDP flows. |
| `tailbridge_udp_flows_total` | Counter | Counts all UDP flows. |
| `tailbridge_udp_datagrams_dropped_total` | Counter | Counts UDP datagrams that Tailbridge drops. |
| `tailbridge_policy_denials_total` | Counter | Counts flows that the network policy denies. |
| `tailbridge_quic_smoothed_rtt_microseconds` | Gauge | Reports the smoothed QUIC round-trip time. |
| `tailbridge_quic_bytes_sent` | Gauge | Reports bytes sent by the current QUIC connection. |
| `tailbridge_quic_bytes_received` | Gauge | Reports bytes received by the current QUIC connection. |
| `tailbridge_quic_bytes_lost` | Gauge | Reports bytes lost by the current QUIC connection. |
| `tailbridge_quic_send_bits_per_second` | Gauge | Reports the five-second QUIC send rate. |
| `tailbridge_quic_receive_bits_per_second` | Gauge | Reports the five-second QUIC receive rate. |

The QUIC RTT excludes the client, Tailscale subnet path, and destination service.
Use this PromQL expression to graph connector-to-edge latency in milliseconds:

```promql
tailbridge_quic_smoothed_rtt_microseconds / 1000
```

Use this expression to show whether the RTT meets a 25 ms target:

```promql
tailbridge_quic_smoothed_rtt_microseconds < bool 25000
```

Scrape `/metrics` every five seconds to keep the same resolution as the internal
QUIC observer. Use this alert for a sustained target violation:

```yaml
- alert: TailbridgeConnectorRTTHigh
  expr: tailbridge_ready == 1 and tailbridge_quic_smoothed_rtt_microseconds > 25000
  for: 1m
  labels:
    severity: warning
  annotations:
    summary: Tailbridge connector RTT is above 25 ms
```

Use these expressions to graph observed QUIC traffic in megabits per second:

```promql
tailbridge_quic_send_bits_per_second / 1000000
tailbridge_quic_receive_bits_per_second / 1000000
```

The throughput gauges measure actual QUIC traffic. They do not run synthetic
traffic and do not measure unused connection capacity. A synthetic test can
compete with production traffic and change the result that it measures.

Each Tailbridge component limits concurrent UDP flows with `TB_MAX_UDP_FLOWS`.

Tailbridge drops a new datagram when the UDP flow limit is full. It increments `tailbridge_udp_datagrams_dropped_total` for the drop.

Tailbridge also counts malformed datagrams, policy denials, socket errors, and QUIC send errors as drops.

A QUIC send error includes a datagram that exceeds the negotiated QUIC datagram size.

## OpenTelemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces through OTLP over HTTP.

Telemetry uses a bounded batch processor. Export failure does not stop network traffic.

## Sentry

Set `SENTRY_DSN` to report panics and fatal process errors.

Sentry does not receive packet payloads or private keys.
