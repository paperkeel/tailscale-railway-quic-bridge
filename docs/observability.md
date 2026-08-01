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

The Prometheus endpoint reports readiness, TCP flows, policy denials, QUIC round-trip time, byte counts, and lost bytes.

## OpenTelemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces through OTLP over HTTP.

Telemetry uses a bounded batch processor. Export failure does not stop network traffic.

## Sentry

Set `SENTRY_DSN` to report panics and fatal process errors.

Sentry does not receive packet payloads or private keys.
