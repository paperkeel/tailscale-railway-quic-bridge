# Configuration

Tailbridge reads runtime configuration from environment variables only.

Use the setup CLI to generate mutual TLS values. Never commit generated environment files.

## Common variables

| Variable | Required | Default | Description |
|---|---:|---|---|
| `TB_CONNECTOR_ID` | Yes | None | Stable identity for the pair. |
| `TB_ENVIRONMENT` | Yes | None | Railway environment name. |
| `TB_MTLS_CA_B64` | Yes | None | Base64 PEM trust bundle. |
| `TB_MTLS_CERT_B64` | Yes | None | Base64 PEM leaf certificate. |
| `TB_MTLS_KEY_B64` | Yes | None | Base64 PEM private key. |
| `TB_ADMIN_LISTEN_ADDR` | No | Component-specific | Health and metrics address. |
| `TB_LOG_LEVEL` | No | `info` | Structured log level. |

## Edge variables

| Variable | Required | Default | Description |
|---|---:|---|---|
| `TB_ALLOWED_ROUTES` | Yes | None | Comma-separated destination CIDRs. |
| `TB_QUIC_LISTEN_ADDR` | No | `:4433` | Connector QUIC listener. |
| `TB_TCP_LISTEN_ADDR` | No | `[::]:15001` | Transparent TCP listener. |
| `TB_UDP_LISTEN_ADDR` | No | `[::]:15002` | Transparent UDP listener. |
| `TB_MAX_TCP_FLOWS` | No | `4096` | Concurrent TCP limit. |
| `TB_UDP_IDLE_TIMEOUT` | No | `30s` | UDP mapping timeout. |
| `TB_MANAGE_TAILSCALE` | No | `true` | Start bundled Tailscale. |
| `TS_AUTHKEY` | First start | None | Tailscale credential. |
| `TS_HOSTNAME` | Yes | None | Stable Tailscale hostname. |
| `TS_STATE_DIR` | No | `/var/lib/tailscale` | Persistent Tailscale state. |
| `TS_AUTH_ONCE` | No | `true` | Reuse existing authentication. |
| `TS_USERSPACE` | No | `false` | Require kernel networking. |
| `TS_EXTRA_ARGS` | Yes | None | Route and tag arguments. |

## Connector variables

| Variable | Required | Default | Description |
|---|---:|---|---|
| `TB_EDGE_ENDPOINT` | Yes | None | Edge host and QUIC port. |
| `TB_ALLOWED_DESTINATIONS` | Yes | None | Railway destination CIDRs. |
| `TB_MAX_TCP_FLOWS` | No | `4096` | Concurrent QUIC stream limit. Match the edge value. |
| `TB_TCP_DIAL_TIMEOUT` | No | `10s` | Private TCP dial timeout. |
| `TB_RECONNECT_MIN_DELAY` | No | `250ms` | Initial reconnect delay. |
| `TB_RECONNECT_MAX_DELAY` | No | `15s` | Maximum reconnect delay. |
| `TB_UDP_IDLE_TIMEOUT` | No | `30s` | UDP mapping timeout. |
| `PORT` | No | `9002` | Railway health port. `TB_ADMIN_LISTEN_ADDR` takes priority. |

## OpenTelemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTLP trace export.

The exporter also reads these standard variables:

```text
OTEL_EXPORTER_OTLP_HEADERS
OTEL_EXPORTER_OTLP_COMPRESSION
OTEL_EXPORTER_OTLP_TIMEOUT
OTEL_TRACES_SAMPLER_ARG
```

Tailbridge disables OTLP when the endpoint is empty.

## Sentry

Set `SENTRY_DSN` to enable Sentry.

Optional variables are:

```text
SENTRY_ENVIRONMENT
SENTRY_RELEASE
SENTRY_TRACES_SAMPLE_RATE
```

Tailbridge disables Sentry when the DSN is empty.
