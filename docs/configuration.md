# Configuration

Tailbridge reads runtime configuration from environment variables only.

Use the Tailbridge CLI to generate mutual TLS values. Never commit generated environment files.

## Common variables

| Variable | Required | Default | Description |
|---|---:|---|---|
| `TB_EDGE_ID` | Yes | None | Stable identity for the shared Tailbridge edge. |
| `TB_CONNECTOR_ID` | Connector only | None | Stable identity for one Railway connector. |
| `TB_ENVIRONMENT` | Connector only | None | Railway environment name. |
| `TB_MTLS_CA_B64` | Yes | None | Base64 PEM trust bundle. |
| `TB_MTLS_CERT_B64` | Yes | None | Base64 PEM leaf certificate. |
| `TB_MTLS_KEY_B64` | Yes | None | Base64 PEM private key. |
| `TB_ADMIN_LISTEN_ADDR` | No | Component-specific | Health and metrics listen address. Use a numeric port from 1 through 65535. |
| `TB_LOG_LEVEL` | No | `info` | JSON log level. Use `debug`, `info`, `warn`, or `error`. |

## Edge variables

| Variable | Required | Default | Description |
|---|---:|---|---|
| `TB_CONNECTORS_B64` | Yes | None | Base64 JSON connector registry. SST sets this value. |
| `TB_ALLOWED_ROUTES` | Yes | None | Comma-separated virtual destination CIDRs. SST sets the assigned connector `/16` routes. |
| `TB_QUIC_LISTEN_ADDR` | No | `:4433` | QUIC listen address for Tailbridge connector sessions. |
| `TB_TCP_LISTEN_ADDR` | No | `[::]:15001` | Transparent TCP listen address. |
| `TB_UDP_LISTEN_ADDR` | No | `[::]:15002` | Transparent UDP listen address. |
| `TB_MAX_TCP_FLOWS` | No | `4096` | Concurrent TCP flow limit. Use an integer from 1 through 1000000. |
| `TB_MAX_UDP_FLOWS` | No | `4096` | Concurrent UDP flow limit. Use an integer from 1 through 1000000. |
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
| `TB_EDGE_ENDPOINT` | Yes | None | Tailbridge edge host and numeric QUIC port. |
| `TB_VIRTUAL_PREFIX` | Yes | None | Assigned virtual IPv6 `/16` for this connector. |
| `TB_REAL_PREFIX` | No | `fd12::/16` | Railway private IPv6 `/16` for this connector. |
| `TB_DNS_SUFFIX` | Yes | None | Project DNS suffix below `railway.internal`. |
| `TB_ALLOWED_DESTINATIONS` | Yes | None | Railway destination CIDRs. |
| `TB_MAX_TCP_FLOWS` | No | `4096` | Concurrent TCP flow limit. Use an integer from 1 through 1000000. |
| `TB_MAX_UDP_FLOWS` | No | `4096` | Concurrent UDP flow limit. Use an integer from 1 through 1000000. |
| `TB_TCP_DIAL_TIMEOUT` | No | `10s` | Private TCP dial timeout. |
| `TB_RECONNECT_MIN_DELAY` | No | `250ms` | Initial reconnect delay. |
| `TB_RECONNECT_MAX_DELAY` | No | `15s` | Maximum reconnect delay. |
| `TB_UDP_IDLE_TIMEOUT` | No | `30s` | UDP mapping timeout. |
| `PORT` | No | `9002` | Railway health port from 1 through 65535. `TB_ADMIN_LISTEN_ADDR` takes priority. |

## Validation

Tailbridge validates all configuration during startup. Tailbridge stops startup when a value is invalid.

Listen addresses must contain a numeric port from 1 through 65535. `TB_EDGE_ENDPOINT` must also contain a host.

`TB_MAX_TCP_FLOWS` and `TB_MAX_UDP_FLOWS` must contain integers from 1 through 1000000.

Duration values must use Go duration syntax and must be greater than zero. Examples include `250ms`, `10s`, and `1m`.

CIDR variables must contain at least one valid CIDR. Separate multiple CIDRs with commas.

Connector and environment names must start with a letter or digit. They can contain up to 63 letters, digits, periods, underscores, or hyphens.

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

When you enable OTLP, `OTEL_TRACES_SAMPLER_ARG` must contain a number from `0` through `1`.

## Sentry

Set `SENTRY_DSN` to enable Sentry.

Optional variables are:

```text
SENTRY_ENVIRONMENT
SENTRY_RELEASE
SENTRY_TRACES_SAMPLE_RATE
```

Tailbridge disables Sentry when the DSN is empty.

`SENTRY_TRACES_SAMPLE_RATE` is optional when you enable Sentry. Its default value is `0.01`.

If you set `SENTRY_TRACES_SAMPLE_RATE`, use a number from `0` through `1`.
