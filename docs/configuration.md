# Configuration

Tailbridge reads runtime configuration from environment variables only.

Use the Tailbridge CLI to generate mutual TLS values. Never commit generated environment files.

## Common variables

| Variable               |              Required | Default            | Description                                                                 |
| ---------------------- | --------------------: | ------------------ | --------------------------------------------------------------------------- |
| `TB_EDGE_ID`           |                   Yes | None               | Stable identity for the shared Tailbridge edge.                             |
| `TB_CONNECTOR_ID`      | Static connector only | None               | Stable identity for one Railway connector.                                  |
| `TB_ENVIRONMENT`       | Static connector only | None               | Railway environment name.                                                   |
| `TB_MTLS_CA_B64`       | Edge and static connector | None            | Base64 PEM trust bundle.                                                    |
| `TB_MTLS_CERT_B64`     | Edge and static connector | None            | Base64 PEM leaf certificate.                                                |
| `TB_MTLS_KEY_B64`      | Edge and static connector | None            | Base64 PEM private key.                                                     |
| `TB_ADMIN_LISTEN_ADDR` |                    No | Component-specific | Health and metrics listen address. Use a numeric port from 1 through 65535. |
| `TB_LOG_LEVEL`         |                    No | `info`             | JSON log level. Use `debug`, `info`, `warn`, or `error`.                    |

## Edge variables

| Variable                      |     Required | Default                                      | Description                                                                                                                                             |
| ----------------------------- | -----------: | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TB_REGISTRATION_MODE`        |           No | `static`                                     | Registration mode. Use `static`, `migration`, or `dynamic`.                                                                                             |
| `TB_CONNECTORS_B64`           |  Static mode | None                                         | Base64 JSON static connector registry. Migration mode can use this value with the dynamic registry.                                                     |
| `TB_QUIC_LISTEN_ADDR`         |           No | `:4433`                                      | QUIC listen address for Tailbridge connector sessions.                                                                                                  |
| `TB_TCP_LISTEN_ADDR`          |           No | `[::]:15001`                                 | Transparent TCP listen address.                                                                                                                         |
| `TB_UDP_LISTEN_ADDR`          |           No | `[::]:15002`                                 | Transparent UDP listen address.                                                                                                                         |
| `TB_MAX_TCP_FLOWS`            |           No | `4096`                                       | Concurrent TCP flow limit. Use an integer from 1 through 1000000.                                                                                       |
| `TB_MAX_UDP_FLOWS`            |           No | `4096`                                       | Concurrent UDP flow limit. Use an integer from 1 through 1000000.                                                                                       |
| `TB_UDP_IDLE_TIMEOUT`         |           No | `30s`                                        | UDP mapping timeout.                                                                                                                                    |
| `TB_MANAGE_TAILSCALE`         |           No | `true`                                       | Start bundled Tailscale.                                                                                                                                |
| `TB_REGISTRATION_FROZEN`      |           No | `false`                                      | Block new registration requests and approvals. Renewal for known identities continues.                                                                  |
| `TB_NEW_PROJECTS_FROZEN`      |           No | `true`                                       | Block the first environment for an unknown Railway project. New environments for known projects continue.                                               |
| `TB_ALLOWED_PROJECT_IDS_B64`  |           No | Empty array                                  | Base64 JSON array of project IDs that can pass the new-project freeze.                                                                                  |
| `TB_REGISTRATION_LISTEN_ADDR` |           No | `:4434`                                      | Public QUIC registration listener.                                                                                                                      |
| `TB_APPROVAL_LISTEN_ADDR`     |           No | `tailscale0:9443`                            | Approval API interface and port. Use a Tailscale interface name or a tailnet address.                                                                   |
| `TB_DNS_LISTEN_ADDR`          |           No | `tailscale0:53`                              | Stable split-DNS resolver interface and port.                                                                                                           |
| `TB_REGISTRY_PATH`            |           No | `/var/lib/tailbridge/registry/tailbridge.db` | SQLite registry path on persistent storage.                                                                                                             |
| `TB_VIRTUAL_NETWORK`          |           No | `fd40::/10`                                  | Virtual address pool. Use a canonical ULA prefix from `/10` through `/16`.                                                                              |
| `TB_EXCLUDED_PREFIXES`        |           No | `fd12::/16`                                  | Prefixes that the virtual pool must not allocate or overlap.                                                                                            |
| `TB_OIDC_POLICIES_B64`        | Dynamic mode | None                                         | Base64 JSON array of generic OIDC trust policies.                                                                                                       |
| `TB_APPROVAL_TAILSCALE_TAGS`  |           No | `tag:tailbridge-ci`                          | Tailscale tags that can call the approval API.                                                                                                          |
| `TB_INTERMEDIATE_CERT_B64`    | Dynamic mode | None                                         | Base64 PEM online intermediate certificate chain.                                                                                                       |
| `TB_INTERMEDIATE_KEY_B64`     | Dynamic mode | None                                         | Base64 PEM online intermediate private key. Store this value as a secret.                                                                               |
| `TB_PREVIEW_LEASE`            |           No | `24h`                                        | Lease duration for environments that are not persistent.                                                                                                |
| `TB_PERSISTENT_LEASE`         |           No | `720h`                                       | Lease duration for persistent environments.                                                                                                             |
| `TB_PERSISTENT_ENVIRONMENTS`  |           No | `production,staging,development`             | Environment names that receive persistent leases.                                                                                                       |
| `TB_SLOT_QUARANTINE`          |           No | `24h`                                        | Delay before a withdrawn `/16` can be allocated again.                                                                                                  |
| `TB_RECONCILE_INTERVAL`       |           No | `1m`                                         | Route, lease, and nftables reconciliation interval.                                                                                                     |
| `TS_AUTHKEY`                  |  First start | None                                         | Tailscale credential.                                                                                                                                   |
| `TS_HOSTNAME`                 |          Yes | None                                         | Stable Tailscale hostname.                                                                                                                              |
| `TS_STATE_DIR`                |           No | `/var/lib/tailscale`                         | Persistent Tailscale state.                                                                                                                             |
| `TS_AUTH_ONCE`                |           No | `true`                                       | Reuse existing authentication.                                                                                                                          |
| `TS_USERSPACE`                |           No | `false`                                      | Require kernel networking.                                                                                                                              |
| `TS_EXTRA_ARGS`               |          Yes | None                                         | Tailscale startup arguments. In dynamic mode, include tags but do not include `--advertise-routes`. The Tailbridge reconciler is the only route writer. |

## Connector variables

| Variable                   |           Required | Default               | Description                                                                      |
| -------------------------- | -----------------: | --------------------- | -------------------------------------------------------------------------------- |
| `TB_REGISTRATION_MODE`     |                 No | `static`              | Connector registration mode. Use `static` or `dynamic`.                          |
| `TB_EDGE_ENDPOINT`         |                Yes | None                  | Tailbridge edge host and numeric data QUIC port.                                 |
| `TB_REGISTRATION_ENDPOINT` |       Dynamic mode | None                  | Tailbridge edge host and numeric registration QUIC port.                         |
| `TB_IDENTITY_DIR`          |       Dynamic mode | `/var/lib/tailbridge` | Persistent connector identity and assignment directory.                          |
| `TB_ENROLLMENT_NONCE`      | First registration | None                  | One-time random value that CI writes through the Railway control plane.          |
| `TB_DNS_PROJECT_ALIAS`     |       Dynamic mode | None                  | Approved project DNS label.                                                      |
| `TB_DNS_ENVIRONMENT_ALIAS` |       Dynamic mode | None                  | Approved environment DNS label.                                                  |
| `TB_TRUST_BUNDLE_B64`      |       Dynamic mode | None                  | Base64 PEM trust bundle for first contact with the edge.                         |
| `RAILWAY_PROJECT_ID`       |       Dynamic mode | Railway value         | Stable Railway project ID.                                                       |
| `RAILWAY_ENVIRONMENT_ID`   |       Dynamic mode | Railway value         | Stable Railway environment ID.                                                   |
| `RAILWAY_ENVIRONMENT_NAME` |       Dynamic mode | Railway value         | Descriptive name and OIDC environment binding.                                   |
| `RAILWAY_DEPLOYMENT_ID`    |       Dynamic mode | Railway value         | Deployment identifier for audit events.                                          |
| `TB_VIRTUAL_PREFIX`        |        Static mode | None                  | Assigned virtual IPv6 `/16` for this connector.                                  |
| `TB_REAL_PREFIX`           |                 No | `fd12::/16`           | Railway private IPv6 `/16` for this connector.                                   |
| `TB_DNS_SUFFIX`            |        Static mode | None                  | Project DNS suffix below `railway.internal`.                                     |
| `TB_ALLOWED_DESTINATIONS`  |                Yes | None                  | Railway destination CIDRs.                                                       |
| `TB_MAX_TCP_FLOWS`         |                 No | `4096`                | Concurrent TCP flow limit. Use an integer from 1 through 1000000.                |
| `TB_MAX_UDP_FLOWS`         |                 No | `4096`                | Concurrent UDP flow limit. Use an integer from 1 through 1000000.                |
| `TB_TCP_DIAL_TIMEOUT`      |                 No | `10s`                 | Private TCP dial timeout.                                                        |
| `TB_RECONNECT_MIN_DELAY`   |                 No | `250ms`               | Initial reconnect delay.                                                         |
| `TB_RECONNECT_MAX_DELAY`   |                 No | `15s`                 | Maximum reconnect delay.                                                         |
| `TB_UDP_IDLE_TIMEOUT`      |                 No | `30s`                 | UDP mapping timeout.                                                             |
| `PORT`                     |                 No | `9002`                | Railway health port from 1 through 65535. `TB_ADMIN_LISTEN_ADDR` takes priority. |

Do not set `TB_LEASE_CLASS` on a connector. The edge derives the lease class from the approved environment identity.

Dynamic connectors do not use `TB_MTLS_CERT_B64`, `TB_MTLS_KEY_B64`, `TB_VIRTUAL_PREFIX`, or `TB_DNS_SUFFIX`. The registration response supplies these values.

## OIDC policy format

`TB_OIDC_POLICIES_B64` contains a JSON array. Each item defines one identity provider. The edge treats GitHub as one profile of this generic format.

Required policy fields include `id`, `issuer`, `jwksUrl`, `audiences`, `maxTokenAge`, `projectIdClaim`, and `environmentClaim`. Use `requiredClaims` for exact values. Use `oneOfClaims` for a short overlap list, such as two approved reusable workflow revisions.

The GitHub profile can bind `projectIdClaim` to `repo_property_tailbridge_railway_project_id`. GitHub prefixes enabled repository custom properties with `repo_property_` in the OIDC token. GitHub currently marks this feature as a public preview. The generic policy format lets an adopter select a different project claim or OIDC provider.

The edge validates `exp`, `nbf`, `iat`, the audience, the issuer, the project binding, the environment binding, the workflow SHA, and the replay claim. It records repository, workflow-run, and workflow-attempt claims for audit. These audit claims do not grant access by themselves.

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
