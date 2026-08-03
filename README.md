# Tailbridge

Tailbridge gives a tailnet direct access to Railway private services.

Railway does not accept public UDP. This restriction can force a Railway Tailscale node through DERP.

This project moves the Tailscale subnet router to a public edge host. Outbound QUIC connectors then reach Railway environments.

```text
Tailscale client
      │ direct WireGuard UDP
      ▼
Tailbridge edge
      │ authenticated QUIC sessions
      ├───────────────┐
      ▼               ▼
Railway connector A  Railway connector B
      │               │
Railway project A    Railway project B
```

## Project status

This repository contains an alpha version of Tailbridge.

Tailbridge supports transparent IPv6 TCP and UDP forwarding. Tailbridge also supports Railway private DNS.

Do not use Tailbridge for critical production traffic until the public system tests pass.

## Properties

- One shared Tailbridge edge serves up to 32 Railway environments.
- Each Railway environment uses one stable connector slot and virtual IPv6 `/16`.
- Tailnet clients need no software other than Tailscale.
- The Tailbridge edge keeps one stable Tailscale identity.
- Railway deployments do not register new Tailscale devices.
- TCP uses independent QUIC streams.
- UDP uses QUIC datagrams.
- Mutual TLS authenticates the Tailbridge edge and Tailbridge connector.
- Runtime configuration uses environment variables only.
- OpenTelemetry and Sentry are optional.

## Requirements

You need GitHub, Cloudflare, DigitalOcean, Railway, and Tailscale accounts.

The standard template deployment does not require a source fork. GitHub Actions runs the required Node.js and pnpm tools.

Tailbridge uses SST to manage the shared edge and all connectors. Cloudflare R2 stores encrypted production state.

The Railway environment needs private networking. Protected services must listen on IPv6.

## Deployment

You do not need to fork the Tailbridge source repository.

The standard deployment uses a repository from the public [Tailbridge SST template](https://github.com/bearfire-dev/tailbridge-sst-template).

The [setup procedure](docs/setup.md) contains all configuration and deployment steps.

A stable connector slot keeps the project virtual addresses unchanged.

Tailbridge gives each service a project-qualified Railway hostname:

```text
postgres.billing.railway.internal
api.billing.railway.internal
```

## Advanced SST use

The template uses the `@bearfire-dev/tailscale-railway-quic-bridge` package from GitHub Packages.

Advanced SST projects can import the `Tailbridge` component directly. The [setup procedure](docs/setup.md) contains the package and component details.

## Images

Releases publish these images:

```text
ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-edge
ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-connector
ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-cli
```

The deployment workflow resolves each `master` image to an immutable digest. It stores the deployed digest pair in SST state.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Design decisions](docs/design-decisions.md)
- [Setup](docs/setup.md)
- [Operations](docs/operations.md)
- [Observability](docs/observability.md)
- [Performance tests](docs/performance.md)
- [Security](docs/security.md)
- [Changelog](CHANGELOG.md)

## Known limits

- One shared Tailbridge edge supports 32 connector slots.
- Connector slots map to `/16` networks inside `fd20::/11` by default.
- A slot change changes all virtual addresses for that Railway project.
- UDP payloads must fit the negotiated QUIC datagram size.
- Tailbridge supports only TCP and UDP.
- The Tailbridge edge requires Linux transparent proxy support.
- A single Tailbridge edge has a short outage during an upgrade.

## Development

1. Run the complete checklist in [CONTRIBUTING.md](CONTRIBUTING.md).

2. Build both images:

   ```bash
   docker build -f Dockerfile.edge -t tailbridge-edge:test .
   docker build -f Dockerfile.connector -t tailbridge-connector:test .
   ```

## License

Apache License 2.0. See [LICENSE](LICENSE).

Tailscale, Railway, DigitalOcean, and other marks belong to their respective owners. This project has no vendor affiliation.
