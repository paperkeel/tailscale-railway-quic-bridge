# Tailscale Railway QUIC Bridge

Tailscale Railway QUIC Bridge gives a tailnet direct access to Railway private services.

Railway does not accept public UDP. This restriction can force a Railway Tailscale node through DERP.

This project moves the Tailscale subnet router to a public edge host. A QUIC connector then reaches Railway through an outbound connection.

```text
Tailscale client
      │ direct WireGuard UDP
      ▼
Tailbridge edge
      │ authenticated QUIC
      ▼
Railway connector
      │
Railway private services
```

## Project status

This repository contains an alpha implementation.

The current implementation supports transparent IPv6 TCP and UDP forwarding. It also supports Railway private DNS.

Do not use it for critical production traffic until the public system tests pass.

## Properties

- One pair serves all services in one Railway environment.
- Tailnet clients need no software other than Tailscale.
- The edge keeps one stable Tailscale identity.
- Railway deployments do not register new Tailscale devices.
- TCP uses independent QUIC streams.
- UDP uses QUIC datagrams.
- Mutual TLS authenticates the pair.
- Runtime configuration uses environment variables only.
- OpenTelemetry and Sentry are optional.

## Requirements

The edge host needs:

- Linux.
- Docker Compose.
- A stable public IP address.
- Public UDP ports `41641` and `4433`.
- `/dev/net/tun`.
- The `NET_ADMIN` and `NET_RAW` capabilities.

The Railway environment needs private networking. Protected services must listen on IPv6.

## Quick start

Build the setup CLI:

```bash
go build -o tailbridge ./cmd/tailbridge
```

Generate paired environment files:

```bash
./tailbridge init \
  --output ./private \
  --connector-id railway-production \
  --environment production \
  --edge-endpoint edge.example.com:4433
```

Keep the generated directory private. It contains mutual TLS private keys.

Merge the generated policy fragment into the tailnet policy. Add grants for the required users and ports.

Set a tagged, non-ephemeral Tailscale credential in `private/edge.env`:

```text
TS_AUTHKEY=YOUR_NON_EPHEMERAL_KEY
```

Deploy the edge with [the edge guide](docs/deployment-edge.md).

Deploy the connector with [the Railway guide](docs/deployment-railway.md).

Configure Tailscale split DNS:

```text
Domain: railway.internal
Nameserver: fd12::10
```

Approve `fd12::/16` if the tailnet policy does not auto-approve it.

Access a service normally:

```bash
psql -h postgres.railway.internal -d DATABASE_NAME
curl http://api.railway.internal:3000
```

## Images

Releases publish these images:

```text
ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-edge
ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-connector
ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-cli
```

Use a version tag or digest. Do not use `latest`.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Design decisions](docs/design-decisions.md)
- [Edge deployment](docs/deployment-edge.md)
- [Railway deployment](docs/deployment-railway.md)
- [Operations](docs/operations.md)
- [Observability](docs/observability.md)
- [Performance tests](docs/performance.md)
- [Security](docs/security.md)
- [Changelog](CHANGELOG.md)

## Known limits

- One pair supports one Railway environment.
- The first release advertises Railway's shared `fd12::/16` range.
- UDP payloads must fit the negotiated QUIC datagram size.
- Only TCP and UDP are supported.
- The edge requires Linux transparent proxy support.
- A single edge has a short outage during an edge upgrade.

## Development

Run the complete checklist in [CONTRIBUTING.md](CONTRIBUTING.md).

Build both images:

```bash
docker build -f Dockerfile.edge -t tailbridge-edge:test .
docker build -f Dockerfile.connector -t tailbridge-connector:test .
```

## License

Apache License 2.0. See [LICENSE](LICENSE).

Tailscale, Railway, DigitalOcean, and other marks belong to their respective owners. This project has no vendor affiliation.
