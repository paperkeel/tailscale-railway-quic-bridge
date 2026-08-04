# Architecture

## Goal

Tailbridge removes DERP from the default network path to Railway private services.

The client connects directly to the Tailbridge edge. The Tailbridge edge forwards each flow through the outbound Tailbridge connector.

## Deployment control plane

SST manages the DigitalOcean edge. A separate deployment repository manages each Railway connector. The control plane does not process application traffic.

Cloudflare R2 stores the encrypted SST state. Local state is available only for disposable development stages.

SST uses these resource dependencies:

1. SST creates the mutual TLS certificates and the edge SSH key.

2. SST creates the DigitalOcean SSH key, volume, droplet, firewall, and volume attachment.

3. SST mounts the volume and deploys the edge through SSH.

4. A project deployment writes a one-time nonce through the Railway control plane.

5. The connector generates identity and transport keys on its Railway volume.

6. GitHub Actions joins the tailnet and approves the pending identity with an OIDC token.

7. The edge allocates a route, issues a 24-hour certificate, and reconciles nftables and Tailscale routes.

SST transfers edge configuration through SSH. The project deployment transfers connector configuration through Railway variables.

The connector opens QUIC to the edge public IPv4 address on UDP port `4433`. Public DNS is not in this path.

## Registration

The public registration listener uses UDP port `4434` and a separate ALPN. The edge authenticates itself with the configured trust root. The connector does not use TOFU.

The first request includes the Railway project ID, environment ID, identity public key, transport public key, and an HMAC proof. The proof uses a random nonce that CI writes to the connector service through Railway. A caller that knows only the public Railway IDs cannot create this proof.

The approval API binds only to the Tailscale interface. It uses the Tailscale local identity command to require a configured CI tag. It then validates a generic OIDC policy, the project claim, the environment claim, the reusable workflow revision, and the token replay identifier.

The registry uses the Railway project ID and environment ID as its stable key. Readable DNS aliases are separate, approved values. Environment names remain descriptive values.

The edge stores registrations, leases, certificates, route allocations, OIDC replay records, and audit events in SQLite on the DigitalOcean volume.

`TB_REGISTRATION_FROZEN` blocks all new requests and approvals. `TB_NEW_PROJECTS_FROZEN` blocks the first environment for an unknown project. It permits new environments for projects that are already known. Both controls permit certificate and lease renewal for active identities.

The default virtual pool is `fd40::/10`. Each active connector receives one `/16`. The pool contains 64 allocations before exclusions. It does not overlap Railway's `fd12::/16` prefix.

## Components

The Tailbridge edge runs Tailscale in kernel mode. It also runs the QUIC server and the transparent proxy.

The Tailbridge connector runs inside Railway. It creates the outbound QUIC session and opens private service connections.

## TCP path

The Tailbridge edge uses nftables TPROXY rules for traffic from `tailscale0`. TPROXY preserves the original destination address.

The Tailbridge edge terminates the client TCP connection. It opens one QUIC stream for that flow.

The Tailbridge connector validates the destination. It then opens a new TCP connection inside Railway.

Each TCP flow has an independent QUIC stream. Packet loss on one stream does not block other streams.

## UDP path

The Tailbridge edge receives redirected UDP datagrams. Linux supplies the original destination through socket control data.

The Tailbridge edge assigns a flow identifier. It sends each application datagram through a QUIC datagram.

The Tailbridge connector keeps one UDP socket for each flow. It closes these sockets when the active QUIC session ends.

Traffic in either direction refreshes the idle timeout. Idle mappings expire after the configured timeout.

QUIC does not retry application datagrams. This behavior preserves UDP semantics.

## DNS path

Tailscale sends all `railway.internal` queries to one stable resolver on the edge.

The resolver accepts names in this form:

```text
service.project-alias.environment-alias.railway.internal
```

The edge looks up the approved aliases. It sends the query through the active connector for that registration. The connector removes the project and environment labels before it queries Railway private DNS.

The connector removes IPv4 records. It translates Railway private IPv6 answers into the allocated virtual `/16`.

The edge returns `NXDOMAIN` for an unknown alias. It returns `SERVFAIL` when the registration exists but its connector is not ready.

## Deployment replacement

When a newer connector session becomes ready, the Tailbridge edge marks the previous session as draining.

The active session and the draining session overlap for up to 15 seconds. The edge then closes the draining session.

Each connector session accepts the intersection of the edge routes and connector destinations.

The Tailbridge edge and Tailbridge connector enforce the accepted routes for that session.

New flows use the active session. Existing TCP flows remain on the draining session during the drain interval.

Existing UDP flows stay bound to the draining session. The edge accepts responses only from their original session.

The Tailbridge edge closes these UDP flows when the draining session ends.

The handshake includes the Tailbridge connector process start time.

The Tailbridge edge rejects an older process while a newer process is active. This rule stops an old replica from reclaiming the session.

The Tailbridge connector has no Tailscale identity. Railway replacement cannot create a duplicate Tailscale device.

## Trust model

Tailscale authenticates users, the Tailbridge edge, and the CI approval caller. Mutual TLS authenticates the Tailbridge edge and each approved connector.

Connector certificates use protocol version 3. Their SPIFFE path contains the Railway project ID, environment ID, and identity-key ID. Static connectors continue to use protocol version 2 during the migration release.

The Tailbridge edge and Tailbridge connector enforce destination CIDRs. Tailnet grants provide the first authorization layer.
