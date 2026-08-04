# Security

Tailbridge extends a private tailnet into a Railway environment. Treat both containers as network infrastructure.

## Authentication

Tailscale authenticates users and the edge. Mutual TLS authenticates the Tailbridge edge and connector.

Each certificate contains a URI identity. A dynamic connector identity contains the Railway project ID, environment ID, and identity-key ID.

The edge validates OIDC tokens with configured issuer, JWKS, audience, and claim rules. GitHub is the documented default profile. Other OIDC providers can use the same policy model.

The edge stores a hash of each accepted replay claim until the token expires.

## Authorization

Use narrow Tailscale grants. Permit only the required users, destinations, and ports.

Both Tailbridge components also validate destination CIDRs. A connector cannot request an undeclared route.

## Secrets

Generated environment files contain private keys. Store them with mode `0600`.

The online intermediate key exists on the edge. It issues 24-hour connector and edge certificates and renews them after 12 hours. Rotate the 30-day intermediate with a seven-day overlap. Rotate the root each year through a controlled SST update. Keep the root key in the SST state and out of the edge container.

The connector prepares a new identity key after one year. A deployment nonce and OIDC approval authorize the rotation. The old identity stays valid for a 24-hour overlap and becomes inactive only after the new identity completes a QUIC session.

Do not commit environment files. Do not place secrets in image build arguments.

The recovery process requires a tagged, preauthorized, non-ephemeral Tailscale credential.

An ephemeral credential cannot restore a stable Tailscale machine identity.

## Exposure

Expose only UDP `41641`, `4433`, and `4434` publicly on the edge. Permit SSH only from the configured `sshSourceCidrs` for SST deployment. Keep administration and approval endpoints private. Bind the approval API and DNS resolver to the Tailscale interface.

The Railway connector needs no public endpoint.

Run the connector as an unprivileged user. Do not give it Linux capabilities or access to `/dev/net/tun`.

Give network capabilities only to the edge. Verify this privilege boundary in each deployment manifest before release.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting. Do not open a public issue for an active vulnerability.
