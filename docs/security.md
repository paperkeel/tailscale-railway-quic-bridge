# Security

Tailbridge extends a private tailnet into a Railway environment. Treat both containers as network infrastructure.

## Authentication

Tailscale authenticates users and the edge. Mutual TLS authenticates the Tailbridge edge and connector.

Each certificate contains a URI identity. The peer validates the role and connector identifier.

## Authorization

Use narrow Tailscale grants. Permit only the required users, destinations, and ports.

Both Tailbridge components also validate destination CIDRs. A connector cannot request an undeclared route.

## Secrets

Generated environment files contain private keys. Store them with mode `0600`.

Do not commit environment files. Do not place secrets in image build arguments.

## Exposure

Expose only UDP `41641` and `4433` on the edge. Keep administration endpoints private.

The Railway connector needs no public endpoint.

Run the connector as an unprivileged user. Do not give it Linux capabilities or access to `/dev/net/tun`.

Give network capabilities only to the edge. Verify this privilege boundary in each deployment manifest before release.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting. Do not open a public issue for an active vulnerability.
