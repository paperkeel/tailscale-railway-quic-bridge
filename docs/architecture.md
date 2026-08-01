# Architecture

## Goal

Tailbridge removes DERP from normal access to Railway private services.

The client connects directly to a public Tailscale subnet router. The subnet router forwards each flow through an outbound Railway connector.

## Components

The edge container runs Tailscale in kernel mode. It also owns the QUIC server and transparent proxy.

The connector runs inside Railway. It creates the outbound QUIC session and opens private service connections.

## TCP path

The edge uses nftables TPROXY rules on traffic from `tailscale0`. TPROXY preserves the original destination address.

The edge terminates the client TCP connection. It opens one QUIC stream for that flow.

The connector validates the destination. It then opens a new TCP connection inside Railway.

Each TCP flow has an independent QUIC stream. Packet loss on one stream does not block other streams.

## UDP path

The edge receives redirected UDP datagrams. Linux supplies the original destination through socket control data.

The edge assigns a flow identifier. It sends each application datagram through a QUIC datagram.

The connector keeps one UDP socket for each flow. Idle mappings expire after the configured timeout.

QUIC does not retry application datagrams. This behavior preserves UDP semantics.

## DNS path

Tailscale sends `railway.internal` queries to `fd12::10`. The advertised Railway route includes this resolver.

The edge and connector forward DNS like other UDP or TCP traffic.

## Deployment replacement

The edge accepts a new connector session before it drains the previous session.

New flows use the newest ready session. Existing TCP flows remain on the old session during the drain interval.

The handshake includes the connector process start time. The edge rejects an older process while a newer process is active. This rule prevents an old Railway replica from reclaiming the session during deployment overlap.

The Railway connector has no Tailscale identity. Railway replacement cannot create a duplicate Tailscale device.

## Trust model

Tailscale authenticates users and the edge. Mutual TLS authenticates the edge and connector.

Both components enforce destination CIDRs. Tailnet grants provide the first authorization layer.
