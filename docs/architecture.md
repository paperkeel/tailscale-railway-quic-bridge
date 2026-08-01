# Architecture

## Goal

Tailbridge removes DERP from the default network path to Railway private services.

The client connects directly to the Tailbridge edge. The Tailbridge edge forwards each flow through the outbound Tailbridge connector.

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

The Tailbridge connector keeps one UDP socket for each flow in the active QUIC session. It closes these sockets when the session ends.

Traffic in either direction refreshes the idle timeout. Idle mappings expire after the configured timeout.

QUIC does not retry application datagrams. This behavior preserves UDP semantics.

## DNS path

Tailscale sends `railway.internal` queries to `fd12::10`. The advertised Railway route includes this resolver.

The Tailbridge edge and Tailbridge connector forward DNS like other UDP or TCP traffic.

## Deployment replacement

When a newer connector session becomes ready, the Tailbridge edge marks the previous session as draining.

The active session and the draining session overlap for up to 15 seconds. The Tailbridge edge then closes the draining session.

Each connector session accepts the intersection of the edge routes and connector destinations.

The Tailbridge edge and Tailbridge connector enforce the accepted routes for that session.

New flows use the active session. Existing TCP flows remain on the draining session during the drain interval.

Existing UDP flows stay bound to the draining session. The edge accepts responses only from the session that created each flow.

The Tailbridge edge closes these UDP flows when the draining session ends.

The handshake includes the Tailbridge connector process start time.

The Tailbridge edge rejects an older process while a newer process is active. This rule prevents an old replica from reclaiming the session.

The Tailbridge connector has no Tailscale identity. Railway replacement cannot create a duplicate Tailscale device.

## Trust model

Tailscale authenticates users and the Tailbridge edge. Mutual TLS authenticates the Tailbridge edge and Tailbridge connector.

The Tailbridge edge and Tailbridge connector enforce destination CIDRs. Tailnet grants provide the first authorization layer.
