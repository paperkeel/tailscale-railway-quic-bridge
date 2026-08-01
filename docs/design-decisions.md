# Design decisions

## Use a paired bridge

Railway does not give a service a public UDP listener. A Tailscale node in Railway can therefore fail to make a direct WireGuard path.

Tailbridge puts the Tailscale node on a host with a public UDP port. The Railway component makes an outbound QUIC connection to that host. This design keeps the Tailscale client configuration unchanged.

## Do not use a custom DERP server

A custom DERP server is still a relay. It does not create a direct path to a Railway node. It also changes the DERP map for the tailnet.

Tailscale recommends a peer relay when normal DERP performance is not sufficient. Tailbridge uses a different model. It advertises the Railway private subnet from a direct Tailscale edge and uses a dedicated backhaul for that subnet.

See the [Tailscale DERP server documentation](https://tailscale.com/docs/reference/derp-servers).

## Do not put Cloudflare in the required data path

Cloudflare Tunnel and Cloudflare Mesh can connect private networks. They require Cloudflare client or network configuration in addition to Tailscale. Cloudflare Spectrum can proxy UDP, but general UDP support requires an Enterprise add-on.

Cloudflare can protect a separate administration site or receive telemetry. Tailbridge does not require it for data forwarding.

See the [Cloudflare connection method guide](https://developers.cloudflare.com/learning-paths/replace-vpn/connect-private-network/connection-methods/) and [Spectrum plan table](https://developers.cloudflare.com/spectrum/protocols-per-plan/).

## Use Go

Go has maintained implementations for QUIC, TLS, Linux sockets, and OpenTelemetry. It also produces static binaries for small container images.

The connector image uses a non-root distroless base. The edge image extends the official Tailscale image because it needs Tailscale, nftables, and network capabilities.

## Use one pair for one Railway environment

Railway service names resolve inside an environment. One connector can therefore reach all allowed services in that environment.

The first release uses one active connector session. A new Railway deployment replaces the active session and drains the old session. Separate environments use separate pairs and connector identifiers.
