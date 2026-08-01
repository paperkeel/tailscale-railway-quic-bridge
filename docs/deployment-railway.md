# Deploy the Railway connector

Create a Railway service from this repository. Set its Dockerfile to `Dockerfile.connector`.

Import the values from the generated `connector.env` file as Railway variables.

Do not create a public domain. Do not create a TCP proxy.

Railway uses `/readyz` for deployment health. The connector listens on the Railway `PORT` value. It uses port `9002` when Railway does not set `PORT`.

Enable outbound IPv6 only if the selected edge endpoint needs IPv6. Railway private IPv6 works without that setting.

Deploy the service. The logs must show `edge session ready`.

Confirm these checks:

1. `/readyz` returns HTTP 200 inside Railway.
2. The edge reports one ready connector.
3. `fd12::10` responds through the pair.
4. A private service accepts a test connection.

The connector needs no volume. It does not join Tailscale.

Railway can overlap a new connector with the old connector. The edge sends new flows to the newest session.
