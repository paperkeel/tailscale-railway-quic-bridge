# Deploy the Tailbridge connector on Railway

1. Create a Railway service from this repository.

2. Set the service Dockerfile to `Dockerfile.connector`.

3. Import the generated `connector.env` values as Railway variables.

4. Do not create a public domain.

5. Do not create a TCP proxy.

6. Configure Railway to use `/readyz` for deployment health.

   The Tailbridge connector listens on `PORT`. It uses port `9002` when Railway does not set `PORT`.

7. If the edge endpoint needs IPv6, enable outbound IPv6.

   Railway private IPv6 works without outbound IPv6.

8. Deploy the service.

9. Confirm that the logs show `edge session ready`.

10. Confirm that `/readyz` returns HTTP 200 inside Railway.

11. Confirm that the Tailbridge edge reports one ready Tailbridge connector.

12. Confirm that `fd12::10` responds through the Tailbridge edge and Tailbridge connector.

13. Confirm that a private service accepts a test connection.

The Tailbridge connector needs no volume. It does not join Tailscale.

Railway can overlap two Tailbridge connector deployments. The Tailbridge edge sends new flows to the newest session.
