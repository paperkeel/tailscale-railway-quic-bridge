# Performance testing

Use this test to compare direct Tailscale access with the Tailbridge relay path.

## Test procedure

1. Deploy `performance-test/Dockerfile` to a Railway service.
2. Set `PORT=8080` for the service.
3. Join the service to the test tailnet.
4. Deploy the Tailbridge edge and connector.
5. Approve the edge route for the Railway IPv6 range.
6. Make the test client accept Tailscale subnet routes.

```bash
sudo tailscale set --accept-routes=true
```

Linux and BSD clients do not accept subnet routes by default. Configure each test
client, or enforce the `UseTailscaleSubnets` system policy on supported managed
clients. Tailscale does not provide a tailnet policy setting that changes this
default for every unmanaged Linux client.

7. Get the `fd12::/16` Railway private IPv6 address from `ip -j addr` in the test service.
8. Get the direct Tailscale address from `tailscale ip -4` in the test service.
9. Confirm that both health requests return `ready`.

```bash
curl http://DIRECT_TAILSCALE_IP:8080/healthz
curl -g 'http://[RAILWAY_IPV6_ADDRESS]:8080/healthz'
```

10. Run the comparison script with both addresses.

```bash
performance-test/run-comparison.sh \
  http://DIRECT_TAILSCALE_IP:8080 \
  'http://[RAILWAY_IPV6_ADDRESS]:8080' \
  docs/performance-testing/results/TEST_NAME
```

The script runs each latency stage for 60 seconds. It makes one HTTP request per second.

The script runs each throughput stage for 60 seconds. It downloads a generated 16 GiB response and discards the data.

The direct path uses the performance service's Tailscale node. The relay path uses the edge subnet route and the Tailbridge connector.

Do not compare results from different clients, regions, service sizes, or test durations.

## Recorded test

See [2026-08-03 development test](results/2026-08-03-development/README.md) for the first external test record.
