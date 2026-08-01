# Performance tests

Measure Tailbridge against the actual Railway environment. Local tests cannot reproduce Railway networking.

Use the same client, Railway region, service, payload, and test period for each path. Stop unrelated workloads during a run.

## Confirm the Tailscale path

Run these commands on the client:

```bash
tailscale ping tailbridge-production
tailscale status
tailscale netcheck
```

The ping result must name the edge public address as a direct endpoint. Do not accept a DERP or peer-relay result for a Tailbridge measurement.

## Required paths

Measure:

1. Railway public TCP proxy.
2. Tailscale public DERP.
3. Tailscale peer relay, when the tailnet uses one.
4. The complete Tailbridge path.

Capture the QUIC byte, loss, and round-trip metrics before and after each Tailbridge run.

## TCP tests

Run `iperf3` with one, four, and 32 streams. Test both directions for 30 seconds.

```bash
iperf3 -c iperf.railway.internal -t 30 -P 1 --json
iperf3 -c iperf.railway.internal -t 30 -P 4 --json
iperf3 -c iperf.railway.internal -t 30 -P 32 --json
iperf3 -c iperf.railway.internal -t 30 -P 4 -R --json
```

Repeat each test five times. Record the median and p95 results.

## UDP tests

Test 256-byte and 1,200-byte datagrams. Test 10 Mbps and 100 Mbps rates.

```bash
iperf3 -c iperf.railway.internal -u -b 10M -l 256 -t 30 --json
iperf3 -c iperf.railway.internal -u -b 100M -l 1200 -t 30 --json
```

Record loss, jitter, CPU, memory, and QUIC round-trip time.

## Release targets

Tailbridge should reach 70 percent of raw QUIC backhaul throughput.

It should exceed the measured public DERP throughput by at least two times.

Run a one-hour load test before a stable release. Memory must remain bounded.

## Result record

Store these values for each run:

| Field | Value |
|---|---|
| Commit and image digest | Required |
| Client and edge region | Required |
| Railway region | Required |
| Tailscale path from `tailscale ping` | Required |
| Round-trip time | Median and p95 |
| TCP throughput | Median and p95 |
| UDP loss and jitter | Median and p95 |
| Edge and connector CPU | Peak and average |
| Edge and connector memory | Peak and average |

Publish the redacted result with each beta or stable release. Do not publish private addresses or service names.
