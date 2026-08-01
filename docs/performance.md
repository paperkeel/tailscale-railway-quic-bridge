# Performance tests

1. Measure Tailbridge in the actual Railway environment.

   Local tests cannot reproduce Railway networking.

2. Use the same client, Railway region, service, payload, and test period for each path.

3. Stop unrelated workloads during a test.

## Confirm the Tailscale path

1. Run these commands on the client:

   ```bash
   tailscale ping tailbridge-production
   tailscale status
   tailscale netcheck
   ```

2. Confirm that the ping result names the Tailbridge edge public address as a direct endpoint.

3. Do not accept a DERP or peer-relay result for a Tailbridge measurement.

## Required paths

1. Define one target for each path:

| Path | Test target | Required path check |
|---|---|---|
| Railway public TCP proxy | `RAILWAY_PUBLIC_HOST` and `RAILWAY_PUBLIC_PORT` | The target is the Railway public proxy. |
| Tailscale public DERP | `DERP_BASELINE_HOST` and `DERP_BASELINE_PORT` | `tailscale ping DERP_BASELINE_HOST` reports `via DERP`. |
| Tailscale peer relay | `PEER_RELAY_HOST` and `PEER_RELAY_PORT` | `tailscale ping PEER_RELAY_HOST` reports `via peer relay`. |
| Complete Tailbridge path | `iperf.railway.internal` and the service port | `tailscale ping tailbridge-production` reports the edge public address. |

2. Set `TEST_HOST` and `TEST_PORT` to one row before each test.

3. Run the required path check before each measurement.

4. Skip the peer-relay path when the tailnet does not use a peer relay.

5. Record the QUIC byte counters before and after each Tailbridge test. Use the difference as the test byte count.

6. Record QUIC round-trip samples in microseconds.

7. Verify that the edge and connector negotiated QUIC DATAGRAM support.

8. Record `SendDatagram` failures separately from receiver-observed loss. Record `DatagramTooLargeError` failures separately from other send failures.

## TCP tests

1. Test the forward direction with one, four, and 32 streams:

   ```bash
   iperf3 -c "$TEST_HOST" -p "$TEST_PORT" -t 30 -P 1 --json
   iperf3 -c "$TEST_HOST" -p "$TEST_PORT" -t 30 -P 4 --json
   iperf3 -c "$TEST_HOST" -p "$TEST_PORT" -t 30 -P 32 --json
   ```

2. Test the reverse direction with four streams:

   ```bash
   iperf3 -c "$TEST_HOST" -p "$TEST_PORT" -t 30 -P 4 -R --json
   ```

3. Repeat each test five times.

4. Record the median and p95 results.

## UDP tests

1. Test 256-byte and 1,200-byte datagrams.

2. Test rates of 10 Mbps and 100 Mbps:

   ```bash
   iperf3 -c "$TEST_HOST" -p "$TEST_PORT" -u -b 10M -l 256 -t 30 --json
   iperf3 -c "$TEST_HOST" -p "$TEST_PORT" -u -b 100M -l 1200 -t 30 --json
   ```

3. Record loss, jitter, CPU, memory, and QUIC round-trip time.

## Release targets

Tailbridge should reach 70 percent of raw QUIC connection throughput.

Tailbridge should exceed the measured public DERP throughput by at least two times.

UDP loss must not exceed 1 percent at 10 Mbps or 2 percent at 100 Mbps. Apply these limits to each datagram size and direction.

UDP jitter must not exceed two times the Railway public proxy baseline for the same rate and datagram size.

QUIC DATAGRAM send failures must be zero for application datagrams of 1,200 bytes or less. Receiver-observed loss is separate from send failures.

1. Run a one-hour load test before a stable release.

2. Confirm that memory use stays within the configured limits.

## Result record

1. Store these values for each test:

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

2. Remove private addresses and service names from the result.

3. Publish the result with each beta or stable release.
