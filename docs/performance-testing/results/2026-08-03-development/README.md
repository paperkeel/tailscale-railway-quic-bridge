# Development performance test: 2026-08-03

## Result

Tailbridge carried HTTP traffic through the approved Railway IPv6 route.

| Path | Samples | Mean latency | P50 latency | P95 latency | Throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| Direct Tailscale | 53 | 132.536 ms | 130.330 ms | 148.100 ms | 0.096 Mbps |
| Tailbridge relay | 51 | 155.174 ms | 153.159 ms | 159.080 ms | 158.030 Mbps |

The relay added 22.638 ms to the mean application latency. It delivered approximately 1,646 times the direct throughput.

These results apply only to this test setup. They are not a general Tailscale or Railway benchmark.

## Connector-to-edge latency

The edge sampled the QUIC connection statistics every five seconds for one minute.
The 12 samples measured the connection between DigitalOcean SFO3 and Railway
`us-west2`.

| Samples | Mean RTT | Minimum RTT | Maximum RTT | Target |
| ---: | ---: | ---: | ---: | ---: |
| 12 | 2.208 ms | 2.187 ms | 2.219 ms | Less than 25 ms |

All samples met the target. The measured connector-to-edge RTT was approximately
1.4 percent of the 155.174 ms relay application latency.

The result shows that the QUIC connection did not cause most of the application
latency. The application measurement also included the client, Tailscale subnet
route, TCP setup, HTTP processing, and Railway service path.

## Test setup

- Date: 2026-08-03 UTC
- Release: `internal-testing`
- Branch: `development`
- Client: Linux workstation in the central United States
- Edge: DigitalOcean SFO3, Ubuntu 24.04, 1 vCPU, 2 GiB RAM
- Tailscale edge version: 1.98.8
- Connector: Railway `us-west2`
- Performance service: Railway `us-west2`
- Direct target: Railway performance service through Tailscale userspace networking
- Relay target: Railway private IPv6 through the approved `fd12::/16` subnet route
- Payload: generated 16 GiB HTTP response
- Latency duration: 60 seconds for each path
- Throughput duration: 60 seconds for each path

Before the test, `tailscale ping` reached the direct target through DERP SFO. It reached the edge through direct UDP after the test.

The direct path changed from DERP to a direct peer path after the benchmark. The recorded CSV files contain application results only.

## Evidence

- `direct-latency.csv` contains all direct latency samples.
- `direct-throughput.csv` contains the direct transfer result.
- `relay-latency.csv` contains all relay latency samples.
- `relay-throughput.csv` contains the relay transfer result.
- `connector-quic-rtt.csv` contains the connector-to-edge RTT samples.
- The two summary files contain the calculated values in the table.

The direct transfer received 719,356 bytes before the 60-second limit. The relay transfer received 1,185,209,461 bytes before the same limit.

Neither transfer completed the generated 16 GiB response before the limit.

## Reproduction

1. Complete the procedure in [Performance testing](../../README.md).
2. Confirm that `/healthz` returns `ready` through both paths.
3. Run `performance-test/run-comparison.sh` with the direct and relay addresses.
4. Keep the raw CSV files with the result record.
5. Record the Tailscale peer path before and after the test.
