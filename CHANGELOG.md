# Changelog

This project uses Semantic Versioning.

## Unreleased

### Added

- Tailbridge now limits concurrent UDP flows with `TB_MAX_UDP_FLOWS`.
- The metrics endpoint now reports active UDP flows, total UDP flows, and dropped UDP datagrams.

### Changed

- Tailbridge now validates flow limits, listen addresses, log levels, and enabled telemetry sample rates during startup.
- The Tailbridge CLI now validates names and endpoints before it writes configuration files.
- Tailbridge now uses quic-go `v0.61.0` and `golang.org/x/sys` `v0.47.0`.
- The edge image now uses Tailscale `v1.98.8`.

### Fixed

- The Tailbridge CLI now rejects newline and control characters that could inject environment variables.
- The Tailbridge connector now closes UDP flows when their QUIC session ends.
- The Tailbridge connector now rejects changes to the endpoints of an existing UDP flow.
- The Tailbridge edge now binds each UDP response to the session that created its flow.
- TCP copy failures now close both connections and release the flow limit.
- Control exchanges and TCP connection attempts now use deadlines.
- Tailbridge now reports administration listener failures and stops the Tailbridge component that has the failed listener.
- The Tailbridge edge now removes partial network policy changes after an apply failure.
- The Tailbridge edge now uses explicit IPv4 and IPv6 nftables TPROXY targets.
- The Tailbridge CLI now restores the previous generated files when a bundle write fails.

## 0.1.0-alpha.2 - 2026-08-01

### Changed

- The release workflow cross-compiles multi-platform images on the native runner architecture.
- The build workflows cache container layers between CI and release builds.
- Private repositories now use OCI provenance, and public releases receive GitHub attestations.

## 0.1.0-alpha.1 - 2026-08-01

### Added

- Tailbridge added a direct Tailscale edge with a QUIC connection to Railway.
- Tailbridge added transparent IPv6 TCP and UDP forwarding.
- Tailbridge added mutual TLS with URI identities and 90-day leaf certificates.
- Tailbridge added stable Tailscale state and ordered Railway deployment replacement.
- The repository added Railway, Docker Compose, and DigitalOcean deployment templates.
- Tailbridge added JSON logs, Prometheus metrics, OpenTelemetry traces, and Sentry error reporting.
- The repository added a multi-platform container release workflow with provenance and SBOM data.
