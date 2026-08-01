# Changelog

This project uses Semantic Versioning.

## 0.1.0-alpha.2 - 2026-08-01

### Changed

- Cross-compile multi-platform images on the native runner architecture.
- Cache container layers between CI and release builds.
- Use OCI provenance on private repositories and add GitHub attestations after publication.

## 0.1.0-alpha.1 - 2026-08-01

### Added

- Direct Tailscale edge with a QUIC backhaul to Railway.
- Transparent IPv6 TCP and UDP forwarding.
- Mutual TLS with URI identities and 90-day leaf certificates.
- Stable Tailscale state and ordered Railway deployment replacement.
- Railway, Docker Compose, and DigitalOcean deployment templates.
- JSON logs, Prometheus metrics, OpenTelemetry traces, and Sentry error reporting.
- Multi-platform container release workflow with provenance and SBOM data.
