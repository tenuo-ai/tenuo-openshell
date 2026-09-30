# Changelog

All notable changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- OpenShell `HTTP_REQUEST / PRE_CREDENTIALS` supervisor middleware with secure
  TLS and JWT defaults.
- Tenuo warrant, proof-of-possession, constraint, approval, and replay checks.
- NeMo Agent Toolkit 1.8 middleware plugin with application-scoped authority.
- Authenticated real-gateway demo, offline signed receipt audit, baseline
  comparison, and A2A interoperability proof.
- Redis-backed atomic cross-replica approval replay protection.
- Atomic versioned policy reload, signed revocation enforcement with persistent
  rollback floors, health/readiness endpoints, and Prometheus metrics.
- Hardened HA Helm deployment with required receipt persistence and network
  isolation.
- Native Redis Cluster replay support and provider-neutral policy readiness.

### Fixed

- Unified approval replay semantics across in-memory, standalone Redis, and
  Redis Cluster backends; approval nonces are single-use per deployment.
- Release approval reservations when required receipt persistence prevents an
  effect from being allowed. Unconfirmed cleanup remains a bounded pending
  lease instead of being reported as a consumed approval replay.
- Label enforcement-decision timing accurately when it includes replay and
  receipt I/O.
- Restricted admin and DNS NetworkPolicy rules, made DNS selectors configurable,
  aligned Helm and release image tags, and scaled voluntary disruption policy.

There has not yet been a public release.
