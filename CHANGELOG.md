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
- `single_use_tools` accepts each proof of possession for a listed tool once
  across the deployment; resends deny `tenuo_pop_replayed`.
- Per-sandbox `mcp.passthrough_methods` and `mcp.allow_client_responses`.
- `tenuo-openshell-agent`: in-sandbox holder key, warrant from a file or
  `TENUO_WARRANT`, and a loopback MCP proxy that signs `tools/call`, denies
  out-of-warrant calls locally, and turns OpenShell denials into JSON-RPC
  errors.
- `tenuo-openshell`: `policy add`, `register`, `warrant issue`, and
  `provision` operator commands.
- Demo scenario with an unmodified MCP Python SDK client through the signing
  proxy.
- Demo scenario where the sandbox generates its holder key and signs calls at
  run time; documented holder-key custody model.

### Changed

- Sandbox policies must list `destinations`: the MCP host, port, optional
  path, and tools each serves. Other destinations, and tools a destination
  does not serve, deny `tenuo_destination_denied`.
- The middleware strips `params._meta.tenuo` on allow unless the binding sets
  `tenuo_meta: preserve`.
- Bodyless Streamable HTTP `GET` and `DELETE` requests are forwarded; other
  bodyless or non-`POST` requests deny.

### Fixed

- Denial receipts commit to the sandbox's trusted-roots digest when they are
  built.
- `TENUO_DECISION_LOG` is read once rather than on every decision.
- Unified approval replay semantics across in-memory, standalone Redis, and
  Redis Cluster backends; approval nonces are single-use per deployment.
- Release approval reservations when required receipt persistence prevents an
  effect from being allowed. Unconfirmed cleanup remains a bounded pending
  lease instead of being reported as a consumed approval replay. An allow
  receipt is written only after the approval nonce commit succeeds.
- Label enforcement-decision timing accurately when it includes replay and
  receipt I/O.
- Restricted admin and DNS NetworkPolicy rules, made DNS selectors configurable,
  aligned Helm and release image tags, and scaled voluntary disruption policy.

There has not yet been a public release.
