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
- Approvals through the sandbox proxy: pending requests recorded in the
  sandbox, `tenuo-openshell approve` to review and sign them (hash recomputed
  from what the approver sees), and single-use attachment on retry.
- NeMo Agent Toolkit 1.8 ReAct agent example with a human approval step,
  runnable without a model key, and an in-sandbox approval scenario in the
  OpenShell demo.
- Demo scenario where the sandbox generates its holder key and signs calls at
  run time; documented holder-key custody model.
- Threat model covering assets, trust boundaries, attackers, controls, and
  residual risks.
- cargo-fuzz targets for MCP body parsing, policy loading, and the full
  decision, with committed seeds and a daily and pull-request Fuzz workflow.
- `cargo deny` policy for advisories, licenses, and sources, a Supply chain
  workflow, and Dependabot for Cargo, uv, GitHub Actions, and Docker.
- Optional `HTTP_RESPONSE / PRE_RETURN` binding (`--evaluate-results`): signed
  result receipts with the SHA-256, size, and status of each allowed call's
  result, linked to its authorization receipt, in `<log>.results.jsonl`.
- Per-sandbox `max_result_bytes` withholds larger results with
  `tenuo_result_too_large`, or `tenuo_result_unmeasurable` when a limited
  result cannot be measured.
- Optional OpenTelemetry traces over OTLP gRPC, one span per decision,
  configured by the standard `OTEL_*` variables and off by default.
- `receipts export` verifies a receipt log's signatures and hash chain and
  writes one JSON object per receipt for log pipelines.
- Result metrics: `tenuo_openshell_results_total`,
  `tenuo_openshell_result_receipt_failures_total`, and
  `tenuo_openshell_result_correlation_evictions_total`.
- Helm values for result evaluation and OTLP export.
- The sandbox proxy reports a withheld result as a call that already ran, so
  agents do not retry it as if it were denied.

### Changed

- `approval_replay_protection` defaults to `true`. A policy that omits it
  now makes approvals single-use, which needs Redis in production or
  `--allow-in-memory-replay` for a single-instance evaluation. Set it to
  `false` explicitly to keep the old behavior.
- Deployment guide documents policy-file integrity: the file is unsigned and
  controls authorization.
- Requires Tenuo 0.3.2. The integration now uses Tenuo core for warrant-chain
  encoding (`meta_envelope`), strict JSON parsing in the middleware
  (`parse_json_strict`), approval review and signing (`matches_warrant`,
  `approve_request`), and authorization-receipt chain verification
  (`receipt::verify_chain`), instead of its own copies.
- `tenuo-openshell approve` requires `--trusted-root`. It verifies the pending
  warrant chain to that root and checks the recorded request against the
  warrant before showing anything. Pending requests now carry the request
  Tenuo produced and the warrant chain.
- Receipt export rejects an authorization log signed by more than one key,
  even without `--verify-with`.
- Proofs from Tenuo 0.3.2 cover null argument values. Calls signed by older
  clients that drop `null` arguments are denied; upgrade those clients.
- The demo MCP server no longer rewrites `_meta.tenuo` to standard base64;
  Tenuo 0.3.2 verifiers accept either alphabet.
- GitHub Actions in every workflow are pinned by commit SHA.
- Requests rejected before evaluation (oversized body, invalid binding config,
  missing target) now count in the decision metrics.
- Sandbox policies must list `destinations`: the MCP host, port, optional
  path, and tools each serves. Other destinations, and tools a destination
  does not serve, deny `tenuo_destination_denied`.
- The middleware strips `params._meta.tenuo` on allow unless the binding sets
  `tenuo_meta: preserve`.
- Bodyless Streamable HTTP `GET` and `DELETE` requests are forwarded; other
  bodyless or non-`POST` requests deny.

### Fixed

- The middleware and the in-sandbox agent no longer write Tenuo's per-denial
  message, which can quote argument values, to stderr.
- Denial receipts commit to the sandbox's trusted-roots digest when they are
  built.
- `TENUO_DECISION_LOG` is read once rather than on every decision.
- Decision and replay-cleanup log lines write a JSON-RPC id outside
  `[A-Za-z0-9-_.:/+@]` (or longer than 128 bytes) as `hex:` plus its bytes, so
  a sandbox-chosen id cannot add log lines or fields.
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
