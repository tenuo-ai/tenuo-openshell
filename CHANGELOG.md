# Changelog

All notable changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.4] - 2026-10-05

### Added

- A 5-minute [quickstart](docs/quickstart.md) for OpenShell users. It adds
  Tenuo to the gateway OpenShell's installer set up, in development mode,
  and makes an allowed, a denied, and an approval-gated call, with no model
  or API key. `make quickstart` runs it against a gateway laid out like an
  installed one.
- `tenuo-openshell dev up`, `dev down`, and `dev status`:
  - run the middleware (`--insecure-dev`, in-memory replay) and a demo MCP
    server as Docker containers on 127.0.0.1;
  - keep dev keys and policy in `~/.local/state/tenuo-openshell/dev`; and
  - print the `[[openshell.supervisor.middleware]]` block and the gateway
    restart command. They never edit the OpenShell installation.
- `tenuo-openshell demo call <tool> key=value...`: one `tools/call` from the
  sandbox, with a one-line outcome naming who allowed, denied, or held it.
  `--unsigned` sends it without the agent.
- Approval-gated warrants from the CLI (#54): `warrant issue` and
  `provision` take `--approver` (repeatable), `--min-approvals`, and
  `--require-approval <tool>`. `--preset demo` issues the quickstart's task.
- `provision --dev` and `approve --dev` use the dev environment's keys.
  `provision --dev` also adds the sandbox to the dev policy and waits until
  the middleware serves it.
- `ghcr.io/tenuo-ai/tenuo-openshell-demo`: the quickstart's sandbox image
  (the agent and curl) and demo MCP server, built per platform from the
  release's agent binaries.
- `nemo-agent-toolkit-tenuo` supports NVIDIA NeMo Agent Toolkit 1.9
  (`nvidia-nat-core>=1.8,<1.10`). The plugin code is unchanged; CI runs the
  plugin tests and `nat info components` discovery against both 1.8 and 1.9.
  `ci/nat-compat.sh` runs them against a chosen minor release.

### Changed

- Restored the canonical Apache License 2.0 text in source and release
  artifacts.
- Clarified that the documented middleware security scope applies to the
  pinned OpenShell release and removed a broken documentation index link.
- The previous quickstart is now [Going to production](docs/production-quickstart.md),
  run by `make production-quickstart`.
- `tenuo-openshell approve` takes `--request` as optional when one request is
  pending.
- `tenuo-openshell-agent proxy` creates the holder key when there is none, so
  it can start with the sandbox before a warrant is provisioned.
- The plugin's locked development environment uses Agent Toolkit 1.9, which
  moves `cryptography` from 46.0.7 to 48.0.1.
- The NeMo Agent Toolkit example runs on Agent Toolkit 1.9. Since 1.9,
  `nvidia-nat-langchain` installs model providers as extras, so the example
  installs `nvidia-nat-langchain[openai,nvidia]`.
- The OpenShell end-to-end suite installs the plugin with
  `nvidia-nat-core>=1.8,<1.10`.

## [0.1.3] - 2026-10-05

Unpublished release candidate. Superseded by 0.1.4 before artifacts were
published.

## [0.1.2] - 2026-10-05

### Changed

This release tightens production defaults, and existing deployments need
these changes when they upgrade:

1. **Sign the policy.** Run `tenuo-openshell keygen --out
   policy-signing.key` once, then `tenuo-openshell policy sign` for every
   version. Pass the printed public key as `--policy-signing-key`. With Helm,
   put `policy.json.sig` in the policy ConfigMap and the public key in the
   Secret named by `policy.signingKeySecret`
   (default `tenuo-openshell-policy-key`). `--allow-unsigned-policy` keeps the
   old behavior.
2. **Use `rediss://` with a password** for the replay store.
   `--allow-plaintext-replay` keeps the old behavior.
3. **Move `tenuo_meta: preserve`** from the OpenShell attachment to
   `"forward_proof": "preserve"` on the sandbox in the Tenuo policy. An
   attachment that still sets `preserve` fails `ValidateConfig`.
4. **List idempotent tools.** Every tool is now single-use, so an identical
   call inside one 30-second proof window is denied `tenuo_pop_replayed`.
   List read-only tools an agent may repeat in `idempotent_tools`.
5. **Approvals.** `approval_replay_protection: false` now also needs
   `--allow-reusable-approvals` in production.

### Security

- Every tool accepts a signed call once, unless it is listed in
  `idempotent_tools`. This is interim until proofs carry a per-call nonce
  (#21).
- Production refuses a replay Redis URL that is not `rediss://` with a
  password and hostname verification.
- `forward_proof` on the operator policy decides whether a destination
  receives the proof.
- Production requires a policy signed with `--policy-signing-key`.
- Production refuses reusable approvals unless explicitly allowed.

### Added

- `tenuo-openshell keygen --out FILE [--public-out FILE]` creates issuer,
  approver, and policy signing keys. It never overwrites a file and prints the
  public key in the form `--trusted-root` and `--policy-signing-key` accept.
  `policy keygen` is an alias.
- `tenuo-openshell policy sign`, and `--sign-with KEY` on `policy init` and
  `policy add`, which sign each version as it is written.
- `tenuo-openshell policy init` creates a policy that trusts no sandboxes.
- The middleware starts on a policy with `"sandboxes": {}`, denies every
  request, and reports ready. It no longer needs a placeholder sandbox before
  the first one exists. A missing policy file is still an error, and now
  suggests `policy init`.
- The `tenuo_openshell_policy_sandboxes` metric counts trusted sandboxes.
- `tenuo-openshell register --only gateway|sandbox` prints one block.
  The default output is unchanged.
- `tenuo-openshell register --insecure-dev` registers an `http://` endpoint
  with `allow_insecure_transport` for a local `--insecure-dev` middleware.
  Without it, `register` now requires an `https://` endpoint and `--ca`.
- When OpenShell itself denies a call (`policy_denied`, an MCP protocol check,
  `middleware_failed`, or another middleware's reason code), the sandbox proxy
  reports OpenShell's code and detail instead of `forbidden`, and adds
  OpenShell's bounded denial fields under `data.tenuo.openshell`. Tenuo
  middleware codes still start with `tenuo_` and keep their messages.
- `tenuo-openshell register --openshell-policy` refuses to print a gateway
  block when an endpoint that can match a protected host is L4 TCP (no
  `protocol`, or `tcp`), `websocket`, `sql`, or `tls: skip`. It matches hosts
  with OpenShell's host-pattern rules.
- The sandbox proxy explains `tenuo_pop_replayed` as a duplicate of a call
  that was already accepted.
- The demo signs every policy version it writes.
- [Quickstart](docs/quickstart.md): one allowed and two denied calls on an
  OpenShell gateway from released artifacts, checked end to end by
  `make quickstart`.
- [Issuing warrants in production](docs/production-issuance.md): Tenuo Cloud
  as the managed issuer, where each key lives, per-request issuance for
  multi-user platforms (#17), and rotation.
- `examples/issuance/`, a minimal per-request issuance service on the public
  `tenuo` Python package, with a test that installs its warrants with the
  real agent.
- `make bench` (`scripts/bench.sh`) and `tenuo-openshell-bench`, which drive
  the release middleware over gRPC with in-memory and Redis replay stores, and
  [Performance](docs/performance.md) with the method and results. The README
  now cites release-build numbers instead of a debug-build sample.
- `register --only gateway` does not need `--mcp-host`, and `policy init
  --sign-with` writes the signature before the policy.

### Deprecated

- `single_use_tools` and `tenuo-openshell policy add --single-use` have no
  effect and log a warning.

## [0.1.1] - 2026-10-04

### Added

- `ghcr.io/tenuo-ai/tenuo-openshell-agent`, a signed `linux/amd64` and
  `linux/arm64` image that holds only the static agent binary. A sandbox
  Dockerfile adds the agent with one `COPY --from` line.
- The Helm chart is published to GHCR as
  `oci://ghcr.io/tenuo-ai/charts/tenuo-openshell` and signed with cosign.

### Changed

- The release builds each middleware image platform on a native runner.

## [0.1.0] - 2026-10-04

First release.

### Supervisor middleware

- OpenShell `HTTP_REQUEST / PRE_CREDENTIALS` supervisor middleware for MCP
  Streamable HTTP. It verifies each `tools/call` against a Tenuo warrant chain
  before credential injection. It checks the destination, the holder's proof
  of possession, argument constraints, signed approvals, and revocation.
- Production by default: server TLS and OpenShell extension JWT verification
  are required, and partial security configuration refuses to start.
- Trust policy keyed by OpenShell's authenticated `sandbox_id`. Each sandbox
  lists its trusted roots, and the MCP destinations it may reach with the
  tools each serves. Other destinations deny `tenuo_destination_denied`.
- Single-use approvals across replicas, backed by Redis or Redis Cluster
  (`redis://` or `rediss://`). `single_use_tools` accepts each proof for a
  listed tool once.
- Versioned policy hot reload that keeps the last valid snapshot. Signed
  revocation lists with freshness bounds and persistent rollback floors.
- Strict MCP parsing. Lifecycle methods pass through an allowlist, other
  methods deny, and `mcp.passthrough_methods` and `mcp.allow_client_responses`
  are per-sandbox opt-ins. `params._meta.tenuo` is stripped on allow unless
  the binding sets `tenuo_meta: preserve`.
- Signed, hash-chained authorization receipts, which can be required before an
  allow (`--require-receipts`). With `--evaluate-results`, the optional
  `HTTP_RESPONSE / PRE_RETURN` binding adds signed result receipts and a
  per-sandbox `max_result_bytes` limit. `receipts export` verifies receipt
  logs and writes them as JSON lines.
- `/live` and `/ready` endpoints, Prometheus metrics, and optional
  OpenTelemetry traces. Logs never contain argument values, and log lines
  cannot be forged through JSON-RPC ids.

### Sandbox agent and operator CLI

- `tenuo-openshell-agent` runs inside the sandbox. It generates and holds the
  task's key and holds its warrant, from a file or `TENUO_WARRANT`. A
  loopback MCP proxy signs each `tools/call`, so the agent's MCP client needs
  no changes. Out-of-warrant calls are denied locally, and middleware denials
  come back as JSON-RPC errors.
- Approvals: pending requests are recorded in the sandbox.
  `tenuo-openshell approve` verifies the request against the warrant and a
  trusted root, shows the exact tool and arguments, and signs them. Each
  approval authorizes one call.
- Sub-agent delegation: `tenuo-openshell-agent delegate` attenuates the
  warrant to a sub-agent's key, and `tenuo-openshell delegate` does the same
  across sandboxes. `--terminal` prevents further delegation. Revoking any
  warrant in a chain denies every call that carries it.
- `tenuo-openshell` also provides `policy add`, `register`, `warrant issue`,
  `provision`, and `receipts export`.

### NeMo Agent Toolkit

- `nemo-agent-toolkit-tenuo`, an Agent Toolkit 1.8 middleware plugin that
  denies unauthorized function calls before `call_next`, using
  application-scoped authority.
- A ReAct agent example with a human approval step that runs without a model
  key.

### Deployment and supply chain

- HA Helm chart with Redis replay, persistent receipts and rollback floors,
  probes, a pod disruption budget, a default-deny NetworkPolicy, and a
  read-only root filesystem.
- Non-root container image for `linux/amd64` and `linux/arm64`, with SBOM and
  build provenance, signed with keyless cosign.
- Static musl binaries of `tenuo-openshell-agent` and `tenuo-openshell` for
  Linux x86_64 and aarch64, and `tenuo-openshell` for macOS arm64. They are
  signed with keyless cosign, listed in `SHA256SUMS`, and attested.
- Threat model, architecture, deployment, operations, receipts, and provider
  documentation.
- cargo-fuzz targets for MCP parsing, policy loading, and the full decision.
  cargo-deny checks advisories, licenses, and sources. GitHub Actions are
  pinned by commit.

### Demo

- An authenticated demo against a pinned, real OpenShell v0.1.2 gateway. It
  compares every scenario with and without Tenuo, confirms that denied calls
  never reach the tool, and verifies every receipt offline. It also covers an
  A2A handoff and an unmodified MCP SDK client.

### Compatibility

- NVIDIA OpenShell v0.1.2 (`6648bd0c290efbc41ba131ee9831ee45cd431f94`),
  supervisor middleware protocol `openshell.middleware.v1` 1.0.
- NVIDIA NeMo Agent Toolkit `nvidia-nat-core` 1.8.x.
- Tenuo 0.3.2 or later within 0.3.

[Unreleased]: https://github.com/tenuo-ai/tenuo-openshell/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/tenuo-ai/tenuo-openshell/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/tenuo-ai/tenuo-openshell/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/tenuo-ai/tenuo-openshell/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tenuo-ai/tenuo-openshell/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tenuo-ai/tenuo-openshell/releases/tag/v0.1.0
