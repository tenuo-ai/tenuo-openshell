# Threat model

This page states what the supervisor middleware protects, from whom, where
each control is enforced, and what remains exposed. It covers the Rust
middleware in this repository as pinned to OpenShell v0.1.2. The Agent Toolkit
plugin appears only where it changes the picture; it shares the agent's process
and is defense in depth, not a boundary.

Component responsibilities and request flow are in
[Architecture](architecture.md). This page does not repeat them.

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Effects behind MCP tools | MCP destinations | The thing being protected: restarts, writes, reads of sensitive data. |
| Provider credentials | OpenShell, injected after the middleware allows | Turn an admitted request into a real effect. The middleware runs `PRE_CREDENTIALS` and never receives them. |
| Issuer keys | Orchestrator, outside the sandbox | Mint root warrants. The middleware holds only their public keys (`trusted_roots`). |
| Holder keys | Task runtime, inside the sandbox | Sign each call's proof of possession. |
| Approver keys | Approvers | Sign approvals for tools that require them. |
| Receipt signing key | Middleware (`--receipt-key`) | Makes receipts attributable to this deployment. |
| TLS server key | Middleware (`--tls-key`) | Authenticates the middleware to OpenShell. |
| OpenShell extension JWT key | OpenShell gateway; the middleware holds the public key | Authenticates gateway and supervisor callers. |
| Trust policy | Policy file or provider snapshot | Selects trust roots, destinations, and replay settings per sandbox. Whoever controls it controls authorization. |
| Replay state | Redis (or process memory in development) | Makes approval nonces and `single_use_tools` proofs single-use. |
| Revocation floors | Per-replica files (`rollback_floor_path`) | Prevent a revocation list from being rolled back. |
| Receipts | Per-replica append-only file (`--receipt-log`) | Evidence of each verified `tools/call` decision. |

## Trust boundaries

1. **Agent process → OpenShell supervisor.** The agent runs inside the sandbox
   and is untrusted. Every byte of an MCP request body, including
   `params._meta.tenuo` and the JSON-RPC `id`, is attacker-controlled.
2. **OpenShell supervisor or gateway → middleware.** gRPC over TLS with an
   OpenShell extension bearer JWT. The middleware trusts OpenShell to report
   the authenticated `sandbox_id`, the HTTP method, and the destination host,
   port, and path, and to enforce the decision it returns, including a
   replacement body.
3. **Middleware → Redis.** Shared replay state across replicas.
4. **Middleware → policy provider.** The built-in provider reads a local file.
   Other providers must authenticate their source before returning a snapshot.
5. **OpenShell → MCP destination.** After an allow, OpenShell injects
   credentials and forwards the request. Responses and server-to-client
   messages return to the agent without passing this middleware.

Issuance happens outside all of these: the orchestrator mints a warrant for a
holder public key the task runtime exported. See
[holder key custody](architecture.md#holder-key-custody).

## Attackers

| Attacker | Starting position | Goal |
| --- | --- | --- |
| Prompt-injected or compromised agent | Code execution in the sandbox, with the task's holder key and warrant | An effect outside its task: another tool, other arguments, a repeat of an approved action, a different destination. |
| Another sandbox on the same gateway | Its own supervisor credential and policy entry | Act under the first sandbox's trust roots, or spend its approvals. |
| Network attacker between supervisor and middleware | Can observe or modify traffic on that path | Forge an allow, change the forwarded body, or capture reusable material. |
| Malicious or compromised MCP destination | Receives forwarded requests; controls responses | Reuse authority it receives, or steer the agent through responses. |
| Operator error | Configures OpenShell, the policy, or the middleware | Not an attacker, but the most likely way a control is disabled. |
| Compromised policy source | Can write the policy file or provider snapshot | Add a trust root, widen destinations, or disable replay protection. |

## Threats and mitigations

"Where enforced" names the code or document section that implements the
control. Residual risk is what remains when the control works as written.

| # | Threat | Mitigation | Where enforced | Residual risk |
| --- | --- | --- | --- | --- |
| 1 | Agent calls a tool or argument set its task was not granted. | The warrant chain must verify to a trusted root, name the tool, and satisfy every argument constraint; approvals are checked when the warrant requires them. | `evaluate::authorize_tool` → Tenuo `Guard::check_received` | Anything inside the warrant is allowed. The middleware does not judge intent. Narrow warrants, approvals, and short lifetimes are the controls. |
| 2 | Agent omits `_meta.tenuo` or supplies a forged or malformed one. | Missing authority denies `tenuo_missing_warrant`; undecodable authority denies `tenuo_invalid_request`; an untrusted root or bad signature denies. | `evaluate::authorize_tool`, `tenuo::sdk::transport::mcp_meta::decode_meta` | None beyond the signature scheme. |
| 3 | A warrant copied out of the sandbox, or from another task, is replayed. | Every call carries a proof of possession signed by the warrant's holder key over the warrant, tool, arguments, and a time bucket. | Tenuo `Guard::check_received` | The holder key lives in the sandbox. An agent that controls the sandbox controls the key; the warrant is what bounds it. See [holder key custody](architecture.md#holder-key-custody). |
| 4 | A captured request body is resent. | Proofs expire after `window * max_windows` (150 s by default). Calls to `single_use_tools` reserve the proof once across the deployment. On allow, `_meta.tenuo` is stripped by default so the destination never holds a reusable proof. | `policy::PolicySet::reserve_claims`, `replay::pop_claim`, `mcp::strip_tenuo`, `policy::meta_mode` | The proof signs a 30-second bucket, not a per-call nonce. For any tool not in `single_use_tools`, whoever holds the body can resend it through the binding while the proof is valid. Per-call uniqueness needs a nonce in the Tenuo proof. See [Replay](architecture.md#replay). |
| 5 | An approval is used twice. | Approval nonces (approver key plus nonce) are reserved atomically for all approvals on a request, committed before allow, and shared across replicas through Redis. | `policy::PolicySet::reserve_claims`, `replay::RedisReplayStore`, `main.rs` (production refuses to start without Redis unless `--allow-in-memory-replay`) | Only when the policy sets `approval_replay_protection: true`; it defaults to `false`. The approval is spent once the middleware allows, even if OpenShell or the destination then fails. See [Consumed approvals](operations.md#consumed-approvals). |
| 6 | Parser differential: duplicate keys, batches, trailing bytes, escaped method names, or non-object bodies make the middleware and the destination read different requests. | Strict single-object parse: repeated keys, arrays, trailing data, and non-string methods deny. Methods are compared after JSON unescaping. In strip mode the forwarded `tools/call` body is re-encoded from the parsed value. The parser and decision path are fuzzed. | `mcp::parse_body`, `mcp::strip_tenuo`, `fuzz/` | With `tenuo_meta: preserve` and for pass-through methods, the original bytes are forwarded; a destination parser could still differ on inputs both accept. |
| 7 | A tool grant meant for one server is spent on another server that exposes the same tool name. | Each sandbox lists its destinations and the tools each serves; other hosts, ports, paths, and tools deny `tenuo_destination_denied` before the warrant is examined. | `policy::PolicySet::admit_destination`, called twice in `evaluate::decide` | `"tools": ["*"]` admits every tool at that destination. Host matching uses the target OpenShell reports; the middleware does not resolve names. |
| 8 | Traffic reaches a tool without a warrant check. | Unknown methods deny. Only listed lifecycle methods pass. Extra methods and client responses to server-initiated requests are per-sandbox opt-ins. `tools/call` cannot be a pass-through method. Only bodyless `GET` and `DELETE` pass without a JSON-RPC body; other methods deny. | `mcp::parse_body`, `policy::parse_mcp_options`, `evaluate::decide` | Pass-through methods and client responses carry no warrant check. A bodyless `GET` opens a server-to-client stream that is not inspected. |
| 9 | Traffic avoids the middleware entirely. | Out of scope for the middleware. OpenShell network policy must deny alternate paths. | [Protocol coverage](architecture.md#protocol-coverage), [Upstream verification](upstream-verification.md#uncovered-paths) | `tls: skip` endpoints, raw TCP, binary WebSocket frames, and server-to-client WebSocket messages are not inspected. `EvaluateWebSocketSession` returns `unimplemented`. |
| 10 | Another sandbox acts under this sandbox's trust roots. | Policy is selected by the authenticated `sandbox_id`, never a display name. A supervisor JWT must name the same `sandbox_id` as the request. | `service::MiddlewareService::require_supervisor`, `auth::ExtensionJwtVerifier::verify`, `policy::PolicySet::sandbox` | Replay state is deployment-wide by design. A sandbox whose policy trusts the same roots and destination, and that obtains another sandbox's signed body, can spend that body's approval first. Nonces are reserved only after full verification. |
| 11 | A network attacker forges an allow or rewrites the forwarded body. | Production mode requires server TLS and verifies the extension JWT: `EdDSA`, `typ`, optional `kid`, exact issuer and audience, required claims, expiry, issue time, one-hour maximum lifetime, and caller shape. Partial TLS or JWT configuration refuses to start. | `main.rs` `production_security`, `auth::ExtensionJwtVerifier::verify` | OpenShell v0.1.2 does not provision client certificates, so caller authentication is a bearer token. Repeated `jti` values are accepted because OpenShell reuses tokens; a stolen token works until it expires. `--insecure-dev` disables TLS and caller authentication. |
| 12 | A network attacker between the middleware and Redis deletes or plants replay keys. | The Helm NetworkPolicy limits the middleware's egress to the configured Redis selector; the Redis URL comes from a Secret. Redis errors deny `tenuo_verifier_failed` and fail readiness. | `deploy/helm/tenuo-openshell/templates/networkpolicy.yaml`, `policy::PolicyManager::ready` | The Redis client is built without TLS support, so the connection is plaintext. An attacker on that path, or any client that can write to Redis, can defeat single-use guarantees or deny service. Redis must be on an isolated network and accept writes only from the middleware. |
| 13 | A malicious destination reuses authority or manipulates the agent. | `_meta.tenuo` is stripped before forwarding unless the binding sets `tenuo_meta: preserve`. With `--evaluate-results`, a sandbox's `max_result_bytes` withholds oversized results of allowed calls. | `mcp::strip_tenuo`, `policy::meta_mode`, `result.rs` | With `preserve`, the destination receives a proof it can resend within the proof window. Result content is hashed and size-limited, not inspected; results and server-initiated messages can prompt-inject the agent, whose reach is still bounded by its warrant. The size limit runs after the effect and only for responses matched to a request on the same replica. |
| 14 | A compromised policy source adds a trust root, widens a destination, or disables replay protection. | Policy versions must increase; a lower or equal version, invalid JSON, or failed revocation check keeps the last valid snapshot. Provider snapshots may carry `valid_until`, after which the sandbox denies and readiness fails. The file provider performs no network I/O. | `policy::PolicyManager::reload_once`, `policy::PolicySet::snapshot_fresh`, [Providers](providers.md) | The middleware does not verify a signature on the policy document. Anyone who can write the policy file, ConfigMap, or provider source controls authorization. Protect it like the issuer keys. |
| 15 | A revoked warrant is used, or revocation state is rolled back. | Signed revocation lists are verified against the sandbox's trust roots, bounded by `max_staleness_secs`, and pinned by a persistent per-replica rollback floor. Stale or missing state denies and fails readiness. | `policy::PolicySet::from_json` (`RevocationTracker`, `FileFloorStore`), `policy::PolicySet::revocation_ready` | Only for sandboxes with `revocation` configured; others rely on expiry bounded by `max_warrant_lifetime_secs`. Floors are local files; deleting one resets that replica's floor. |
| 16 | A decision is denied or disputed after the fact. | Verified `tools/call` decisions are signed with the receipt key and hash-chained. With `--require-receipts`, an allow becomes a denial when its receipt cannot be written. In production mode without `--allow-in-memory-replay`, a configured receipt key must already exist. With `--evaluate-results`, a signed result receipt links each matched result's digest, size, and status to its allow receipt. `receipts export` verifies both chains. | `receipt::ReceiptLog::record`, `evaluate::authorize_tool`, `main.rs` `receipt_log`, `result_receipt.rs`, `export.rs` | A receipt records the decision, not that the tool ran; a result receipt shows a result came back. Result receipts are best-effort even with `--require-receipts`, and unmatched responses have none. Only decisions that reach warrant verification are receipted; malformed bodies, destination denials, missing or undecodable authority, and replay denials are not. The chain shows modification and insertion but not removal of the newest entries unless receipts are exported elsewhere. |
| 17 | Resource exhaustion. | Bodies over 262,144 bytes deny. JSON nesting is bounded by serde_json's recursion limit. Replay reservations are 30-second leases. | `service::MiddlewareService::evaluate_http_request`, `mcp::parse_json`, `replay::RESERVATION_LEASE_SECS` | No per-sandbox rate limit. The middleware fails closed, so an unavailable Redis or policy source blocks covered traffic. |
| 18 | Logs leak arguments or carry forged entries. | Metrics carry counts only. Decision-log request ids outside a small token alphabet are written hex-encoded, so a sandbox-chosen JSON-RPC id cannot add lines or fields. Guards are built with `DenialReporting::Debug`, so Tenuo's per-denial message, which can quote argument values, is not written. Result log lines use the same id escaping. Trace spans carry bounded, argument-free attributes. | `telemetry.rs`, `evaluate::log_safe_id`, `policy::PolicySet::from_json`, `result.rs`, `otel.rs` | Decision codes and request ids are still logged. Receipts record argument digests for verified calls. With an OTLP endpoint configured, sandbox ids, tool names, warrant ids, and outcomes are sent to the collector. |
| 19 | Operator misconfiguration disables a control. | Production is the default: TLS, JWT, and Redis are required, a configured receipt key must already exist, and `--insecure-dev` cannot be combined with production options. Policies must list destinations; `"*"` cannot be mixed with named tools; `tools/call` cannot be a pass-through method. | `main.rs`, `policy::parse_destinations`, `policy::parse_mcp_options` | Still possible: `--insecure-dev` or `--allow-in-memory-replay` in production, `approval_replay_protection` left `false`, `"tools": ["*"]` on a multi-server sandbox, `preserve` for a destination that does not verify, broad pass-through methods, a shared replay key prefix across environments, or missing network policy for uncovered paths. |
| 20 | The in-sandbox agent is used to sign calls for someone else, or bypassed. | `tenuo-openshell-agent proxy` listens on loopback only and refuses other addresses. The holder key is created `0600` in a `0700` directory and only the public key is printed. `install-warrant` rejects a warrant for another key. Redirects are not followed, so a signed call cannot be moved to another destination. The sandbox policy lists the proxy as the only binary allowed to reach MCP. | `agent/src/main.rs`, `agent/src/authority.rs`, `agent/src/proxy.rs`, [sandbox-agent.md](sandbox-agent.md) | Any process in the sandbox can use the loopback proxy, so it holds the same authority as the key: the warrant is the bound. The proxy's local check trusts the chain's own root and is advisory; the middleware is the enforcement point. |
| 21 | A dependency or build input is compromised. | `Cargo.lock` is enforced with `--locked`. `cargo deny` checks advisories, licenses, and sources (crates.io only). Workflow actions are pinned by commit and updated through Dependabot. Release images are non-root and read-only, built with SBOM and provenance, and signed with cosign. | `deny.toml`, `.github/workflows/`, `.github/dependabot.yml`, `Dockerfile` | No release has been published yet. See [Releasing](releasing.md). |
| 22 | An approver signs something other than what they reviewed, or an approval is spent on another call. | An approval signs a request hash over the warrant id, tool, canonical arguments, and holder. `tenuo-openshell approve` verifies the pending warrant chain to a `--trusted-root`, checks the recorded request against that warrant with Tenuo's `ApprovalRequest::matches_warrant` (hash, holder, message, approvers, threshold, expiry), displays only fields from the verified request, refuses a key the warrant does not list, and asks for confirmation unless `--yes`. Tenuo's `approve_request` signs with a random nonce and caps validity at the warrant's expiry. The proxy attaches an approval only to the request it matches and deletes it once attached; the middleware verifies the hash and accepts each nonce once. | `src/bin/tenuo-openshell.rs` (`review`), `agent/src/approvals.rs`, Tenuo `Guard`, `policy::PolicySet::reserve_claims` | The sandbox writes the pending request, so a compromised agent chooses what to ask for; the approver must judge the request itself, and the warrant still bounds it. The agent can fill the pending directory with requests. `--yes` skips review. The approver key's host is trusted. |

## Residual risks in one place

- The proof of possession signs a 30-second time bucket, not a per-call nonce.
  Only `single_use_tools` are single-use; other calls can be resent for up to
  150 seconds by anyone who holds the body and can reach the binding.
- Approvals are single-use only with `approval_replay_protection: true`, and an
  approval is spent at allow even if delivery then fails.
- `tls: skip`, raw TCP, binary WebSocket frames, and server-to-client WebSocket
  messages bypass the middleware. Network policy must close them.
- Pass-through methods, client responses, and bodyless `GET`/`DELETE` carry no
  warrant check.
- A compromised agent can do anything its warrant allows. The holder key is in
  the sandbox by design.
- Caller authentication is a reusable bearer JWT over server-authenticated TLS.
  `--insecure-dev` removes both.
- Redis traffic is plaintext; the replay guarantee depends on network isolation.
- The trust policy is not signed; its integrity depends on who can write it.
- The result size limit applies only to responses matched to an allowed call
  on the same replica within 10 minutes; others are delivered unchecked. A
  limit added by a policy reload is not enforced unless the middleware runs
  with `--evaluate-results`.
- Result receipts are best-effort, including with `--require-receipts`.

## Assumptions

- OpenShell reports `sandbox_id`, method, host, port, and path faithfully,
  enforces the returned decision and replacement body, and applies
  `on_error: fail_closed`.
- OpenShell network policy denies the uncovered paths listed above.
- Issuer, approver, and orchestrator keys stay outside the sandbox.
- Replica clocks are synchronized well within the 30-second proof bucket and
  the JWT and revocation tolerances.
- Redis, the policy source, and the receipt volume are reachable only by the
  middleware and its operators.

## Verification

- Unit tests in `src/` cover each denial path named above, replay and receipt
  failure ordering, and JWT negative cases. `make check` runs them.
- `fuzz/` holds cargo-fuzz targets for the MCP parser, the policy loader, and
  the full decision. The `evaluate` target asserts that an allowed
  `tools/call` is exactly a call the harness signed and that the forwarded
  body carries no `_meta.tenuo`. The Fuzz workflow runs each target daily and
  on changes to the parser, policy, or decision code.
- `make e2e` exercises the HTTP path through a real pinned OpenShell gateway
  and sandbox and confirms denied calls do not reach the effect.

Update this page when a control, default, or covered path changes.
