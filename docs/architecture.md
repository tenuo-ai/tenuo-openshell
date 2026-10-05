# Architecture and trust boundaries

## Purpose

OpenShell decides which tool name and destination a sandbox may reach. Tenuo
adds task-scoped authority over the exact tool arguments, warrant lifetime,
delegation chain, holder proof, and approvals. The controls are complementary.

```text
application issues or attenuates warrant
                │
                ▼
Agent Toolkit middleware (early in-process denial)
                │ proposed MCP tools/call
                ▼
OpenShell L7 policy (tool and destination admission)
                │ before provider credentials
                ▼
Tenuo supervisor middleware (independent authorization boundary)
                │ allowed request
                ▼
credential injection ──► destination (optional defense-in-depth verification)
```

## Components

| Component | Responsibility | Security boundary? |
| --- | --- | --- |
| `tenuo-openshell-agent` | Hold the task's key and warrant in the sandbox; sign MCP calls through a loopback proxy | No; it gives early, readable denials. The middleware enforces |
| Agent Toolkit plugin | Fast denial before a Python function runs | Defense in depth; shares the application process |
| OpenShell middleware | Verify caller identity, destination, and Tenuo authority for covered outbound MCP calls | Yes, for configured bindings |
| OpenShell L7 policy | Restrict destination and MCP tool name | Yes, but does not inspect nested tool arguments |
| Destination verifier | Re-verify preserved `_meta.tenuo` immediately before an effect | Optional independent boundary |
| A2A example | Prove attenuated authority can cross a JSON-RPC handoff | Interoperability proof, not a distributed package |

Trust roots are selected by authenticated, immutable `sandbox_id`, never a
display name. The middleware runs before OpenShell injects provider
credentials and therefore must not receive them.

The [threat model](threat-model.md) lists the attackers these boundaries face,
where each control is enforced, and the residual risk.

## Holder key custody

Proof of possession is signed per call over the warrant, tool, arguments, and
a time bucket, so the signer must be the runtime that chooses the arguments.
In an OpenShell deployment that runtime is inside the sandbox. The supported
model is:

1. The task runtime generates its holder key inside the sandbox and exports
   only the public key.
2. The orchestrator, outside the sandbox, issues or attenuates a task warrant
   to that public key. The issuer and parent holder keys never enter the
   sandbox.
3. The runtime signs each `tools/call` as it makes it.

What this guarantees:

- A compromised agent can act only within its warrant: the tools, argument
  constraints, lifetime, and approvals the orchestrator granted. It cannot
  widen that. It can delegate a narrower part of it to another key unless its
  warrant is terminal; every link in the chain is verified and checked for
  revocation. See [Sub-agents](sandbox-agent.md#sub-agents).
- A warrant copied out of the sandbox is unusable without the holder key, and
  a warrant copied between tasks is unusable without the other task's key.
- Keys are per task. Revoking or letting a warrant expire ends that task's
  authority without rotating anything else.

What it does not guarantee: that the agent only uses its authority for the
task's intent. That is what narrow warrants, approvals, and short lifetimes
are for.

`tenuo-openshell-agent` implements this model: it generates the key, holds the
warrant, and signs calls through a loopback MCP proxy so the agent's MCP client
is unchanged. `tenuo-openshell provision` performs steps 1 and 2 from the
operator side. See [Running an agent under Tenuo](sandbox-agent.md).

A signer outside the sandbox adds protection only if it decides what to sign.
A signer that signs whatever the sandbox asks is equivalent to a key inside
the sandbox. The demo's `MCP client` scenarios exercise the supported model
end to end with an unmodified MCP SDK client; the other scenarios use
host-signed fixtures so that each negative case is reproducible.

## Destination binding

Warrant capabilities name tools, not servers. Each sandbox policy therefore
lists the MCP destinations the binding may reach and the tools each one
serves:

```json
"destinations": [
  {"host": "logs.internal", "port": 443, "path": "/mcp", "tools": ["read_logs"]},
  {"host": "ops.internal", "port": 443, "path": "/mcp", "tools": ["restart_service"]}
]
```

A request to an unlisted host, port, or path, or a `tools/call` for a tool the
destination does not serve, denies `tenuo_destination_denied` before the
warrant is examined. `"tools": ["*"]` admits any tool at that destination and
is appropriate only when the sandbox reaches a single MCP server.

## Replay

Approval nonces are single-use across the deployment.

A proof of possession signs a time bucket rather than a per-call nonce, and
Ed25519 signatures are deterministic. An identical call in the same bucket
therefore carries a byte-identical proof. Every tool reserves that proof once
across the deployment, for at most `window * max_windows` seconds (150 by
default). A resend denies `tenuo_pop_replayed`, including a legitimate
identical call inside the bucket. List a tool in `idempotent_tools` only when
a resent identical call is the same effect. `single_use_tools` is deprecated,
has no effect, and logs a warning at startup.

This is interim. A per-call nonce in the proof
([tenuo-ai/tenuo-openshell#21](https://github.com/tenuo-ai/tenuo-openshell/issues/21))
lets an intentional identical call succeed while a captured body still fails.
When Tenuo ships it, `idempotent_tools` is no longer needed.

On allow, the middleware strips `params._meta.tenuo` by default so the
destination never receives a reusable proof. Set the sandbox's
`forward_proof` to `preserve` only for destinations that verify the warrant
again themselves. The OpenShell attachment cannot set that.

## Failure behavior

Malformed requests, unsupported batches, missing sandbox policy, unknown
destinations, unknown trust roots, verification errors, and unavailable
verifier state deny by default. MCP lifecycle methods pass only through an
explicit allowlist. Unknown methods fail closed.

Production replicas share a Redis replay store. Approval identity is global to
the deployment, and multi-approval reservation is one atomic transaction, so a
failed batch reserves nothing. Redis keys share a deployment-specific cluster
hash slot. Reservations begin as 30-second pending leases. The nonce is committed
before the allow receipt is written, and that receipt is written only after
the commit succeeds. A failed commit or receipt write releases only the
calling reservation. An unconfirmed release of a still-pending lease remains
pending rather than appearing replayed and expires with the lease. Versioned policy
snapshots reload atomically and preserve the last valid snapshot. Signed
revocation lists have freshness bounds and persistent per-replica rollback
floors; readiness fails when either revocation or Redis is unavailable.

Authorization receipts can be required before execution. In that mode an
allowed operation becomes a fail-closed denial when its signed receipt cannot
be persisted. The Helm profile stores chained operational state on per-replica
persistent volumes and exposes bounded, argument-free metrics separately from
the authenticated gRPC listener.

The standalone runtime uses a local file policy provider and a durable local
receipt outbox. Optional control-plane adapters refresh complete snapshots and
export signed receipts in the background; they never add a network dependency
to an authorization decision. Remotely sourced snapshots carry a bounded
`valid_until`, and optional dependencies contribute local-only readiness checks.
See [Provider integration](providers.md) for the adapter contract.

## Protocol coverage

The supported authorization point is OpenShell v0.1.2 MCP Streamable HTTP
`HTTP_REQUEST / PRE_CREDENTIALS`. The optional `HTTP_RESPONSE / PRE_RETURN`
binding records and limits results; see [Tool results](#tool-results).
`tls: skip`, raw TCP, binary WebSocket frames,
and server-to-client WebSocket messages are outside the boundary and must be
blocked by network policy. See [Upstream verification](upstream-verification.md)
for the pinned contract.

Within a configured destination:

| Request | Default | Configurable |
| --- | --- | --- |
| `POST` `tools/call` | Warrant, proof, arguments, approvals, and a single-use proof | `idempotent_tools` |
| `POST` lifecycle: `initialize`, `ping`, `notifications/initialized`, `notifications/cancelled`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | Forwarded | — |
| `POST` other methods, such as `resources/read` or `prompts/get` | Denied | `mcp.passthrough_methods` |
| `POST` JSON-RPC responses to server-initiated sampling, elicitation, or roots requests | Denied | `mcp.allow_client_responses` |
| Bodyless `GET` (server-to-client stream) and `DELETE` (session end) | Forwarded | — |
| Batches, other HTTP methods, `GET`/`DELETE` with a body | Denied | — |

Passthrough methods and client responses carry no warrant check. Enable them
only for servers whose resources and prompts the sandbox may read freely.

### Tool results

With `--evaluate-results`, `Describe` also advertises
`HTTP_RESPONSE / PRE_RETURN`. OpenShell then sends this service the response
to every request on the attachment. The response runs after the upstream call,
so this binding records and limits results. It is not an authorization point.

OpenShell reuses one `RequestContext.request_id` for a request and its
response. When the request path allows a `tools/call`, it records that id with
the sandbox id, JSON-RPC id, tool, leaf warrant id, allow receipt hash, and
the sandbox's `max_result_bytes`. The record lives in a bounded map on the
replica that decided the call: 65,536 in-flight calls, ten minutes each.
Eviction is counted in metrics. A response takes its record once.

| Response | Action |
| --- | --- |
| No record: lifecycle traffic, denied calls, calls a later stage stopped, an expired or evicted record, or a response on another replica | Skipped. Delivered unchanged. |
| Declared `Content-Length` above `max_result_bytes` | Blocked at the response head. |
| Known length, `WHOLE_BODY_BYTES` offered | Read as one unit, hashed, receipted, then delivered. Over the limit blocks before the head is sent. |
| Unknown length or too large for one unit, such as Server-Sent Events | Read with `STREAM_BYTES`, hashed per unit, receipted at the final unit. Passing the limit aborts delivery mid-stream. |
| Only `HEADERS_ONLY` offered: bodyless, partial, encoded, or `no-transform` | Skipped, except that a limit with an unknown, unreadable length blocks `tenuo_result_unmeasurable`. |

A block before the response head returns OpenShell's 403 with
`tenuo_result_too_large` or `tenuo_result_unmeasurable`. A block during
streaming ends delivery without a reason code. A block withholds the result;
the tool call already ran and is not rolled back.

The size limit is the only point where this binding fails closed. Result
receipts are best-effort, including with `--require-receipts`. That flag
guarantees an authorization receipt exists before an effect is allowed.
Withholding the result of an effect that already ran because its result
receipt could not be written adds no evidence about the effect, and invites a
retry of a non-idempotent call. Failed result receipts are counted in
`tenuo_openshell_result_receipt_failures_total`.

The limit lives in the Tenuo policy, keyed by `sandbox_id`, rather than in
the attachment `config`. The attachment is part of the OpenShell sandbox
policy, which the sandbox creator writes; the Tenuo policy is the operator's.
`ValidateConfig` accepts an empty attachment or `tenuo_meta: strip`, and
rejects `preserve`.

When the attachment is `fail_closed`, an unreachable middleware blocks
responses as well as requests on that attachment. See
[Receipts](receipts.md) for the result receipt format.
