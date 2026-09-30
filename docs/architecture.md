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
  widen or re-delegate beyond that.
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
therefore carries a byte-identical proof, and any holder of the request body
can resend it while the proof is valid (at most `window * max_windows`, 150
seconds by default). Tools listed in a sandbox's `single_use_tools` accept
each proof once; a resend denies `tenuo_pop_replayed`. A legitimate identical
call inside the same bucket is also denied, so list only non-idempotent tools.
Per-call uniqueness for every tool requires a nonce in the proof itself, which
is a Tenuo protocol change rather than a middleware setting.

On allow, the middleware strips `params._meta.tenuo` by default so the
destination never receives a reusable proof. Set `tenuo_meta: preserve` in
the OpenShell middleware config only for destinations that verify the warrant
again themselves.

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
`HTTP_REQUEST / PRE_CREDENTIALS`. `tls: skip`, raw TCP, binary WebSocket frames,
and server-to-client WebSocket messages are outside the boundary and must be
blocked by network policy. See [Upstream verification](upstream-verification.md)
for the pinned contract.

Within a configured destination:

| Request | Default | Configurable |
| --- | --- | --- |
| `POST` `tools/call` | Warrant, proof, arguments, and approvals checked | `single_use_tools` |
| `POST` lifecycle: `initialize`, `ping`, `notifications/initialized`, `notifications/cancelled`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | Forwarded | — |
| `POST` other methods, such as `resources/read` or `prompts/get` | Denied | `mcp.passthrough_methods` |
| `POST` JSON-RPC responses to server-initiated sampling, elicitation, or roots requests | Denied | `mcp.allow_client_responses` |
| Bodyless `GET` (server-to-client stream) and `DELETE` (session end) | Forwarded | — |
| Batches, other HTTP methods, `GET`/`DELETE` with a body | Denied | — |

Passthrough methods and client responses carry no warrant check. Enable them
only for servers whose resources and prompts the sandbox may read freely.
