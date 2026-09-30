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
| Agent Toolkit plugin | Fast denial before a Python function runs | Defense in depth; shares the application process |
| OpenShell middleware | Verify caller identity and Tenuo authority for covered outbound MCP calls | Yes, for configured bindings |
| OpenShell L7 policy | Restrict destination and MCP tool name | Yes, but does not inspect nested tool arguments |
| Destination verifier | Re-verify preserved `_meta.tenuo` immediately before an effect | Optional independent boundary |
| A2A example | Prove attenuated authority can cross a JSON-RPC handoff | Interoperability proof, not a distributed package |

Trust roots are selected by authenticated, immutable `sandbox_id`, never a
display name. Holder keys remain outside the sandbox in the demo; a signed
warrant without the matching holder proof is unusable. The middleware runs
before OpenShell injects provider credentials and therefore must not receive
them.

## Failure behavior

Malformed requests, unsupported batches, missing sandbox policy, unknown trust
roots, verification errors, and unavailable verifier state deny by default.
MCP lifecycle methods pass only through an explicit allowlist. Unknown methods
fail closed.

Production replicas share a Redis replay store. Approval identity is global to
the deployment, and multi-approval reservation is one atomic transaction, so a
failed batch reserves nothing. Redis keys share a deployment-specific cluster
hash slot. A required receipt failure conditionally releases only the calling
reservation; a successful decision leaves it consumed. Versioned policy
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
