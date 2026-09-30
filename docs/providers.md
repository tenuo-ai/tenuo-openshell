# Provider integration contract

The middleware is complete in standalone mode. A default installation reads a
local policy, verifies warrants locally, stores receipts locally, and makes no
request to a hosted Tenuo service. An account, API key, or control plane is not
part of the quickstart or the authorization path.

This document defines the narrow interfaces for operators that later want a
control plane. The interfaces are provider-neutral. Any control plane that
follows them can refresh snapshots and export receipts without joining the
authorization path.

## Invariants

Every provider integration must preserve these properties:

1. Authorization performs no control-plane network request.
2. Only a complete, authenticated, monotonically newer snapshot is activated.
3. An unavailable provider leaves the last valid snapshot active only until its
   configured freshness deadline.
4. Expired policy or revocation state makes readiness fail and protected calls
   deny closed.
5. Receipts are signed and durably appended before an exporter attempts remote
   delivery.
6. Export retries are idempotent and never repeat an authorized tool effect.
7. Provider credentials stay in the middleware or a companion process. They
   never enter an OpenShell sandbox, warrant, tool arguments, or model context.

## Policy snapshots

`PolicyProvider` in `src/policy.rs` is the embedded adapter interface. Its
`load` method returns one complete JSON snapshot. `PolicyManager` independently
validates the schema, policy version, trust roots, signed revocation state, and
rollback floors before atomically activating it.

The built-in `FilePolicyProvider` is the standalone default. A remote adapter
has two supported shapes:

- implement `PolicyProvider` in a separately packaged binary build; or
- run as a companion process that verifies remote material and atomically
  renames a completed snapshot over the configured policy file.

The companion-process shape is preferred initially because it keeps provider
SDKs, credentials, and networking out of the enforcement process. Never write
the active file in place.

Remotely sourced snapshots must include `valid_until`, expressed as a Unix
timestamp in seconds:

```json
{
  "version": 42,
  "valid_until": 1893456000,
  "max_warrant_lifetime_secs": 900,
  "approval_replay_protection": true,
  "sandboxes": {}
}
```

Standalone operator-managed files may omit `valid_until`. A remote adapter
must choose a bounded value based on the authenticated source lease, not extend
it merely because the local cache remains readable. The adapter must preserve
the current file when refresh, signature verification, tenant binding, or
schema conversion fails. Every accepted lease refresh uses a higher snapshot
`version`, even when the effective sandbox rules are unchanged; equal versions
with different bytes are rejected rather than guessed to be safe.

## Readiness

`/ready` already checks policy-source freshness, snapshot expiry, signed
revocation freshness, and the replay store. Embedded adapters can additionally
implement `admin::ReadinessCheck` and pass checks to `serve_with_checks`.

A readiness check must inspect local state only. Kubernetes probes must not
turn into control-plane network calls. Suitable checks include the age of an
authenticated cache, the health of a durable local outbox, or a bounded export
backlog. Optional exporters should report metrics without taking enforcement
out of service; an operator may make them required when evidence-delivery
policy demands it.

## Receipt export

The receipt log is the durable local outbox. Each line is a hex-encoded signed
CBOR receipt, and the adjacent `.pub` file contains the receipt signer public
key. An exporter should:

1. checkpoint a byte offset in durable local state;
2. decode and verify each receipt before upload;
3. use the hash of the receipt bytes as its idempotency key;
4. batch without reordering a signer's receipt chain;
5. advance its checkpoint only after a durable remote acknowledgement; and
6. apply bounded exponential backoff without blocking authorization.

Do not send raw provider credentials, private keys, unrestricted arguments, or
extra warrant material beyond the signed receipt artifact. Log rotation must
coordinate with the export checkpoint; never truncate an unacknowledged log.

With `--evaluate-results`, `<log>.results.jsonl` is a second outbox with the
same line format and its own chain. `tenuo-openshell-middleware receipts
export` is a reference decoder for both; see [Receipts](receipts.md).

## Mapping a managed control plane

A managed adapter can map this contract onto four operations without changing
the agent or enforcement protocol:

| Local contract | Control-plane operation |
| --- | --- |
| Snapshot refresh | Fetch authenticated sandbox-to-root policy and signed SRL |
| Receipt outbox | Upload signed receipts with hash-based idempotency |
| Readiness state | Report cache age and required-export backlog locally |
| Optional status loop | Register the deployment and publish bounded health metrics |

Tenuo Cloud is one optional implementation of this contract.

## Adapter acceptance tests

An adapter is ready to publish when its test suite proves:

- a fresh checkout passes `make smoke` with the adapter absent;
- removing every provider credential causes no outbound provider request;
- an invalid, rolled-back, equivocated, or expired snapshot is never active;
- cached authority behaves predictably through a network partition and denies
  after `valid_until`;
- duplicate receipt uploads produce one remote record;
- a crashed exporter resumes from its durable checkpoint; and
- logs, metrics, and errors contain no credentials, private keys, full warrants,
  approvals, or unrestricted arguments.
