# Operations runbook

## Health model

`/live` reports process health. `/ready` additionally requires a recently read
valid policy, fresh signed revocation state when configured, and a reachable
replay backend. Provider-synchronized policies also require an unexpired
`valid_until`; optional adapters may add local cache or outbox checks. Remove an
unready pod from service; do not route around a failed authorization dependency.

Prometheus metrics on the admin port report allow/deny counts, verifier
failures, aggregate enforcement-decision time, active policy version, the
number of trusted sandboxes (`tenuo_openshell_policy_sandboxes`), and policy
reload failures. A policy with no sandboxes is valid and ready, and denies
every request. Decision time includes configured replay-store and
receipt-persistence I/O. Metrics never contain warrant bodies, arguments,
approvals, keys, or OpenShell display names.

With `--evaluate-results`, three more series cover tool results:

| Metric | Meaning |
| --- | --- |
| `tenuo_openshell_results_total{outcome}` | `delivered`, `blocked`, `incomplete`, or `skipped` responses. `skipped` includes every response this service did not authorize. |
| `tenuo_openshell_result_receipt_failures_total` | Result receipts that could not be appended. Delivery was not affected. |
| `tenuo_openshell_result_correlation_evictions_total` | Allowed calls forgotten before their response arrived because 65,536 were in flight. Their results are skipped. |

## Traces

When an OTLP endpoint is configured (see
[Deployment](deployment.md#traces)), each decision is one span.
`tenuo.authorize` covers a request decision and `tenuo.result` a result
evaluation; a result span is a child of its call's authorize span. A request
carrying a valid W3C `traceparent` header becomes the authorize span's
parent. The header comes from the sandbox, so treat it as a link, not as
identity.

| Attribute | Spans | Value |
| --- | --- | --- |
| `openshell.sandbox_id` | both | OpenShell `sandbox_id`. |
| `tenuo.outcome` | both | `allow` or `deny`; `delivered`, `blocked`, or `incomplete`. |
| `tenuo.decision_us` | both | Time inside the decision. |
| `tenuo.tool` | both, when a tool call | Tool name. |
| `tenuo.reason_code` | both, when set | The OpenShell reason code. |
| `tenuo.warrant_id` | both, when a warrant was decoded | Leaf warrant id. |
| `rpc.jsonrpc.request_id` | both, when present | JSON-RPC id. |
| `http.response.status_code` | `tenuo.result` | Upstream status. |
| `tenuo.result_bytes` | `tenuo.result` | Bytes read. |

String attributes are cut to 128 bytes. Spans follow the metrics rule: never
arguments, results, warrant bodies, approvals, or keys.

## Policy rollout and rollback

Every change increments top-level `version`. Write the complete validated file
atomically. Replicas retain the last valid snapshot when parsing, compilation,
revocation verification, or version checks fail.

Rollback by creating a new version containing the prior desired policy; never
decrease the version. Investigate `tenuo_openshell_policy_reload_failures_total`
before forcing a restart.

## Replay-store outage

Readiness fails, and approval-bearing requests and calls that reserve a proof
deny `tenuo_verifier_failed`.
Do not switch to in-memory replay during an incident: doing so invalidates the
cross-replica single-use guarantee. Restore Redis or route to a separately
validated deployment using a distinct replay namespace.

## Consumed approvals

An approval nonce is committed before the middleware returns allow, so each
approval authorizes at most one effect. If OpenShell or the destination fails
after that point, the approval is spent even though the effect may not have
happened. A retry denies `tenuo_approval_replayed`; request a new approval
rather than clearing replay state. The same applies to every tool that is not
listed in `idempotent_tools`: a resent proof denies `tenuo_pop_replayed` until
the client signs a fresh proof in the next time bucket.

## Destination denials

`tenuo_destination_denied` means the request's host, port, or path is not in
the sandbox's `destinations`, or that destination does not list the tool.
Compare the OpenShell request log with the policy entry; do not widen a
destination to `"tools": ["*"]` when the sandbox reaches more than one server.

## Revocation outage or staleness

When signed revocation is configured, stale or missing state denies. Restore
the SRL publishing path and deploy a higher policy version carrying a fresh,
valid SRL. Do not delete or edit rollback-floor files. A compromised floor
requires a security incident review, not an automatic reset.

## Receipt failure

With `--require-receipts`, an allowed decision denies before execution if its
receipt cannot be appended. Check volume capacity, permissions, and signer-key
availability. A failed receipt releases its approval reservation, including a commit that
succeeded before the receipt write. No allow receipt is stored for that denial.
If Redis cannot confirm cleanup while the nonce is still pending, it remains
pending for at most 30 seconds; retries deny `tenuo_verifier_failed`, not
`tenuo_approval_replayed`, until cleanup succeeds or the lease expires. Preserve all per-replica logs and
public signer keys when recovering or replacing a pod.

Result receipts never change delivery. A failed append increments
`tenuo_openshell_result_receipt_failures_total` and logs `result receipt was
not stored`. The same volume checks apply. If the volume is at fault,
`--require-receipts` also denies the next allowed call.

## Withheld results

`tenuo_result_too_large` means an allowed call returned more than the
sandbox's `max_result_bytes`. `tenuo_result_unmeasurable` means the sandbox
has a limit and the result had no length and could not be read, usually a
compressed response without `Content-Length`. In both cases the tool call
already ran; only its result was withheld. Tell the task owner before a retry
of a non-idempotent tool. Raise the limit in a higher policy version, or have
the server return smaller or uncompressed results. A result receipt with
`outcome` `blocked` records each case.

## Receipt export

`tenuo-openshell-middleware receipts export` verifies a log and writes JSON
lines for a SIEM. Export rotated copies, one file at a time, and ship
authorization and result logs separately. A nonzero exit means the file did
not verify and nothing was written: keep the file, compare it with the pod's
volume, and treat a broken chain as possible tampering. See
[Receipts](receipts.md) for the schema.

## Key compromise

1. Remove the affected issuer or gateway key in a higher policy/configuration
   version.
2. Publish a signed revocation list when warrant authority may remain live.
3. Rotate receipt and TLS keys through new immutable Secrets.
4. Restart the OpenShell gateway when its middleware registration changes.
5. Preserve receipts, structured decision logs, policy versions, and revocation
   floors for incident analysis.

## Upgrade and rollback

Verify `make check`, the OpenShell compatibility workflow, Helm rendering, and
the adversarial suite for the exact image digest. Roll out one replica at a
time and require readiness before continuing. Roll back the image by digest;
roll policy forward using a new version even when restoring old policy content.
