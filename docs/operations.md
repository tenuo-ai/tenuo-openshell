# Operations runbook

## Health model

`/live` reports process health. `/ready` additionally requires a recently read
valid policy, fresh signed revocation state when configured, and a reachable
replay backend. Provider-synchronized policies also require an unexpired
`valid_until`; optional adapters may add local cache or outbox checks. Remove an
unready pod from service; do not route around a failed authorization dependency.

Prometheus metrics on the admin port report allow/deny counts, verifier
failures, aggregate verification time, active policy version, and policy reload
failures. They never contain warrant bodies, arguments, approvals, keys, or
OpenShell display names.

## Policy rollout and rollback

Every change increments top-level `version`. Write the complete validated file
atomically. Replicas retain the last valid snapshot when parsing, compilation,
revocation verification, or version checks fail.

Rollback by creating a new version containing the prior desired policy; never
decrease the version. Investigate `tenuo_openshell_policy_reload_failures_total`
before forcing a restart.

## Replay-store outage

Readiness fails and approval-bearing requests deny `tenuo_verifier_failed`.
Do not switch to in-memory replay during an incident: doing so invalidates the
cross-replica single-use guarantee. Restore Redis or route to a separately
validated deployment using a distinct replay namespace.

## Revocation outage or staleness

When signed revocation is configured, stale or missing state denies. Restore
the SRL publishing path and deploy a higher policy version carrying a fresh,
valid SRL. Do not delete or edit rollback-floor files. A compromised floor
requires a security incident review, not an automatic reset.

## Receipt failure

With `--require-receipts`, an allowed decision denies before execution if its
receipt cannot be appended. Check volume capacity, permissions, and signer-key
availability. Preserve all per-replica logs and public signer keys when
recovering or replacing a pod.

## Key compromise

1. Remove the affected issuer or gateway key in a higher policy/configuration
   version.
2. Publish a signed revocation list when warrant authority may remain live.
3. Rotate receipt and TLS keys through new immutable Secrets.
4. Restart the OpenShell gateway when its middleware registration changes.
5. Preserve receipts, OCSF events, policy versions, and revocation floors for
   incident analysis.

## Upgrade and rollback

Verify `make check`, the OpenShell compatibility workflow, Helm rendering, and
the adversarial suite for the exact image digest. Roll out one replica at a
time and require readiness before continuing. Roll back the image by digest;
roll policy forward using a new version even when restoring old policy content.
