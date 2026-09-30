# Deploying Tenuo for NVIDIA OpenShell

This guide contains the production configuration that is intentionally kept
out of the project README. Read it with the [architecture](architecture.md),
[operations runbook](operations.md), and
[pinned upstream contract](upstream-verification.md).

## Production requirements

Production mode is the default. It requires:

- server TLS;
- an operator-provisioned OpenShell Ed25519 public key;
- a versioned Tenuo trust policy;
- Redis when approval replay protection is enabled; and
- a pre-generated receipt key and durable receipt path when receipts are
  required.

Start the middleware with explicit production inputs:

```bash
cargo run --release -- \
  --policy /etc/tenuo/openshell-policy.json \
  --listen 0.0.0.0:50051 \
  --tls-cert /etc/tenuo/tls/server.pem \
  --tls-key /etc/tenuo/tls/server-key.pem \
  --openshell-jwt-public-key /etc/openshell/jwt/public.pem \
  --openshell-gateway-id production-gateway \
  --openshell-jwt-key-id production-key-1 \
  --audience urn:openshell:extension:middleware:tenuo/authorization \
  --replay-redis-url redis://redis.security.svc:6379/ \
  --receipt-key /etc/tenuo/receipts/key \
  --receipt-log /var/lib/tenuo/receipts.jsonl \
  --require-receipts \
  --admin-listen 0.0.0.0:9090
```

For native Redis Cluster, replace `--replay-redis-url` with:

```bash
--replay-redis-cluster-urls redis://node-a:6379/,redis://node-b:6379/
```

The verifier pins `alg=EdDSA`, `typ=openshell-ext+jwt`, optional `kid`, exact
issuer, exact audience, caller shape, expiry, issue time, and OpenShell's
one-hour maximum token lifetime. OpenShell reuses extension tokens until
rotation, so repeated `jti` values are accepted as required by the upstream
protocol.

## Register with OpenShell

Register the service with the same audience used by the middleware:

```toml
[[openshell.supervisor.middleware]]
name = "tenuo/authorization"
grpc_endpoint = "https://tenuo-middleware.example:50051"
tls_ca_cert_path = "/etc/openshell/tenuo-middleware-ca.pem"
audience = "urn:openshell:extension:middleware:tenuo/authorization"
max_payload_bytes = 262144
timeout = "2s"
```

The supported authorization point is OpenShell v0.1.2 MCP Streamable HTTP
`HTTP_REQUEST / PRE_CREDENTIALS`. See the
[upstream verification](upstream-verification.md) for the exact contract.

## Configure trust policy

Trust is selected by OpenShell's authenticated `sandbox_id`, never by a
reusable display name:

```json
{
  "version": 1,
  "max_warrant_lifetime_secs": 3600,
  "approval_replay_protection": true,
  "sandboxes": {
    "5ba15c63-8170-4e78-a4aa-df0f94f49642": {
      "trusted_roots": ["<64 lowercase hex characters>"]
    }
  }
}
```

A missing sandbox, missing root, unreadable policy, or unavailable verifier
denies the request.

Policy files are versioned and polled. A valid higher version replaces the
active snapshot atomically. Invalid or rolled-back updates preserve the last
valid version. The default provider reads a local file and performs no network
activity. Provider-synchronized snapshots add a `valid_until` timestamp so a
stale cache cannot remain authoritative indefinitely. See
[Provider integration](providers.md) for the adapter contract.

## Replay protection

Approval identity is the approver key plus nonce across the whole deployment.
Sandbox boundaries do not reset single-use semantics. All nonces on one
request are reserved atomically across replicas, and Redis Cluster keys share
a deployment-specific hash slot.

Production startup fails if replay protection is enabled without Redis.
`--allow-in-memory-replay` is limited to single-instance demonstrations.

Every environment and independent deployment needs a distinct replay key
prefix. Only replicas of the same logical deployment should share a replay
namespace.

## Revocation

A sandbox policy can require a signed Tenuo revocation list:

```json
"revocation": {
  "signed_list_base64": "<signed SRL>",
  "max_staleness_secs": 300,
  "clock_tolerance_secs": 30,
  "rollback_floor_path": "/var/lib/tenuo/revocation-floor.json"
}
```

The middleware verifies issuer signature and freshness and persists a
monotonic rollback floor. Missing, stale, untrusted, rolled-back, or
equivocated state fails closed. Receipts include the SRL version and hash.

## Kubernetes

The [Helm chart](../deploy/helm/tenuo-openshell/README.md) provides the
supported HA profile: Redis replay protection, readiness and liveness probes,
persistent revocation floors and receipts, non-root read-only containers,
resource bounds, a disruption budget, and default-deny network policy.

The caller, admin, DNS, and Redis selectors must match the labels in the
target cluster. The cluster CNI must enforce ingress and egress NetworkPolicy.

## Health and operations

`/live` reports process health. `/ready` additionally requires a valid policy,
fresh revocation state when configured, and a reachable replay backend.
Prometheus metrics are exposed on the separate admin listener.

Use the [operations runbook](operations.md) for policy rollout, replay-store
outages, receipt failures, key compromise, upgrades, and rollback.

## Local development

For isolated local development only, `--insecure-dev` enables plaintext calls
without caller authentication. It cannot be combined with production security
options. Production startup refuses partial TLS or JWT configuration.
