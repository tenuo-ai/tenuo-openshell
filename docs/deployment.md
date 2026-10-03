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
- Redis when approval replay protection or `single_use_tools` is enabled; and
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

Attach it to the sandbox's MCP endpoints in the OpenShell sandbox policy:

```yaml
network_middlewares:
  tenuo-task-authority:
    middleware: tenuo/authorization
    on_error: fail_closed
    endpoints:
      include:
        - mcp.internal
```

On allow, the middleware removes `params._meta.tenuo` before OpenShell
forwards the request. Add `config: {tenuo_meta: preserve}` only when the
destination verifies the warrant again itself.

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
      "trusted_roots": ["<64 lowercase hex characters>"],
      "destinations": [
        {
          "host": "mcp.internal",
          "port": 443,
          "path": "/mcp",
          "tools": ["read_logs", "restart_service"]
        }
      ],
      "single_use_tools": ["restart_service"],
      "mcp": {
        "passthrough_methods": [],
        "allow_client_responses": false
      }
    }
  }
}
```

Each sandbox entry:

| Field | Required | Meaning |
| --- | --- | --- |
| `trusted_roots` | Yes | Issuer public keys whose warrants this sandbox accepts. |
| `destinations` | Yes | MCP servers the binding may reach, and the tools each serves. Host matches case-insensitively; `port` and optional `path` match exactly. `"tools": ["*"]` admits any tool and suits a sandbox that reaches one server. |
| `single_use_tools` | No | Tools whose signed calls are accepted once. Use for non-idempotent tools; an identical call inside the same 30-second proof bucket is also denied. |
| `mcp.passthrough_methods` | No | Extra JSON-RPC methods forwarded without a warrant, such as `resources/read`. `tools/call` is rejected. |
| `mcp.allow_client_responses` | No | Forward the client's responses to server-initiated sampling, elicitation, and roots requests. Default `false`. |
| `max_result_bytes` | No | Largest tool result, in bytes, delivered to this sandbox. Requires `--evaluate-results`; see [Result evidence](#result-evidence). |
| `revocation` | No | Signed revocation list; see below. |

A missing sandbox, missing root, unlisted destination, unreadable policy, or
unavailable verifier denies the request. See
[Architecture](architecture.md#destination-binding) for why destinations are
required.

Top-level `approval_replay_protection` defaults to `true`: each approval nonce
is accepted once across the deployment, which requires Redis in production
(see [Replay protection](#replay-protection)). Setting it to `false` makes an
approval reusable until it expires; do that only for single-call evaluation.

### Policy integrity

The policy file is not signed. Whoever can write it chooses the trusted issuers
for every sandbox, so it is as sensitive as the issuer keys:

- Mount it read-only into the middleware, and limit who can change its source
  (for example the ConfigMap and the RBAC that can edit it).
- Review policy changes like code: a new trusted root or a wider destination
  grants authority.
- A provider that fetches snapshots must authenticate them before returning
  them; see [Provider integration](providers.md).
- Keep `version` monotonic. The middleware refuses a lower version, so an old
  file cannot be replayed onto a running replica.

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

Tools in `single_use_tools` reserve each proof of possession the same way, in
the same atomic reservation as the request's approvals. See
[Architecture](architecture.md#replay) for what this does and does not cover.

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

## Result evidence

`--evaluate-results` (or `TENUO_EVALUATE_RESULTS=true`) adds an
`HTTP_RESPONSE / PRE_RETURN` binding to `Describe`. OpenShell reads the
manifest when the gateway starts, so restart the gateway after changing the
flag. No sandbox policy change is needed: every attachment of
`tenuo/authorization` joins the response chain, with the same `on_error`.

For each `tools/call` this service allowed, the middleware hashes the result
and appends a signed result receipt to `<receipt log>.results.jsonl`. A
sandbox's optional `max_result_bytes` withholds larger results with
`tenuo_result_too_large`. Startup fails when the policy sets
`max_result_bytes` and the flag is off. A later reload that adds the field is
accepted but not enforced until the flag is on, so enable the flag first.

The response binding advertises the same 256 KiB `max_payload_bytes` as the
request binding, so the registration's `max_payload_bytes` applies to both.
Results up to that size are read whole and a block returns a 403; larger or
unknown-length results are read as a stream, and a block ends delivery
mid-stream. Result receipts are best-effort even with `--require-receipts`.
See [Architecture](architecture.md#tool-results) for what is skipped and why.

## Traces

Set the standard OpenTelemetry variables to export one span per decision
over OTLP gRPC:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.observability:4317
OTEL_SERVICE_NAME=tenuo-openshell-middleware   # default
```

`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_TRACES_SAMPLER`, and `OTEL_BSP_*` are
honored. Only the `grpc` protocol is supported; any other
`OTEL_EXPORTER_OTLP_PROTOCOL` fails startup. With no endpoint set, or with
`OTEL_SDK_DISABLED=true` or `OTEL_TRACES_EXPORTER=none`, no exporter is
created and nothing is sent. Export runs in the background and never delays a
decision; a slow or unavailable collector drops spans.

Spans are named `tenuo.authorize` and `tenuo.result`. See
[Operations](operations.md#traces) for the attributes.

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
