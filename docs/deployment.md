# Deploying Tenuo for NVIDIA OpenShell

This guide covers production configuration: registration, the trust policy,
replay protection, revocation, result evidence, traces, and Kubernetes. Read
it with the [architecture](architecture.md),
[operations runbook](operations.md), and
[pinned upstream contract](upstream-verification.md).

## Production requirements

Production mode is the default. It requires:

- server TLS;
- an operator-provisioned OpenShell Ed25519 public key;
- a versioned Tenuo trust policy;
- Redis for single-use proofs and approvals, over `rediss://` with a password;
- a signed policy file and the signing public key; and
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
  --replay-redis-url rediss://:password@redis.security.svc:6379/ \
  --receipt-key /etc/tenuo/receipts/key \
  --receipt-log /var/lib/tenuo/receipts.jsonl \
  --require-receipts \
  --admin-listen 0.0.0.0:9090
```

Production requires `rediss://` with a password. The server certificate is
verified against the system trust store, and hostname verification stays on.
`--allow-plaintext-replay` accepts any other Redis URL and is for a network
that already isolates the store. Replay keys are the single-use control for
approvals and proofs.

For native Redis Cluster, replace `--replay-redis-url` with:

```bash
--replay-redis-cluster-urls rediss://:password@node-a:6379/,rediss://:password@node-b:6379/
```

The verifier pins `alg=EdDSA`, `typ=openshell-ext+jwt`, optional `kid`, exact
issuer, exact audience, caller shape, expiry, issue time, and OpenShell's
one-hour maximum token lifetime. OpenShell reuses extension tokens until
rotation, so repeated `jti` values are accepted as required by the upstream
protocol.

## Register with OpenShell

Register the service with the same audience used by the middleware.
`tenuo-openshell register` prints both blocks below; `--only gateway` or
`--only sandbox` prints one, ready to append to `gateway.toml` or a sandbox
policy:

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
forwards the request. Set `forward_proof` to `preserve` on the sandbox in
this policy when the destination verifies the warrant again itself. The
sandbox attachment cannot request that.

`register` requires an `https://` endpoint and `--ca`. For a middleware
started with `--insecure-dev`, `register --insecure-dev` takes an `http://`
endpoint and prints `allow_insecure_transport = true` with no CA. OpenShell
then sends no caller credential, so use it only for local development.

The supported authorization point is OpenShell v0.1.2 MCP Streamable HTTP
`HTTP_REQUEST / PRE_CREDENTIALS`. See the
[upstream verification](upstream-verification.md) for the exact contract.

## Configure trust policy

Trust is selected by OpenShell's authenticated `sandbox_id`, never by a
reusable display name. A sandbox has an ID only after `openshell sandbox
create`, and the gateway needs the middleware first, so start from a policy
that trusts no sandboxes:

```bash
tenuo-openshell policy init --policy /etc/tenuo/openshell-policy.json
```

The middleware starts on it, denies every request, and logs a warning until
`tenuo-openshell policy add` adds a sandbox. Running replicas load the new
version on their next poll; no restart is needed. A missing policy file is
still a startup error.

A policy with sandboxes looks like this:

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
| `idempotent_tools` | No | Tools for which a resent identical call is the same effect. Every other tool accepts a signed call once; a second identical call inside the proof window is `tenuo_pop_replayed`. |
| `forward_proof` | No | `strip` (default) removes `params._meta.tenuo` before forwarding. `preserve` leaves it for a destination that verifies the warrant itself. |
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
approval reusable until it expires. Production refuses to start with that
setting unless `--allow-reusable-approvals` is set.

### Policy integrity

Production requires a detached signature over the exact policy bytes. Create
a signing key once, sign every policy version with it, and give the middleware
only the public key:

```bash
tenuo-openshell keygen --out policy-signing.key --public-out policy-signing.pub
# prints the public key, for --policy-signing-key
tenuo-openshell policy sign --policy policy.json --key policy-signing.key
# writes policy.json.sig
```

`tenuo-openshell keygen` makes every operator key: issuer, approver, and
policy signing. It writes the secret as 64 hex characters, mode 0600, never
overwrites a file, and prints the public key as 64 hex characters. The same
text, or a file holding it, is what `--trusted-root`, `--policy-signing-key`,
and `receipts export --verify-with` accept. `policy keygen` remains as an
alias.

The signature is Ed25519 over a fixed context string and the SHA-256 of the
policy file, 57 bytes in all. A key held in a KMS or HSM with a message-size
limit can therefore sign it.

Start the middleware with `--policy-signing-key` (64 hex characters, or a
path to that text). When you replace a policy file in place, write the new
`.sig` before the new policy: the middleware skips the reload until the policy
bytes change, so it never pairs the new policy with the old signature. A
Kubernetes ConfigMap that holds both keys updates them together. It checks the signature before the first load and again
before a reload replaces the active snapshot. `--allow-unsigned-policy` is
the explicit exception and cannot be combined with a signing key.

Whoever can sign the policy chooses the trusted issuers for every sandbox, so
the signing key is as sensitive as the issuer keys:

- Mount the policy read-only, and keep the public key in a separate secret
  from the policy file.
- Review policy changes like code: a new trusted root or a wider destination
  grants authority.
- A provider that fetches snapshots must authenticate them before returning
  them; see [Provider integration](providers.md).
- Keep `version` monotonic. The middleware refuses a lower version, so an old
  file cannot be replayed onto a running replica. A restarting replica has no
  floor: it loads any correctly signed policy, including an older one. Keep
  only the current signed version where the middleware reads it. A signed,
  versioned envelope with a persistent floor is tracked in
  [tenuo-ai/tenuo#782](https://github.com/tenuo-ai/tenuo/issues/782).

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

Every tool that is not listed in `idempotent_tools` reserves its proof of
possession the same way, in the same atomic reservation as the request's
approvals. See [Architecture](architecture.md#replay) for what this does and
does not cover.

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
A policy with no sandboxes is ready: the replica is serving its policy
correctly, and that policy denies everything. Readiness that waited for a
sandbox would keep the middleware out of service while the first sandbox is
created, and would take it out again when the last one is removed. Alert on
`tenuo_openshell_policy_sandboxes` instead if an empty policy is unexpected.
Prometheus metrics are exposed on the separate admin listener.

Use the [operations runbook](operations.md) for policy rollout, replay-store
outages, receipt failures, key compromise, upgrades, and rollback.

## Local development

For isolated local development only, `--insecure-dev` enables plaintext calls
without caller authentication. Register it with `tenuo-openshell register
--insecure-dev --middleware-endpoint http://...`. It cannot be combined with production security
options. Production startup refuses partial TLS or JWT configuration.
