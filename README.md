# Tenuo for NVIDIA OpenShell

[![CI](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml)
[![OpenShell E2E](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Task-scoped authorization for agents running in NVIDIA OpenShell and NVIDIA
NeMo Agent Toolkit.

OpenShell controls which tools an agent can reach. Tenuo constrains what the
agent may do with an allowed tool for its current task—including the argument
values it may send—and verifies that authority outside the agent process before
OpenShell injects provider credentials.

```text
model or agent
      │ proposes tools/call
      ▼
OpenShell MCP policy ── tool name and destination
      │ admitted request; credential still absent
      ▼
Tenuo supervisor middleware ── signed task warrant, PoP, arguments
      │ allowed
      ▼
OpenShell credential injection ── remote MCP effect
```

The integration is Apache-2.0. It consists of:

- `tenuo-openshell-middleware`, an operator-run Rust implementation of
  `openshell.middleware.v1.SupervisorMiddleware`;
- `nemo-agent-toolkit-tenuo`, a provider-owned Agent Toolkit plugin that denies
  unauthorized function calls before `call_next`; and
- an authenticated, end-to-end OpenShell demo that proves denied calls do not
  reach the protected effect.

> [!IMPORTANT]
> The production deployment profile is implemented and tested from source.
> Registry artifacts have not been published yet, so install from a pinned
> source revision and override the Helm image until the first signed release.
> Release image tags include the Git tag's `v` prefix. See
> [Releasing](docs/releasing.md) for the publication gate.

## Choose a path

| Goal | Start here |
| --- | --- |
| Verify a standalone checkout | [Run the local smoke test](#quickstart-standalone-smoke-test) |
| See the security boundary work | [Run the authenticated demo](#quickstart-real-openshell-demo) |
| Operate the supervisor middleware | [Secure production mode](#secure-production-mode) |
| Add early denial to Agent Toolkit | [Agent Toolkit plugin](#nvidia-nemo-agent-toolkit-plugin) |
| Connect an optional control plane | [Provider integration contract](docs/providers.md) |
| Review or contribute | [Architecture](docs/architecture.md) and [Contributing](CONTRIBUTING.md) |

## Repository layout

| Path | Contents |
| --- | --- |
| `src/`, `proto/` | Rust supervisor middleware and pinned OpenShell protocol |
| `python/nemo-agent-toolkit-tenuo/` | Independently buildable Agent Toolkit distribution |
| `examples/demo/` | Real OpenShell gateway and destination-verification demo |
| `examples/interoperability/` | Clearly separated A2A interoperability evidence |
| `ci/`, `.github/workflows/` | Local release gate and hosted verification |
| `docs/` | Architecture, operations, provider contract, upstream contract, gap analysis, and release process |

## Core concepts

- A **warrant** is signed, task-scoped authority: tools, argument constraints,
  lifetime, and optional approval requirements.
- **Proof of possession (PoP)** proves that the current task controls the
  warrant holder key; copying a warrant alone is insufficient.
- **Attenuation** delegates a warrant while only narrowing its authority.
- The Agent Toolkit plugin gives fast, in-process feedback. OpenShell
  middleware is the independent boundary for covered outbound MCP traffic.

## Quickstart: standalone smoke test

Verify the open-source onboarding path before installing OpenShell or creating
production credentials:

```bash
make smoke
```

This builds the Rust binaries, creates local fixture authority, starts the
middleware with the built-in file policy provider, and checks `/live`, `/ready`,
metrics, and receipt-key initialization. It requires Rust, Python 3, and
`curl`. It does not require Docker, an account, an API key, or a hosted Tenuo
service, and it makes no request to one. Cargo may download normal build
dependencies on the first run.

## Quickstart: real OpenShell demo

You need Linux or macOS, Docker 28+ or Podman 5+, Rust 1.91+, Python 3.11+,
`git`, `curl`, `jq`, `nc`, `openssl`, and `make`. The first run downloads and
builds pinned OpenShell components and commonly takes 10–20 minutes.

```bash
make demo
```

The launcher prints and writes `results/outcome-matrix.md`. It builds the
gateway, CLI, middleware, and demo workload, while using NVIDIA's pinned
supervisor and sandbox-runtime images. It creates temporary keys and an
authenticated HTTPS middleware registration, then cleans up the runtime.
See [the demo guide](examples/demo/README.md) for platform details and
overrides.

## See the difference

Two tasks share one sandbox. OpenShell admits both `read_logs` and
`restart_service`. Each task has its own holder key, created in a separate
process and not copied into the sandbox. Task A attenuates its warrant to a
read-only child for a third holder in a second sandbox.

```text
Task A  read_logs(payments, staging)                  → effect executed
Task A  restart_service(payments, staging, replicas=3) → effect executed
        same approval presented again                      → tenuo_approval_replayed
        restart without the signed approval                → tenuo_approval_required
        same approval presented for replicas=5             → tenuo_invalid_authority
Task B  read_logs(payments, staging)                  → effect executed
Task B  restart_service(...)                          → tenuo_tool_denied
Task B signing Task A's warrant                       → tenuo_invalid_authority
Task A  read_logs(identity, production)               → tenuo_constraint_denied
Task A  restart_service(..., replicas=8)              → tenuo_constraint_denied
restart without a warrant                             → tenuo_missing_warrant
child   read_logs(payments, staging)                  → effect executed
child   restart_service(...)                          → tenuo_tool_denied
child adding restart_service back                     → attenuation refused
Agent Toolkit restart with Task B's warrant           → denied before the function
A2A child read over JSON-RPC HTTP                     → effect executed
A2A child restart with read-only warrant              → denied before the skill
```

The `replicas=3` restart carries an approval signed by a local fixture key.
That approval does not cover `replicas=5`. The middleware atomically places the
signed approval nonce in a short-lived pending state, persists the required
receipt, and then commits the nonce before allowing the first effect. A
committed approval cannot be used twice. If receipt persistence fails, the
token-owned reservation is released; if Redis cannot confirm that release,
retries fail as verifier-unavailable instead of being misclassified as replays,
and the pending lease expires after 30 seconds. The Agent Toolkit denial is
recorded in the same offline receipt report as the OpenShell and destination
decisions.

The demo also performs a real Tenuo A2A JSON-RPC handoff over localhost HTTP.
It sends the full parent/child warrant stack plus a child-holder
proof-of-possession signature. The worker executes `read_logs`, while the
read-only delegated authority cannot invoke `restart_service`. This is a
separate [interoperability proof](examples/interoperability/README.md), not a
third distributed package.

The launcher downloads the pinned OpenShell source when needed. It runs the
calls with the warrant check, then again through a
second gateway that does not register the middleware. That sandbox policy
keeps the same tool admission rules and omits the middleware block. OpenShell
rejects a sandbox policy that names a middleware the gateway does not
provide.

Calls whose outcomes match are baseline, and the report records why. The
launcher writes `results/outcome-matrix.md` and prints it. Verification
latency is the time inside the warrant check. The report places the p50 and
p99 of 1,000 checks at each enforcement point next to the configured
middleware timeout, and the median end-to-end time of the sandbox calls from
the first run.

The effect server must observe only the four allowed sandbox calls in the
first run. It still denies a direct call that did not pass through OpenShell.
The launcher then verifies the signed authorization receipts offline with the
issuer and receipt-signer public keys. A receipt records the decision; it
does not show that a tool ran. The launcher cleans up afterward. See
[the demo guide](examples/demo/README.md) for prerequisites and overrides.

## OpenShell middleware

The service supports OpenShell v0.1.2's
`HTTP_REQUEST / PRE_CREDENTIALS` binding for MCP Streamable HTTP. For every
covered `tools/call`, it:

1. authenticates the OpenShell caller;
2. binds the JWT's supervisor identity to `RequestContext.sandbox_id`;
3. selects trusted Tenuo roots for that immutable sandbox id;
4. rejects duplicate-key, batched, malformed, or unsupported JSON-RPC bodies;
5. verifies the warrant chain, proof-of-possession, lifetime, revocation mode,
   approvals, tool capability, and argument constraints; and
6. allows, denies with a stable reason code, or forwards the request.
   `tenuo_meta` is `preserve` or `strip`. The demo preserves `_meta.tenuo`
   because the effect server verifies that same warrant. `strip` is for a
   destination that does not verify Tenuo warrants.

MCP lifecycle methods in the explicit allowlist pass without a warrant.
Unknown methods fail closed.

Fail-closed middleware does not see `tls: skip` endpoints, non-HTTP TCP, or
binary WebSocket frames. Those routes have to be denied by network policy
before they can reach a protected tool. This service does not implement
`WEBSOCKET_MESSAGE`. Text frames on that binding, and `HTTP_RESPONSE`, are not
authorization points here. The HTTP demo does not exercise them.

### Secure production mode

Production mode is the default. It requires server TLS and an
operator-provisioned OpenShell Ed25519 public key:

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

For native Redis Cluster, replace `--replay-redis-url` with
`--replay-redis-cluster-urls redis://node-a:6379/,redis://node-b:6379/`.

The verifier pins `alg=EdDSA`, `typ=openshell-ext+jwt`, optional `kid`, exact
issuer, exact audience, caller shape, expiry, issue time, and OpenShell's
one-hour maximum token lifetime. OpenShell intentionally reuses extension
tokens until rotation, so repeated `jti` values are accepted as required by the
upstream protocol.

Register the service with the same audience:

```toml
[[openshell.supervisor.middleware]]
name = "tenuo/authorization"
grpc_endpoint = "https://tenuo-middleware.example:50051"
tls_ca_cert_path = "/etc/openshell/tenuo-middleware-ca.pem"
audience = "urn:openshell:extension:middleware:tenuo/authorization"
max_payload_bytes = 262144
timeout = "2s"
```

For isolated local development only, `--insecure-dev` enables plaintext calls
without caller authentication. It cannot be combined with production security
options. The process otherwise refuses to start when any TLS or JWT requirement
is missing.

### Tenuo trust policy

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

`approval_replay_protection` uses Redis in the supported production profile.
Approval identity is the approver key plus nonce across the whole deployment;
sandbox boundaries do not reset single-use semantics. All nonces on one
request are reserved atomically with expiry across replicas, and the keys share
a deployment-specific Redis Cluster hash slot. Production startup fails if
replay protection is enabled without Redis. `--allow-in-memory-replay` is an
explicit single-instance demo escape hatch.

Policy files are versioned and polled. A valid higher version replaces the
active snapshot atomically; invalid or rolled-back updates preserve the last
valid version. `/ready` fails when the policy provider, replay backend, or
signed revocation state is stale. `/live` and Prometheus `/metrics` share the
separate admin listener.

The default provider reads this local file and performs no network activity.
Provider-synchronized snapshots add a `valid_until` Unix timestamp so a stale
but readable cache cannot remain authoritative indefinitely. The public
provider and readiness interfaces, durable receipt-export contract, and
acceptance tests are documented in [Provider integration](docs/providers.md).

For emergency revocation, a sandbox entry may require a signed Tenuo SRL:

```json
"revocation": {
  "signed_list_base64": "<signed SRL>",
  "max_staleness_secs": 300,
  "clock_tolerance_secs": 30,
  "rollback_floor_path": "/var/lib/tenuo/revocation-floor.json"
}
```

The middleware verifies issuer signature and freshness and persists a
monotonic rollback floor. Missing, stale, untrusted, rolled-back, or equivocated
state fails closed. Receipts include the SRL version and hash.

### Kubernetes deployment

The [Helm chart](deploy/helm/tenuo-openshell/README.md) supplies the supported
HA deployment: Redis replay protection, readiness/liveness probes, persistent
revocation floors and receipts, non-root read-only containers, resource bounds,
a disruption budget, and default-deny network policy. The network selectors
must match the OpenShell gateway/supervisor and Redis namespaces in the target
cluster.

## NVIDIA NeMo Agent Toolkit plugin

The Python distribution follows NVIDIA's partner-owned package convention:

| Surface | Value |
| --- | --- |
| Distribution | `nemo-agent-toolkit-tenuo` |
| Import | `nat.plugins.tenuo` |
| Entry point | `nat_tenuo` |
| Middleware `_type` | `tenuo` |

Install the source package into the same environment as Agent Toolkit 1.8:

```bash
uv sync --locked --project python/nemo-agent-toolkit-tenuo --extra test
uv run --locked --project python/nemo-agent-toolkit-tenuo nat info components
```

Bind authority to an application-controlled task scope rather than accepting it
from model-generated function arguments:

```python
from nat.plugins.tenuo import authority

with authority(warrant.bind(holder)):
    result = await workflow.ainvoke(input)
```

Configure the middleware once and attach it to protected functions:

```yaml
middleware:
  task_authorization:
    _type: tenuo
    trusted_roots:
      - "<issuer public key as 64 hex characters>"

functions:
  read_logs:
    _type: read_logs
    middleware: [task_authorization]
```

The in-process plugin provides early denial and better developer feedback. The
OpenShell service is the independent enforcement boundary for covered outbound
MCP requests.

## Security scope

This repository makes claims only for traffic that crosses the configured
binding. In OpenShell v0.1.2, the middleware does not inspect:

- `tls: skip` endpoints;
- non-HTTP TCP;
- binary WebSocket frames; or
- server-to-client WebSocket messages.

Network policy must deny alternate routes to a protected tool. WebSocket
evaluation is not implemented by this service. The service does not receive
provider credentials because it runs before credential injection.

OpenShell currently authenticates extension callers with server-authenticated
TLS and short-lived bearer JWTs; it does not issue client certificates for
extension mTLS. See [upstream verification](docs/upstream-verification.md) for
the exact pinned contract and [the MCP gap analysis](docs/openshell-gap-analysis.md)
for why argument authorization belongs in middleware.

## Compatibility

| Component | Supported version |
| --- | --- |
| NVIDIA OpenShell | v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` |
| Supervisor middleware protocol | `openshell.middleware.v1`, protocol `1.0` |
| NVIDIA NeMo Agent Toolkit | `nvidia-nat-core` 1.8.x |
| Tenuo Rust crate | 0.3.x (tested with 0.3.1) |
| Tenuo Python package | 0.3.x (tested with 0.3.1) |

Compatibility ranges move only after the unit, plugin-discovery, container,
and real-gateway suites pass against the new version.

## Development

```bash
make test
make check
make e2e
```

CI runs Rust formatting, linting, tests, a release build, Python tests across
supported versions, Agent Toolkit entry-point discovery, wheel/sdist builds,
container builds, and demo-fixture validation. The authenticated OpenShell
gateway suite is also available as a manual and weekly workflow because it
starts the complete pinned supervisor stack.

Repository-level `make check` is the local release gate. It also builds the
wheel and source distribution and verifies that the source archive does not
contain tests that depend on files outside the Python package.

## License

Apache-2.0. Vendored OpenShell protocol files retain NVIDIA's copyright and
SPDX headers.
