# Tenuo for NVIDIA OpenShell

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

## See the difference

Two tasks share one sandbox. OpenShell admits both `read_logs` and
`restart_service`. Each task has its own holder key, created in a separate
process and not copied into the sandbox.

```text
Task A  read_logs(payments, staging)                  → effect executed
Task A  restart_service(payments, staging, replicas=3) → effect executed
Task B  read_logs(payments, staging)                  → effect executed
Task B  restart_service(...)                          → tenuo_tool_denied
Task B signing Task A's warrant                       → tenuo_invalid_authority
Task A  read_logs(identity, production)               → tenuo_constraint_denied
Task A  restart_service(..., replicas=8)              → tenuo_constraint_denied
restart without a warrant                             → tenuo_missing_warrant
```

Run the calls through a real OpenShell gateway and sandbox:

```bash
make demo
```

The launcher downloads the pinned OpenShell source when needed, builds its
gateway and supervisor image, creates an authenticated HTTPS middleware
registration, runs the requests, verifies that the effect server observed only
the three allowed calls, and cleans up. See [the demo guide](examples/demo/README.md)
for prerequisites and overrides.

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
6. allows, denies with a stable reason code, or strips `_meta.tenuo` before
   forwarding to a destination that does not perform Tenuo verification.

MCP lifecycle methods in the explicit allowlist pass without a warrant.
Unknown methods fail closed.

### Production listener

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
  --audience urn:openshell:extension:middleware:tenuo/authorization
```

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
  "max_warrant_lifetime_secs": 3600,
  "sandboxes": {
    "5ba15c63-8170-4e78-a4aa-df0f94f49642": {
      "trusted_roots": ["<64 lowercase hex characters>"]
    }
  }
}
```

A missing sandbox, missing root, unreadable policy, or unavailable verifier
denies the request.

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
uv sync --project python/nemo-agent-toolkit-tenuo --extra test
uv run --project python/nemo-agent-toolkit-tenuo nat info components
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
builds a full supervisor image.

## License

Apache-2.0. Vendored OpenShell protocol files retain NVIDIA's copyright and
SPDX headers.
