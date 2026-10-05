# Tenuo for NVIDIA OpenShell

[![CI](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml)
[![OpenShell E2E](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Give each agent task in an OpenShell sandbox only the tool calls it needs:
which tools, which argument values, for how long, and with whose approval.**

Tenuo plugs into OpenShell as a supervisor middleware. Every MCP `tools/call`
that leaves the sandbox is checked against the task's *warrant* before
OpenShell attaches any credentials. A warrant is a signed grant held by one
task, and it can only narrow when the task delegates. The agent's code does not
change.

[Run the demo](examples/demo/README.md) ·
[Put an agent under Tenuo](docs/sandbox-agent.md) ·
[Deploy](docs/deployment.md)

## Why

An OpenShell sandbox policy answers one question: may this sandbox call
`restart_service` on this server? The policy is written once per sandbox, and
its MCP matcher reads only the tool name
([`sandbox.proto` at v0.1.2](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/proto/sandbox.proto)).
Every task in that sandbox gets the same answer, for any service, environment,
or replica count.

Tenuo answers a narrower question: may *this task* make *this call*? The
warrant names the task's tools and the argument values it may send. It is
bound to a key only that task holds. It can require a human approval for a
specific call, and revoking it stops the task and everything the task
delegated.

Here is the same sandbox policy and the same tool, from the
[demo](examples/demo/README.md):

| Call | OpenShell alone | OpenShell + Tenuo |
| --- | --- | --- |
| Restart `payments` in staging, 3 replicas, with an approval | Runs | Runs |
| Replay that approval | Runs again | Denied `tenuo_approval_replayed` |
| Restart `auth` in staging | Runs | Denied `tenuo_constraint_denied` |
| Restart `payments` with 8 replicas | Runs | Denied `tenuo_constraint_denied` |
| Read `identity` logs in production | Runs | Denied `tenuo_constraint_denied` |
| Use a stolen warrant from another task | Runs | Denied `tenuo_invalid_authority` |
| Sub-agent in a second sandbox, after an ancestor warrant is revoked | Runs | Denied `tenuo_revoked` |

Denied calls never reach the MCP server, and no credential is attached to them.

## How it fits OpenShell

```text
agent's MCP client
      │ tools/call
      ▼
tenuo-openshell-agent proxy ── signs with the task's key (inside the sandbox)
      │
      ▼
OpenShell L7 policy ── binary, destination, tool name
      │ admitted; credential not yet attached
      ▼
Tenuo supervisor middleware ── destination, warrant chain, holder proof,
      │                        arguments, approvals, revocation
      │ allow
      ▼
OpenShell credential injection ──► MCP server
```

- **Uses OpenShell's own extension point.** The middleware implements
  `openshell.middleware.v1.SupervisorMiddleware` at
  `HTTP_REQUEST / PRE_CREDENTIALS`. It needs no fork or patch of OpenShell.
- **Never sees provider credentials.** It runs before injection. On allow, it
  strips the Tenuo proof from the forwarded request by default.
- **Keyed to OpenShell identity.** Trust roots are selected by the
  authenticated `sandbox_id`, never a display name. OpenShell's extension JWT
  is verified on every call.
- **Fails closed.** Malformed requests, unknown sandboxes or destinations, and
  an unavailable replay store or revocation list all deny.
- **Leaves the agent alone.** The agent's MCP client points at a loopback
  proxy in the sandbox, which signs each call. The agent needs no Tenuo code.

Register the middleware with the gateway:

```toml
[[openshell.supervisor.middleware]]
name = "tenuo/authorization"
grpc_endpoint = "https://tenuo-middleware.example:50051"
tls_ca_cert_path = "/etc/openshell/tenuo-middleware-ca.pem"
audience = "urn:openshell:extension:middleware:tenuo/authorization"
max_payload_bytes = 262144
timeout = "2s"
```

Attach it in the sandbox policy:

```yaml
network_middlewares:
  tenuo-task-authority:
    middleware: tenuo/authorization
    on_error: fail_closed
    endpoints:
      include:
        - mcp.internal
```

Then issue the task's warrant. This one allows payments log reads in staging or
dev, and restarts of payments in staging up to 5 replicas:

```json
{
  "read_logs": {
    "service": "payments",
    "environment": {"one_of": ["staging", "dev"]}
  },
  "restart_service": {
    "service": "payments",
    "environment": "staging",
    "replicas": {"range": {"max": 5}}
  }
}
```

`tenuo-openshell register` prints the gateway and sandbox blocks for your
endpoints. `tenuo-openshell provision` generates the holder key inside the
sandbox and installs the warrant. [Running an agent under Tenuo](docs/sandbox-agent.md)
walks through it end to end.

## Capabilities

- **Argument constraints:** exact values, allowed sets, glob patterns, and
  numeric ranges per argument. Once a tool lists constraints, arguments it
  does not list are rejected.
- **Holder-bound warrants:** every call carries a proof of possession from the
  task's key. A warrant copied out of the sandbox or into another task is
  useless.
- **Human approvals:** a warrant can require signed approvals for a tool.
  `tenuo-openshell approve` shows the approver the exact tool and arguments,
  and each approval authorizes one call.
- **Delegation and sub-agents:** an agent can pass a narrower warrant to a
  sub-agent in the same sandbox or in another sandbox. Terminal warrants
  cannot be delegated further. Revoking any warrant in the chain denies every
  call that carries it, including running children.
- **Signed receipts:** every verified decision is signed and hash-chained.
  With `--evaluate-results`, the result of each allowed call gets a receipt
  linked to its decision. Receipts can be verified offline or exported as
  JSON lines.
- **Result limits:** a per-sandbox cap on the bytes of tool results returned to
  the agent.
- **Production operation:**
  - TLS and JWT caller authentication
  - a signed policy file
  - Redis-backed single-use approvals across replicas
  - versioned policy hot reload and signed revocation lists with rollback
    floors
  - Prometheus metrics, OpenTelemetry traces, and a hardened HA Helm chart
- **NeMo Agent Toolkit:** a middleware plugin that denies unauthorized function
  calls in process, before `call_next`.

The decision is fast enough to run inline on every call. Over 1,000
iterations of the demo's requests, in a debug build, it took 0.45 ms at p50 and
1.5 ms at p99. The middleware timeout is 2 s. Each demo run records these
numbers in its outcome matrix.

## Try it

Check a checkout without Docker or OpenShell. This needs Rust, Python 3, and
`curl`:

```bash
make smoke
```

Run the full comparison against a real, pinned OpenShell gateway:

```bash
make demo
```

The demo needs Docker 28+ or Podman 5+, Rust 1.91+, Python 3.11+, `git`,
`curl`, `jq`, `nc`, `openssl`, and `make`. The first run builds the pinned
OpenShell components and takes 10–20 minutes. It runs every scenario twice,
with and without Tenuo, and confirms denied calls never reach the tool. It
writes `results/outcome-matrix.md` and verifies every receipt offline. See the
[demo guide](examples/demo/README.md).

To run an Agent Toolkit ReAct agent with a human approval step, use
[the NeMo Agent Toolkit example](examples/nemo-agent-toolkit/README.md). It
needs no model or API key.

## Install

| Component | Runs | Role |
| --- | --- | --- |
| `tenuo-openshell-middleware` | Next to the OpenShell gateway | The supervisor middleware |
| `tenuo-openshell-agent` | Inside each sandbox | Holds the task's key and warrant, and signs calls through a loopback MCP proxy |
| `tenuo-openshell` | Operator machine or orchestrator | Edits the trust policy, prints OpenShell configuration, and provisions, delegates, and approves |
| `nemo-agent-toolkit-tenuo` | In the Agent Toolkit process | Denies unauthorized function calls before they run |

Deploy the middleware with the Helm chart. See the
[chart README](deploy/helm/tenuo-openshell/README.md) for the values to set:

```bash
helm install tenuo-openshell oci://ghcr.io/tenuo-ai/charts/tenuo-openshell \
  --version 0.1.1 -f values.yaml
```

Or run the image directly: `ghcr.io/tenuo-ai/tenuo-openshell:v0.1.1`.

Add the agent to your sandbox image:

```dockerfile
COPY --from=ghcr.io/tenuo-ai/tenuo-openshell-agent:v0.1.1 \
  /usr/local/bin/tenuo-openshell-agent /usr/local/bin/
```

Download `tenuo-openshell` for Linux or macOS from the
[latest release](https://github.com/tenuo-ai/tenuo-openshell/releases/latest).
Install the Agent Toolkit plugin from PyPI:

```bash
pip install nemo-agent-toolkit-tenuo
```

Images, the chart, and the binaries are signed with keyless cosign and carry
build provenance. See [Verifying a release](docs/releasing.md#verifying-the-image-chart-and-package).
To build from source instead, run `cargo build --release --locked --bins`.

## Guides

| Goal | Guide |
| --- | --- |
| Put an existing agent under Tenuo | [Running an agent under Tenuo](docs/sandbox-agent.md) |
| Deploy the middleware | [Deployment](docs/deployment.md) and the [Helm chart](deploy/helm/tenuo-openshell/README.md) |
| Operate and recover it | [Operations runbook](docs/operations.md) |
| Hold issuer keys and issue warrants per request | [Production issuance](docs/production-issuance.md) |
| Understand the components and trust boundaries | [Architecture](docs/architecture.md) |
| Review attackers, controls, and residual risk | [Threat model](docs/threat-model.md) |
| Verify and export receipts | [Receipts](docs/receipts.md) |
| Add in-process checks to Agent Toolkit | [Agent Toolkit plugin](python/nemo-agent-toolkit-tenuo/README.md) |
| Connect a control plane | [Provider contract](docs/providers.md) |
| Check the pinned OpenShell contract | [Upstream verification](docs/upstream-verification.md) |
| Contribute | [Contributing](CONTRIBUTING.md) |

## Security scope

Tenuo authorizes MCP Streamable HTTP traffic that crosses the configured
middleware binding. OpenShell network policy closes the other paths. In
v0.1.2, the middleware does not see `tls: skip` endpoints, raw TCP, binary
WebSocket frames, or server-to-client WebSocket messages, so deny those routes
to protected servers.

The warrant bounds what a compromised agent can do; it does not judge intent.
Narrow warrants, approvals, and short lifetimes are the controls for that. The
[threat model](docs/threat-model.md) lists each attacker, where each control
is enforced, and what remains.

## Compatibility

| Component | Version |
| --- | --- |
| NVIDIA OpenShell | v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` |
| Supervisor middleware protocol | `openshell.middleware.v1`, protocol `1.0` |
| NVIDIA NeMo Agent Toolkit | `nvidia-nat-core` 1.8.x |
| Tenuo | 0.3.x, tested with 0.3.2 |

A range moves only after the unit, plugin, container, and real-gateway suites
pass against the new version.

## Beyond OpenShell

The same warrant chain is verified at every boundary it crosses. A task can
start in LangGraph, delegate over A2A to an agent in OpenShell, and reach an
MCP server, with each hop checking the same authority. Tenuo integrates with
the OpenAI Agents SDK, LangChain, LangGraph, CrewAI, AutoGen, Google ADK, MCP,
FastMCP, A2A, FastAPI, and Temporal. See the
[Tenuo integration overview](https://github.com/tenuo-ai/tenuo#integrate-at-the-boundary-you-control).

The delegation model is specified in the
[Attenuating Authorization Tokens for Agentic Delegation Chains](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/)
Internet-Draft.

## Development

```bash
make test
make check
make e2e
```

`make check` is the local release gate. See [Contributing](CONTRIBUTING.md).

## License

Apache-2.0. Vendored OpenShell protocol files keep NVIDIA's copyright and SPDX
headers. NVIDIA, OpenShell, and NeMo are trademarks of NVIDIA Corporation.
Tenuo for NVIDIA OpenShell is an independent project by Tenuo.
