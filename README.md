# Tenuo for NVIDIA OpenShell

[![CI](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml)
[![OpenShell E2E](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Portable task authority for agents secured by NVIDIA OpenShell.**

OpenShell provides the secure runtime boundary: sandbox isolation, network
policy, and protected credential injection. Tenuo builds on that boundary by
giving each agent task only the authority it needs: which tools it may call,
which arguments it may send, for how long, and with whose approval.

Tenuo checks every covered MCP `tools/call` before OpenShell attaches provider
credentials. Authority is carried in a signed *warrant* held by the task and
can only become narrower when work is delegated. No fork of OpenShell and no
Tenuo code in the agent are required.

Inside the NVIDIA stack, the same authority can be checked early in NeMo Agent
Toolkit and independently at the OpenShell boundary. When a workflow crosses
into another agent runtime, the warrant travels with the task instead of being
rebuilt as a framework-specific allowlist.

[Quickstart](docs/quickstart.md) ·
[Agent Toolkit](docs/agent-toolkit.md) ·
[Run the demo](examples/demo/README.md) ·
[Put an agent under Tenuo](docs/sandbox-agent.md) ·
[Deploy](docs/deployment.md) ·
[All guides](docs/README.md)

## What Tenuo adds to OpenShell

OpenShell and Tenuo enforce different, complementary scopes:

| Layer | Question it answers | Examples |
| --- | --- | --- |
| OpenShell runtime policy | May this sandbox reach this resource? | Process, filesystem, network destination, credential use |
| Tenuo task authority | May this task make this exact call? | Tool, argument values, expiry, approval, delegation chain |

The OpenShell policy first admits traffic to an approved MCP endpoint. Tenuo
then verifies that the current task has authority for the requested operation.
Both checks must allow before OpenShell injects credentials and forwards the
call.

For example, one sandbox can host several tasks that can reach the same
operations server while their warrants grant different authority:

| Task attempt | Task authority check | Result |
| --- | --- | --- |
| Restart `payments` in staging with the required approval | Tool, arguments, and approval match | Allowed |
| Replay the same approval | Approval was already consumed | Denied |
| Restart `payments` with 8 replicas | Exceeds the warrant's argument limit | Denied |
| Read `identity` logs in production | Outside the task's service and environment scope | Denied |
| Use a warrant copied from another task | Holder proof does not match | Denied |
| Continue after an ancestor warrant is revoked | Delegation chain contains a revoked warrant | Denied |

Denied calls never reach the MCP server, and no credential is attached to them.

## Get started

Choose the shortest path that demonstrates the capability you care about:

| Goal | What you will see | Start |
| --- | --- | --- |
| Prove task-level enforcement | Your own OpenShell gateway: one allowed call, one denied outside the task, and a restart held until you approve it | [Quickstart](docs/quickstart.md) |
| Add authorization to Agent Toolkit | Choose in-process function checks, OpenShell enforcement for MCP calls, or both | [Agent Toolkit guide](docs/agent-toolkit.md) |
| See a human approval flow | A NeMo Agent Toolkit ReAct agent pauses a restart until an approver signs the exact call | [`examples/nemo-agent-toolkit/run.sh`](examples/nemo-agent-toolkit/README.md) |
| Exercise the complete security model | Constraints, approval replay protection, holder binding, cross-runtime delegation, revocation, and signed receipts | [`make demo`](examples/demo/README.md) |
| Protect an existing OpenShell agent | Add the signing proxy, register the middleware, and provision task authority | [Integration guide](docs/sandbox-agent.md) |
| Run it in production | TLS, the gateway's JWT, a signed policy, and Redis replay protection | [Going to production](docs/production-quickstart.md) |

The quickstart adds Tenuo to the OpenShell gateway you already run, in
development mode, in about 5 minutes. `tenuo-openshell dev up` prints the
gateway block for you to paste; it never edits your OpenShell install. The
calls are fixed, so it needs no model or API key, and neither does the Agent
Toolkit example.

```bash
tenuo-openshell dev up      # middleware and a demo MCP server; prints the gateway block
openshell sandbox create --name tenuo-demo ...
tenuo-openshell provision --dev --sandbox tenuo-demo --preset demo
tenuo-openshell demo call restart_service service=payments environment=staging replicas=3
```

Agent Toolkit has two integration paths. The PyPI plugin protects native
functions in process, while the signing proxy and OpenShell middleware protect
MCP calls at the sandbox boundary. The [Agent Toolkit guide](docs/agent-toolkit.md)
shows both and links to the no-model approval example.

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

The operator CLI prints the OpenShell gateway and sandbox configuration, then
provisions a holder key and warrant inside the sandbox. The agent points its
MCP client at the loopback proxy. This example authority allows payments log
reads in staging or dev, and payments restarts in staging up to 5 replicas:

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

The [integration guide](docs/sandbox-agent.md) walks through registration,
policy signing, warrant provisioning, proxy configuration, delegation, and
approvals end to end.

## Core capabilities

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

The decision is fast enough to run inline on every call. In a release build
on one Apple M3 Max laptop, over gRPC, a call to a tool that is not single-use
took 0.18 ms at p50 and 0.28 ms at p99. A single-use call, whose proof is
reserved in Redis, took 0.76 ms at p50 and 1.6 ms at p99, most of it two
round trips to a local Redis. One replica decided about 27,000 single-use
calls per second with 64 concurrent callers, or about 12,000 with required
receipts. The middleware timeout is 2 s. See [Performance](docs/performance.md)
for the method, full tables, and `make bench` to reproduce them.

## Install

### Agent Toolkit plugin

For Agent Toolkit applications, install the published plugin from PyPI. This
is the recommended path for application developers:

```bash
pip install nemo-agent-toolkit-tenuo
nat info components
```

The package metadata selects compatible `nvidia-nat-core` and Tenuo versions.
Current source supports Agent Toolkit 1.8 and 1.9; use a source checkout only
to test changes that have not reached PyPI yet.

### OpenShell components

The OpenShell integration has three components because each belongs at a
different trust boundary:

| Component | Runs | Role |
| --- | --- | --- |
| `tenuo-openshell-middleware` | Next to the OpenShell gateway | The supervisor middleware |
| `tenuo-openshell-agent` | Inside each sandbox | Holds the task's key and warrant, and signs calls through a loopback MCP proxy |
| `tenuo-openshell` | Operator machine or orchestrator | Edits the trust policy, prints OpenShell configuration, and provisions, delegates, and approves |

Deploy the middleware with the Helm chart. See the
[chart README](deploy/helm/tenuo-openshell/README.md) for the values to set:

```bash
helm install tenuo-openshell oci://ghcr.io/tenuo-ai/charts/tenuo-openshell \
  --version 0.1.2 -f values.yaml
```

Or run the image directly: `ghcr.io/tenuo-ai/tenuo-openshell:v0.1.2`.

Add the agent to your sandbox image:

```dockerfile
COPY --from=ghcr.io/tenuo-ai/tenuo-openshell-agent:v0.1.2 \
  /usr/local/bin/tenuo-openshell-agent /usr/local/bin/
```

Download `tenuo-openshell` for Linux or macOS from the
[latest release](https://github.com/tenuo-ai/tenuo-openshell/releases/latest).

Images, the chart, and the binaries are signed with keyless cosign and carry
build provenance. See [Verifying a release](docs/releasing.md#verifying-the-image-chart-and-package).
To build from source instead, run `cargo build --release --locked --bins`.

## Guides

| Goal | Guide |
| --- | --- |
| Find the right evaluation, integration, or operations path | [Documentation index](docs/README.md) |
| Try it in 5 minutes next to your OpenShell gateway | [Quickstart](docs/quickstart.md) |
| Add Tenuo to Agent Toolkit | [Agent Toolkit integration paths](docs/agent-toolkit.md) |
| Run the middleware with TLS, JWT, and a signed policy | [Going to production](docs/production-quickstart.md) |
| Put an existing agent under Tenuo | [Running an agent under Tenuo](docs/sandbox-agent.md) |
| Deploy the middleware | [Deployment](docs/deployment.md) and the [Helm chart](deploy/helm/tenuo-openshell/README.md) |
| Operate and recover it | [Operations runbook](docs/operations.md) |
| Issue warrants per request, with Tenuo Cloud or your own issuer | [Production issuance](docs/production-issuance.md) |

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
| NVIDIA NeMo Agent Toolkit | Current source: 1.8.x and 1.9.x; released range is declared on PyPI |
| Tenuo | 0.3.x, tested with 0.3.2 |

A range moves only after the unit, plugin, container, and real-gateway suites
pass against the new version.

## Portable across agent runtimes

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
