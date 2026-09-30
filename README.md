# Safe delegation and task-level authorization for NVIDIA agents

[![CI](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/ci.yml)
[![OpenShell E2E](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/openshell-e2e.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Portable, least-privilege authority for agents running in NVIDIA OpenShell
and NVIDIA NeMo Agent Toolkit.**

OpenShell controls which tools an agent can reach. Tenuo constrains what the
agent may do with an allowed tool for its current task, including the argument
values it may send, and verifies that authority outside the agent process before
OpenShell injects provider credentials.

When work is delegated, each child receives signed authority that can only
stay equal or become narrower: fewer tools, tighter arguments, shorter expiry,
or additional approval requirements. A child cannot restore authority removed
by its parent.

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

The same authority can cross runtime boundaries without being translated into
framework-specific allowlists. A task can originate in LangGraph, delegate over
A2A to an agent in OpenShell, invoke an Agent Toolkit function, and reach an MCP
server while every boundary verifies the same chain independently.

Tenuo has 10+ native integration surfaces across agent frameworks, protocols,
and execution boundaries, including OpenAI Agents SDK, LangChain, LangGraph,
CrewAI, AutoGen, Google ADK, MCP, FastMCP, A2A, FastAPI, and Temporal. See the
[Tenuo integration overview](https://github.com/tenuo-ai/tenuo#integrate-at-the-boundary-you-control).

Tenuo's task-level authorization and monotonic delegation model is being
advanced through the
[Attenuating Authorization Tokens for Agentic Delegation Chains](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/)
Internet-Draft, authored by Tenuo for interoperable agent delegation.

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
| Operate the supervisor middleware | [Deployment guide](docs/deployment.md) |
| Add early denial to Agent Toolkit | [Agent Toolkit plugin](python/nemo-agent-toolkit-tenuo/README.md) |
| Connect an optional control plane | [Provider integration contract](docs/providers.md) |
| Review or contribute | [Architecture](docs/architecture.md) and [Contributing](CONTRIBUTING.md) |

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

```text
task-scoped read                         -> allowed
unauthorized restart                    -> denied
approved restart                        -> allowed once
replayed approval                       -> denied
delegated child attempting wider action -> denied
A2A child using narrowed authority      -> allowed
```

The demo compares OpenShell with and without Tenuo, confirms that denied calls
do not reach the effect, exercises a real A2A handoff, and verifies signed
receipts offline. See the [demo guide](examples/demo/README.md) for the complete
scenario matrix, evidence model, prerequisites, and overrides.

## OpenShell middleware

The supervisor middleware authenticates OpenShell, selects trust roots from the
immutable `sandbox_id`, verifies the warrant chain and holder proof, checks
tool arguments and approvals, and returns a stable allow or denial decision.

See [Deployment](docs/deployment.md) for production configuration and
[Architecture](docs/architecture.md) for the complete trust boundary.

## NVIDIA NeMo Agent Toolkit plugin

Install the source package into the same environment as Agent Toolkit 1.8:

```bash
uv sync --locked --project python/nemo-agent-toolkit-tenuo --extra test
uv run --locked --project python/nemo-agent-toolkit-tenuo nat info components
```

Bind authority to an application-controlled task scope:

```python
from nat.plugins.tenuo import authority

with authority(warrant.bind(holder)):
    result = await workflow.ainvoke(input)
```

The in-process plugin provides early denial and better developer feedback. The
OpenShell service is the independent enforcement boundary for covered outbound
MCP requests. See the
[Agent Toolkit plugin guide](python/nemo-agent-toolkit-tenuo/README.md) for
configuration and error handling.

## Security scope

Tenuo enforces requests that cross the configured OpenShell middleware
binding. Alternate network paths must be denied separately. In OpenShell
v0.1.2, the middleware does not inspect `tls: skip` endpoints, raw TCP, binary
WebSocket frames, or server-to-client WebSocket messages.

The service runs before credential injection and does not receive provider
credentials. See [upstream verification](docs/upstream-verification.md) for the
exact pinned contract and [the MCP gap analysis](docs/openshell-gap-analysis.md)
for protocol coverage.

## Documentation

| Goal | Guide |
| --- | --- |
| Understand components and trust boundaries | [Architecture](docs/architecture.md) |
| Deploy the middleware | [Deployment](docs/deployment.md) |
| Operate and recover it | [Operations runbook](docs/operations.md) |
| Configure Kubernetes | [Helm chart](deploy/helm/tenuo-openshell/README.md) |
| Connect an optional control plane | [Provider contract](docs/providers.md) |
| Inspect the pinned NVIDIA contract | [Upstream verification](docs/upstream-verification.md) |
| Review or contribute | [Contributing](CONTRIBUTING.md) |

## Compatibility

| Component | Supported version |
| --- | --- |
| NVIDIA OpenShell | v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` |
| Supervisor middleware protocol | `openshell.middleware.v1`, protocol `1.0` |
| NVIDIA NeMo Agent Toolkit | `nvidia-nat-core` 1.8.x |
| Tenuo Rust and Python packages | 0.3.x, tested with 0.3.1 |

Compatibility ranges move only after the unit, plugin-discovery, container,
and real-gateway suites pass against the new version.

## Development

```bash
make test
make check
make e2e
```

`make check` is the local release gate. See [Contributing](CONTRIBUTING.md) for
the repository layout, CI coverage, and development workflow.

## License

Apache-2.0. Vendored OpenShell protocol files retain NVIDIA's copyright and
SPDX headers.
