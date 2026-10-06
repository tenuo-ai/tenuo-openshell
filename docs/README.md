# Tenuo for OpenShell documentation

Start with the outcome you want. The guides separate evaluation, integration,
and production operation so you do not need production infrastructure to see
task authority work.

## Evaluate

| Goal | Guide | What it demonstrates |
| --- | --- | --- |
| Make an allowed, a denied, and an approval-gated call next to your OpenShell gateway | [5-minute quickstart](quickstart.md) | Released artifacts, argument constraints, approvals, development mode |
| Run a NeMo Agent Toolkit agent inside an OpenShell sandbox | [NAT agent guide](nat-agent.md) | A ReAct agent's MCP calls under a warrant, approvals, the in-process plugin, NIM through an OpenShell provider |
| Run the same path with production settings | [Going to production](production-quickstart.md) | TLS and JWT middleware authentication, a signed policy |
| See the complete security model | [Authenticated demo](../examples/demo/README.md) | Approvals, replay protection, holder binding, delegation, revocation, A2A, receipts |
| Run an Agent Toolkit approval flow | [NeMo Agent Toolkit example](../examples/nemo-agent-toolkit/README.md) | ReAct tool use through the signing proxy, an exact-call human approval, no model key required |
| Trace authority across runtime boundaries | [A2A interoperability proof](../examples/interoperability/README.md) | A narrowed warrant and holder proof crossing a JSON-RPC handoff |
| Inspect performance | [Performance](performance.md) | Reproducible latency and throughput with Redis, TLS, and receipts |

## Integrate

| Goal | Guide |
| --- | --- |
| Put an existing OpenShell agent under task authority | [Running an agent under Tenuo](sandbox-agent.md) |
| Choose an Agent Toolkit integration path | [Agent Toolkit integration](agent-toolkit.md) |
| Add early, in-process checks to Agent Toolkit functions | [Agent Toolkit plugin](../python/nemo-agent-toolkit-tenuo/README.md) |
| Issue warrants per request or user | [Production issuance](production-issuance.md) |
| Connect a control plane without putting it on the decision path | [Provider contract](providers.md) |

## Deploy and operate

| Goal | Guide |
| --- | --- |
| Configure production middleware | [Deployment](deployment.md) |
| Install the HA Kubernetes profile | [Helm chart](../deploy/helm/tenuo-openshell/README.md) |
| Monitor, recover, rotate, and upgrade | [Operations runbook](operations.md) |
| Verify and export decision evidence | [Receipts](receipts.md) |
| Verify release signatures and provenance | [Release verification](releasing.md) |

## Understand and review

| Topic | Guide |
| --- | --- |
| Components, data flow, and trust boundaries | [Architecture](architecture.md) |
| Attackers, controls, and residual risk | [Threat model](threat-model.md) |
| Supported versions and the CI job behind each | [Compatibility matrix](compatibility-matrix.md) |
| Supported OpenShell extension contract | [Upstream verification](upstream-verification.md) |
| Protocol coverage and known gaps | [OpenShell gap analysis](openshell-gap-analysis.md) |

For repository setup, testing, and pull-request expectations, see
[Contributing](../CONTRIBUTING.md).
