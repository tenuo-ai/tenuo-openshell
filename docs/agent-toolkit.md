# Tenuo with NVIDIA NeMo Agent Toolkit

Tenuo integrates with Agent Toolkit at two complementary enforcement points.
Choose the path that matches where the effect happens, or use both in one
workflow.

| Path | Protects | Integration | Start here |
| --- | --- | --- | --- |
| OpenShell boundary | MCP calls leaving an OpenShell sandbox | Point Agent Toolkit's MCP client at `tenuo-openshell-agent proxy`; OpenShell invokes the Tenuo supervisor middleware before credential injection | [Runnable ReAct approval example](../examples/nemo-agent-toolkit/README.md) |
| In-process middleware | Native Agent Toolkit functions before `call_next` | Install `nemo-agent-toolkit-tenuo` from PyPI and attach the `tenuo` middleware to protected functions | [Plugin guide](../python/nemo-agent-toolkit-tenuo/README.md) |

The two paths use the same warrant semantics. A workflow can reject an
unauthorized native function early, then carry the same task authority through
MCP for independent verification at the OpenShell boundary.

## Run the Agent Toolkit example

The repository includes a deterministic ReAct workflow that needs no model
account or API key:

```bash
git clone https://github.com/tenuo-ai/tenuo-openshell.git
cd tenuo-openshell
examples/nemo-agent-toolkit/run.sh
```

It demonstrates the complete user-visible approval loop:

1. the agent reads staging logs within its warrant;
2. a restart pauses because it requires an approval;
3. an operator reviews and signs the exact tool and arguments;
4. the retry runs once; and
5. another restart requires a new approval.

The example uses Agent Toolkit's standard ReAct, LangChain, and MCP client
paths. A deterministic OpenAI-compatible model stub makes the outcome
repeatable. Set `NVIDIA_API_KEY` and `TENUO_EXAMPLE_LIVE=1` to run the same
workflow with a hosted NIM model.

## Add the in-process plugin

For an Agent Toolkit application, PyPI is the recommended installation path:

```bash
pip install nemo-agent-toolkit-tenuo
nat info components | grep tenuo
```

Attach `_type: tenuo` middleware to the functions that need task-level
authorization, then bind the task's warrant in application-controlled scope
around the workflow invocation. Model output and function arguments never
select the authority.

See the [plugin guide](../python/nemo-agent-toolkit-tenuo/README.md) for the
configuration and binding API. In production, the application receives a
short-lived warrant from its orchestrator or issuer. The
[production issuance guide](production-issuance.md) covers standalone issuance
and the optional Tenuo Cloud path.

## Carry authority across runtimes

A warrant is not an Agent Toolkit session token or an OpenShell policy object.
It is portable task authority. The same delegation chain can be verified by
Agent Toolkit, OpenShell, an MCP server, an A2A worker, or another supported
runtime without translating it into separate framework-specific grants.

See the [A2A interoperability proof](../examples/interoperability/README.md)
and the [Tenuo integration overview](https://github.com/tenuo-ai/tenuo#integrate-at-the-boundary-you-control).
