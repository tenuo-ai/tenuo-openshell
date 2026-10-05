# NeMo Agent Toolkit agent through the Tenuo signing proxy

A NeMo Agent Toolkit 1.9 ReAct agent whose MCP tools go through
`tenuo-openshell-agent proxy`. The agent's configuration has no Tenuo code:
its `mcp_client` function group points at the loopback proxy, which signs each
`tools/call` with the holder key. The warrant decides which calls leave.

This example demonstrates Agent Toolkit using portable Tenuo authority across
an MCP boundary. It does not use the in-process `nemo-agent-toolkit-tenuo`
plugin. Use the [Agent Toolkit guide](../../docs/agent-toolkit.md) to choose
between the proxy, the plugin, or both.

The example also shows a human approval step:

1. The agent reads the staging payments logs. Allowed.
2. It asks for a restart. The warrant requires one approval for restarts, so
   the agent gets `Approval required: request <hash> …` as a tool error and
   the proxy records the pending request.
3. An approver reviews the exact tool and arguments and approves them:

   ```bash
   tenuo-openshell approve --sandbox my-sandbox --request <hash> \
     --approver-key approver.key --trusted-root issuer.pub
   ```

   `approve` verifies the pending warrant chain to the trusted root and checks
   the request against that warrant before it shows anything, so the
   signature covers exactly what was reviewed.
4. The agent runs again. The restart goes through, and the MCP server verifies
   the warrant and approval again before acting.
5. A later restart needs a new approval: each one authorizes one call.

## Run it

Requirements: Rust, `uv`, `jq`, and `nc`. No model or API key is needed.

```bash
examples/nemo-agent-toolkit/run.sh
```

Expected result:

```text
PASS read allowed; restart held for approval
PASS approved restart ran
PASS a used approval does not authorize another restart
ALL PASS
```

The script builds the binaries, installs NeMo Agent Toolkit 1.9 into a
temporary environment, and runs the steps above against the demo MCP server.
`scripted_llm.py` stands in for the model: an OpenAI-compatible endpoint that
calls the tools the prompt asks for, so NAT's standard `openai` client and
LangChain path are the ones a hosted model would use.

With a hosted model:

```bash
export NVIDIA_API_KEY=...
TENUO_EXAMPLE_LIVE=1 examples/nemo-agent-toolkit/run.sh
```

The live run uses [`workflow.yml`](workflow.yml) with a NIM model. The model
chooses its own calls, so the script reports the run instead of asserting
each step.

This example runs on the host. To run the agent itself inside an OpenShell
sandbox, next to the gateway you already run, follow
[A NeMo Agent Toolkit agent in an OpenShell sandbox](../../docs/nat-agent.md).
[`scripts/openshell-e2e.sh`](../../scripts/openshell-e2e.sh) runs the same
proxy and approval flow inside an OpenShell sandbox.

## Files

| File | Purpose |
| --- | --- |
| [`workflow.yml`](workflow.yml) | ReAct agent on a NIM model with MCP tools through the proxy. |
| [`workflow-scripted.yml`](workflow-scripted.yml) | The same agent on the scripted model. |
| [`scripted_llm.py`](scripted_llm.py) | OpenAI-compatible endpoint that plays a scripted ReAct model. |
| [`run.sh`](run.sh) | Sets up keys, warrant, servers, and proxy; runs and checks each step. |

For in-process early denial inside Agent Toolkit itself, see the
[Agent Toolkit plugin](../../python/nemo-agent-toolkit-tenuo/README.md). The
two compose: the plugin checks a function before it runs, and the proxy signs
and the middleware enforces what reaches MCP.
