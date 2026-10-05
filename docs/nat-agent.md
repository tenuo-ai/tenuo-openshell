# A NeMo Agent Toolkit agent in an OpenShell sandbox

OpenShell keeps your NVIDIA API key out of the sandbox. Tenuo keeps the
agent's tool calls inside its task.

This guide runs a NeMo Agent Toolkit (NAT) 1.9 ReAct agent inside an OpenShell
sandbox. Its MCP tools go through the Tenuo agent's proxy, which signs each
`tools/call` with the sandbox's warrant, and the Tenuo middleware in OpenShell
checks it. The workflow configuration has no Tenuo code: its `mcp_client`
function group points at the proxy on loopback.

It starts where the [quickstart](quickstart.md) ends, and needs no model or
API key until the last, optional section.

| The agent asks for | Without Tenuo | With Tenuo |
| --- | --- | --- |
| The payments logs in staging | Runs | Runs |
| The identity logs in production | Runs | Denied; the agent reads why |
| A restart of payments in staging | Runs | Held until you approve it, then runs once |

OpenShell's sandbox policy lets only the Tenuo agent connect to the MCP
server, so the agent's Python has no way around the proxy.

## Before you start

- You have done the [quickstart](quickstart.md) through step 2: the Tenuo
  CLI is installed, `tenuo-openshell dev up` is running, and your gateway has
  the `tenuo/authorization` block and was restarted. If you cleaned up after
  the quickstart, do its step 2 again.
- `tenuo-openshell` v0.1.6 or later, which adds `demo agent`. Check with
  `tenuo-openshell --version`; to upgrade, repeat the quickstart's step 1.
- About 180 MB of image download.

## 1. Create the agent's sandbox

`dev up` writes a second sandbox policy for this guide. Running it again
changes nothing else:

```bash
tenuo-openshell dev up
```

`~/.local/state/tenuo-openshell/dev/nat-policy.yaml` is the quickstart's
demo policy without curl: only the Tenuo agent may reach the MCP server, and
the middleware checks every call it sends there.

```yaml
    binaries:
      - path: /usr/local/bin/tenuo-openshell-agent
```

NAT's Python is in no rule, so OpenShell lets it reach only loopback inside
the sandbox: the agent's proxy, and a scripted model.

Create the sandbox. Its image holds NAT 1.9 with the MCP client and the
LangChain ReAct agent, the Tenuo agent, and the workflows in `/etc/tenuo-nat`.
The sandbox runs the Tenuo agent's proxy, as in the quickstart:

```bash
openshell sandbox create --name tenuo-nat \
  --from ghcr.io/tenuo-ai/tenuo-openshell-nat-demo:v0.1.6 \
  --policy ~/.local/state/tenuo-openshell/dev/nat-policy.yaml \
  --no-tty --detach -- tenuo-openshell-agent proxy --upstream http://host.openshell.internal:18680/mcp
```

With the OpenShell snap, pass
`--policy ~/snap/openshell/common/tenuo-openshell/nat-policy.yaml`.

Give it the quickstart's task: read the payments logs in staging or dev, and
restart payments in staging once an approver signs the call.

```bash
tenuo-openshell provision --dev --sandbox tenuo-nat --preset demo
```

```text
trusted sandbox tenuo-nat (3d1ba8bc-b1b0-457c-9107-19dd12713b4e) in the dev policy, version 3
sandbox  tenuo-nat
holder   1367b7c55bb70363f3a855e9b98a665299ef6bbb967a82e9e97b4b4a498d0659
warrant  tnu_wrt_01a10cfe2c3c7642a1a2f83b72a09d67
tools    read_logs, restart_service
approval restart_service needs 1 of 1 approver(s)
```

The workflow, `/etc/tenuo-nat/scripted.yml`, is an ordinary NAT
configuration:

```yaml
function_groups:
  ops:
    _type: mcp_client
    server:
      transport: streamable-http
      url: http://127.0.0.1:7415/mcp   # the Tenuo agent's proxy

llms:
  scripted:
    _type: openai
    base_url: http://127.0.0.1:18080/v1
    api_key: not-used
    model_name: scripted

workflow:
  _type: react_agent
  tool_names: [ops]
  llm_name: scripted
  verbose: true
  pass_tool_call_errors_to_agent: true
```

The model is scripted: an OpenAI-compatible endpoint on loopback in the
sandbox that calls the tools the prompt asks for, so the runs below are
repeatable. NAT's `openai` client and the LangChain ReAct agent are the ones a
hosted model uses.

## 2. Run the agent

`demo agent` runs the agent once on a prompt in the sandbox, and prints each
tool call it made and what happened to it. It runs
`openshell sandbox exec --name tenuo-nat -- tenuo-nat-run scripted "<prompt>"`,
which starts the scripted model if needed and runs
`nat run --config_file /etc/tenuo-nat/scripted.yml --input "<prompt>"`.
`--verbose` also prints NAT's own output.

A task inside the warrant runs:

```bash
tenuo-openshell demo agent "Check the payments logs in staging"
```

```text
allowed  read_logs(service=payments, environment=staging): payments/staging: 3 lines, last: GET /health 200
answer   read_logs ran: payments/staging: 3 lines, last: GET /health 200
```

One outside it is denied. The proxy checks the warrant and does not sign the
call, so it never leaves the sandbox. The workflow sets
`pass_tool_call_errors_to_agent`, so the denial is the agent's observation,
and it can answer with it:

```bash
tenuo-openshell demo agent "Check the identity logs in production"
```

```text
denied   read_logs(service=identity, environment=production): Authorization denied: Constraint not satisfied
answer   read_logs did not run: Authorization denied: Constraint not satisfied.
```

<!-- check: open-stdin -->

A restart waits for a human. The proxy records the request, and the agent
reads that it is waiting:

```bash
tenuo-openshell demo agent "Restart payments in staging"
```

```text
held     restart_service(service=payments, environment=staging, replicas=3): waiting for approval, request 8d554873e5d8
         approve it with: tenuo-openshell approve --dev --sandbox tenuo-nat --request 8d554873e5d8
answer   restart_service did not run: Approval required: request 8d554873e5d8 is waiting for an approver.
```

Approve it, as in the quickstart. `approve` shows the exact call and asks
before it signs:

```bash
tenuo-openshell approve --dev --sandbox tenuo-nat
```

```text
tool      restart_service
arguments {"environment":"staging","replicas":3,"service":"payments"}
message   Approval required for tool 'restart_service'
warrant   tnu_wrt_01a10cfe2c3c7642a1a2f83b72a09d67
request   8d554873e5d8a2670a8e457c7374b52a660a29a9e613590e43f3bc21ae35342c
expires   in 300 seconds
approve this call? [y/N] y
approved 8d554873e5d8a2670a8e457c7374b52a660a29a9e613590e43f3bc21ae35342c in sandbox tenuo-nat
```

Ask again. The restart runs, and the approval is spent:

```bash
tenuo-openshell demo agent "Restart payments in staging"
```

```text
allowed  restart_service(service=payments, environment=staging, replicas=3): restarted payments in staging with 3 replicas
answer   restart_service ran: restarted payments in staging with 3 replicas
```

```bash
tenuo-openshell demo agent "Restart payments in staging"
```

```text
held     restart_service(service=payments, environment=staging, replicas=3): waiting for approval, request 8d554873e5d8
         approve it with: tenuo-openshell approve --dev --sandbox tenuo-nat --request 8d554873e5d8
answer   restart_service did not run: Approval required: request 8d554873e5d8 is waiting for an approver.
```

The proxy is the agent's only way to the MCP server. From the same sandbox,
NAT's Python cannot connect to it at all:

```bash
openshell sandbox exec --name tenuo-nat -- python3 -c '
import urllib.request
try:
    urllib.request.urlopen("http://host.openshell.internal:18680/mcp", timeout=5)
except OSError as error:
    print(error)'
```

```text
<urlopen error [Errno 13] Permission denied>
```

The sandbox log names the binary OpenShell refused:
`openshell logs tenuo-nat | grep DENIED` shows
`DENIED /usr/local/bin/python3.12(0) -> host.openshell.internal:18680`.

## 3. Optional: check calls inside the agent too

The [`nemo-agent-toolkit-tenuo`](../python/nemo-agent-toolkit-tenuo/README.md)
plugin is NAT middleware that checks each function call against a warrant
before the function runs. On the MCP tools, it denies a call outside the task
inside the agent, before the call reaches the proxy. The proxy and the
middleware in OpenShell still check every call that gets through.

The image has it installed, and `/etc/tenuo-nat/scripted-plugin.yml` is
`scripted.yml` with the plugin on the `ops` function group:

```yaml
middleware:
  tenuo:
    _type: tenuo
    trusted_roots: ["${TENUO_TRUSTED_ROOT}"]
    warrant_file: ${HOME}/.tenuo/warrant
    holder_key_file: ${HOME}/.tenuo/holder.key
    strip_function_group: true
    approval_required: defer

function_groups:
  ops:
    _type: mcp_client
    server:
      transport: streamable-http
      url: http://127.0.0.1:7415/mcp
    middleware: [tenuo]
```

- `trusted_roots` is the issuer whose warrants the plugin accepts. `demo
  agent` passes the dev issuer's public key as `TENUO_TRUSTED_ROOT`.
- `warrant_file` and `holder_key_file` are the warrant and key that
  `provision` installed in the sandbox. An application binds a task's warrant
  in code; `nat run` has no such code, so the plugin reads the files.
- `strip_function_group` checks `ops__read_logs` as `read_logs`, the MCP
  tool name the warrant uses. Turn it on only for MCP function groups: it
  drops the first `group__` prefix and trusts the rest, so on other functions
  `other__read_logs` would be checked as `read_logs` and still run as itself.
- `approval_required: defer` hands a call that needs an approval on to the
  proxy, which records the request for `approve`. Without it, the plugin
  stops the call with `approval_required`, and there is nothing to approve.
  Defer only when the next stage enforces approvals itself, as the proxy and
  the OpenShell middleware do here. Against an MCP server that does not check
  warrants, a deferred restart would run.

The call outside the task now stops in the agent. The plugin's message names
the reason and a reference, not the arguments:

```bash
tenuo-openshell demo agent --workflow scripted-plugin "Check the identity logs in production"
```

```text
denied   read_logs(service=identity, environment=production): Authorization denied (constraint_violation, ref=7542c5a4c3ef4c8c)
answer   read_logs did not run: Authorization denied (constraint_violation, ref=7542c5a4c3ef4c8c).
```

A restart is handed on to the proxy and held for approval, as before:

```bash
tenuo-openshell demo agent --workflow scripted-plugin "Restart payments in staging"
```

```text
held     restart_service(service=payments, environment=staging, replicas=3): waiting for approval, request 8d554873e5d8
         approve it with: tenuo-openshell approve --dev --sandbox tenuo-nat --request 8d554873e5d8
answer   restart_service did not run: Approval required: request 8d554873e5d8 is waiting for an approver.
```

Of all these runs, the MCP server ran two calls: the read in staging and the
approved restart. If you went on from the quickstart without `dev down`, its
two calls come first.

```bash
docker logs tenuo-openshell-dev-mcp 2>&1 | grep RAN
```

```text
RAN read_logs {"environment": "staging", "service": "payments"}
RAN restart_service {"environment": "staging", "replicas": 3, "service": "payments"}
```

<!-- check: manual-begin -->

## 4. Use a real NVIDIA model

OpenShell gives a sandbox access to a model provider with a provider
profile: the endpoints a credential may go to, and the binaries that may
send it. The sandbox gets a placeholder in `NVIDIA_API_KEY`; OpenShell puts
the real key on a request only on its way to that endpoint, from those
binaries.

You need an NVIDIA API key from [build.nvidia.com](https://build.nvidia.com),
in `NVIDIA_API_KEY` in your shell.

Write the profile. It is NVIDIA's
[example profile](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/providers/nvidia.yaml)
with its own ID, and with `binaries` naming the image's Python by its real
path, which is how OpenShell identifies the process:

```bash
cat >nvidia-nat.yaml <<'EOF'
id: nvidia-nat
display_name: NVIDIA for the NAT agent
description: NVIDIA inference endpoints, for the NAT agent's Python
category: inference
inference_capable: true
credentials:
  - name: api_key
    description: NVIDIA API key
    env_vars: [NVIDIA_API_KEY]
    required: true
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: integrate.api.nvidia.com
    port: 443
    protocol: rest
    access: read-write
    enforcement: enforce
binaries: [/usr/local/bin/python3.12]
EOF
```

Import it, create a provider from your key, and attach it to the sandbox:

```bash
openshell profile lint -f nvidia-nat.yaml
openshell profile import -f nvidia-nat.yaml
openshell provider create --name nvidia --type nvidia-nat --credential NVIDIA_API_KEY
openshell sandbox provider attach tenuo-nat nvidia --wait
```

`--credential NVIDIA_API_KEY` reads the key from your shell. The gateway
stores it; the sandbox never sees it:

```bash
openshell sandbox exec --name tenuo-nat -- printenv NVIDIA_API_KEY
```

```text
openshell:resolve:env:v15912213771702750500_NVIDIA_API_KEY
```

The sandbox's policy now has a rule from the provider next to the Tenuo
ones: `openshell policy get tenuo-nat --full` shows `_provider_nvidia`, which
lets only `/usr/local/bin/python3.12` reach `integrate.api.nvidia.com:443`.
The MCP server is still reachable only through the Tenuo agent.

<!-- check: nim-outcomes -->

Run the agent on `/etc/tenuo-nat/nim.yml`. It is `scripted.yml` with NAT's
`nim` model, `nvidia/nemotron-3-super-120b-a12b`, which reads
`NVIDIA_API_KEY`:

```bash
tenuo-openshell demo agent --workflow nim "Payments is failing in staging. Investigate and fix it."
```

The model chooses its own calls, so the run differs from the scripted one,
but each call it makes gets the same treatment: a staging read runs,
anything outside the task is denied, and a restart is held for
`tenuo-openshell approve --dev --sandbox tenuo-nat`.

A real model may also try to get around a denial. In testing, Nemotron
answered a denied production read by retrying with other service names
(`identity-service`, `auth`, `auth-service`) and with `prod` for
`production`. The warrant denied every attempt, and none reached the MCP
server. `nim.yml` tells the agent that a denial is final so the run ends
cleanly; remove that instruction to watch the attempts.

To use another model, copy the workflow, change `model_name`, upload the copy
with `openshell sandbox upload`, and pass its path in the sandbox to
`--workflow`.

Remove the provider when you are done:

```bash
openshell sandbox provider detach tenuo-nat nvidia --wait
openshell provider delete nvidia
openshell profile delete nvidia-nat
```

<!-- check: manual-end -->

## 5. Clean up

```bash
openshell sandbox delete tenuo-nat
tenuo-openshell dev down
```

As in the quickstart, remove the `tenuo/authorization` block from your
gateway configuration and restart the gateway once you no longer run the
middleware.

<!-- check: unregister-gateway -->

## Next steps

| Goal | Guide |
| --- | --- |
| Put your own agent's image under Tenuo | [Running an agent under Tenuo](sandbox-agent.md) |
| Choose between the plugin, the proxy, or both | [Agent Toolkit integration](agent-toolkit.md) |
| Bind a task's warrant in your own NAT application | [Agent Toolkit plugin](../python/nemo-agent-toolkit-tenuo/README.md) |
| Run the middleware with TLS, the gateway's JWT, and a signed policy | [Going to production](production-quickstart.md) |
