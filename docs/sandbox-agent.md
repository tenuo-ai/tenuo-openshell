# Running an agent under Tenuo in OpenShell

This guide takes an existing OpenShell sandbox from no Tenuo authority to an
agent whose MCP tool calls are signed in the sandbox and checked by the
middleware. The agent's MCP client does not change: it connects to a loopback
proxy instead of the MCP server.

```text
agent's MCP client ──► tenuo-openshell-agent proxy (127.0.0.1:7415)
                           │ signs tools/call with the sandbox holder key
                           ▼
                       OpenShell ──► Tenuo middleware ──► MCP server
```

Two binaries are involved:

| Binary | Runs | Purpose |
| --- | --- | --- |
| `tenuo-openshell` | Operator machine or orchestrator | Edit the trust policy, print OpenShell configuration, issue and provision warrants. |
| `tenuo-openshell-agent` | Inside the sandbox | Hold the key, hold the warrant, sign calls through a loopback MCP proxy. |

Add the agent to the sandbox image. The image
`ghcr.io/tenuo-ai/tenuo-openshell-agent` holds only the static binary, for
`linux/amd64` and `linux/arm64`, so it works on any base image:

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/tenuo-ai/tenuo-openshell-agent:v0.1.1 \
  /usr/local/bin/tenuo-openshell-agent /usr/local/bin/
```

The agent verifies the MCP server's TLS certificate against the system trust
store, so the image needs CA certificates. Pin the agent image by digest in
production.

Get `tenuo-openshell` for Linux or macOS arm64 from the
[latest release](https://github.com/tenuo-ai/tenuo-openshell/releases/latest).
See [Verifying a release binary](releasing.md#verifying-a-release-binary).
The release also has the agent as static Linux archives, for images built
without a registry.

To build both from source, run `cargo build --release --locked --bins`. The
[demo image](../examples/demo/Dockerfile.sandbox) shows a two-stage build.

## 1. Trust policy

Create the issuer key that signs warrants. `tenuo-openshell keygen` writes the
secret key (mode 0600, never overwriting a file) and the public key, and prints
the public key:

```bash
tenuo-openshell keygen --out issuer.key --public-out issuer.pub
```

The middleware needs a policy file before the first sandbox exists. Create one
that trusts no sandboxes; the middleware starts on it and denies every request:

```bash
tenuo-openshell policy init --policy /etc/tenuo/openshell-policy.json
```

Once the sandbox exists, add it, the issuer that signs its warrants, and each
MCP server it may reach. The sandbox ID comes from
`openshell sandbox get <name> -o json`:

```bash
tenuo-openshell policy add \
  --policy /etc/tenuo/openshell-policy.json \
  --sandbox-id 5ba15c63-8170-4e78-a4aa-df0f94f49642 \
  --trusted-root issuer.pub \
  --mcp https://mcp.internal/mcp \
  --tools read_logs,restart_service

tenuo-openshell policy sign \
  --policy /etc/tenuo/openshell-policy.json \
  --key policy-signing.key
```

The command creates the file if needed, merges into an existing sandbox entry,
increments `version`, and refuses to write a policy the middleware would reject.
Running middleware replicas pick up the new version on their next poll.

## 2. OpenShell configuration

```bash
tenuo-openshell register \
  --middleware-endpoint https://tenuo-middleware.example:50051 \
  --ca /etc/openshell/tenuo-middleware-ca.pem \
  --mcp-host mcp.internal \
  --openshell-policy sandbox-policy.yaml
```

This prints the gateway registration block and the sandbox policy
`network_middlewares` block. `--only gateway` or `--only sandbox` prints just
one, to append to `gateway.toml` or a sandbox policy. For a local middleware
started with `--insecure-dev`, pass `--insecure-dev` and an `http://`
endpoint, and leave out `--ca`. `--openshell-policy` refuses to print that block
when a protected host allows `tls: skip`, raw TCP, or a binary WebSocket. In
the sandbox policy's `network_policies` entry
for the MCP server, list the agent as the binary allowed to reach it:

```yaml
    binaries:
      - path: /usr/local/bin/tenuo-openshell-agent
```

With only the proxy listed, an agent that bypasses it cannot reach the MCP
server at all. If other binaries are listed, their calls still reach the
middleware and deny `tenuo_missing_warrant`.

## 3. Holder key and warrant

The holder key is generated inside the sandbox and never leaves it. The
warrant is not a secret: without the key it cannot produce a proof of
possession. See [holder key custody](architecture.md#holder-key-custody).

### File delivery (recommended)

One command generates the key in the sandbox, issues a warrant to its public
key, and installs it:

```bash
tenuo-openshell provision \
  --sandbox my-sandbox \
  --issuer-key issuer.key \
  --capabilities @capabilities.json \
  --ttl 3600
```

To delegate from an orchestrator's own warrant instead of minting, pass
`--parent-key` and `--parent-warrant`. The child can only be narrower than the
parent.

The warrant lands in `~/.tenuo/warrant`. The proxy re-reads it on every call,
so provisioning again rotates or narrows the authority without restarting the
agent.

### Environment delivery

For a runtime that receives configuration only through its environment,
generate the key, issue the warrant, and pass it when starting the proxy:

```bash
holder="$(openshell sandbox exec --name my-sandbox --no-tty -- tenuo-openshell-agent keygen)"
warrant="$(tenuo-openshell warrant issue --holder "$holder" \
  --issuer-key issuer.key --capabilities @capabilities.json --ttl 3600)"
openshell sandbox exec --name my-sandbox --env "TENUO_WARRANT=$warrant" -- \
  tenuo-openshell-agent proxy --upstream https://mcp.internal/mcp
```

`TENUO_WARRANT` takes precedence over the file and is fixed for the life of the
process.

### Capabilities

`--capabilities` takes JSON or `@file`. Each tool maps argument names to
constraints. A bare value is an exact match.

```json
{
  "read_logs": {
    "service": "payments",
    "environment": {"one_of": ["staging", "dev"]},
    "lines": {"range": {"max": 500}},
    "path": {"pattern": "/var/log/*"},
    "query": {"wildcard": true}
  }
}
```

| Constraint | Meaning |
| --- | --- |
| value, or `{"exact": value}` | Equal to the value. |
| `{"one_of": [values]}` | One of the listed values. |
| `{"pattern": "glob"}` | Glob match on a string. |
| `{"range": {"min": n, "max": n}}` | Number within the bounds; either may be omitted. |
| `{"wildcard": true}` | Any value. |

Once a tool lists any constraint, arguments that are not listed are rejected;
use `{"wildcard": true}` to admit one without constraining it. A tool with
`{}` accepts any arguments, so prefer listing each argument.

## 4. Run the proxy and point the agent at it

```bash
tenuo-openshell-agent proxy --upstream https://mcp.internal/mcp
```

Configure the agent's MCP client with `http://127.0.0.1:7415/mcp`. The proxy
listens on loopback only. Run one proxy per MCP server, each with its own
`--listen` port.

Check what the sandbox holds at any time:

```bash
tenuo-openshell-agent status
```

## Denials the agent sees

A call outside the warrant never leaves the sandbox. A call the middleware
denies comes back from OpenShell as HTTP 403, which the proxy converts. In both
cases the agent's MCP client receives a JSON-RPC error rather than a transport
failure:

```json
{"jsonrpc": "2.0", "id": 3, "error": {
  "code": -32001, "message": "Authorization denied: Tool not authorized by warrant",
  "data": {"tenuo": {"code": "tool-not-authorized",
                     "message": "Tool not authorized by warrant",
                     "source": "agent"}}}}
```

`message` carries the reason because many MCP clients show only that field.
`source` is `agent` for a local denial and `openshell` for a denial that came
back from OpenShell as HTTP 403. Then `code` says who denied it:

- A code starting `tenuo_`, such as `tenuo_constraint_denied`, is the Tenuo
  middleware's reason.
- Any other code is OpenShell's own: its L7 policy (`policy_denied`), an MCP
  check such as `mcp_protocol_version_not_allowed`, an unreachable middleware
  (`middleware_failed`), or another middleware's reason code. `message`
  includes OpenShell's `detail`, so check the sandbox policy, not the warrant.

`data.tenuo.openshell` carries OpenShell's `error`, `reason_code`, `detail`,
`layer`, `protocol`, `policy`, `middleware`, and `rule` fields when present,
each at most 256 bytes:

```json
{"code": -32001,
 "message": "Authorization denied: OpenShell denied this call (policy_denied): …",
 "data": {"tenuo": {"code": "policy_denied", "source": "openshell",
                    "message": "OpenShell denied this call (policy_denied): …",
                    "openshell": {"error": "policy_denied", "policy": "demo-mcp",
                                  "rule": "POST /mcp", "layer": "l7", "detail": "…"}}}}
```

Approval-gated calls use `-32002`; see below.

## Approvals

A warrant can require signed approvals for a tool. When the agent calls it
without one, the proxy records the pending request in the sandbox and returns
`-32002` with the request hash:

```json
{"code": -32002,
 "message": "Approval required: request 88c6…55ba is waiting for an approver (…); retry the same call once it is approved",
 "data": {"tenuo": {"code": "approval-required", "request_hash": "88c6…55ba", "source": "agent"}}}
```

An approver reviews and signs it from outside the sandbox. Create the
approver key once with `tenuo-openshell keygen --out approver.key
--public-out approver.pub`; `approver.pub` is the key the warrant must name as
a required approver:

```bash
tenuo-openshell approve --sandbox my-sandbox --request 88c676b2 \
  --approver-key approver.key --trusted-root issuer.pub
```

The sandbox wrote the pending request, so `approve` trusts none of it until it
checks it. The request records the approval request Tenuo produced and the
warrant chain it was checked against. `approve` verifies that chain to a
`--trusted-root` (usually the sandbox's `trusted_roots`), then checks the
request against that warrant: hash, holder, approval message, approvers,
threshold, and expiry. Only then does it show the tool, arguments, and
message, all taken from the verified request. It refuses a key the warrant
does not list as an approver and asks for confirmation unless `--yes` is
passed. Tenuo core signs the approval with a random nonce, valid for `--ttl`
seconds (300 by default) and never past the warrant's expiry, and it is
installed in the sandbox.

The agent retries the same call. The proxy attaches the approval, removes it,
and the middleware accepts its nonce once. A second identical call needs a new
approval. With `min_approvals` above one, each approver runs `approve`; the
proxy attaches every approval installed for that request.

For approvals signed elsewhere, `tenuo-openshell approve --pending <file>`
reads the output of `tenuo-openshell-agent pending --json` and prints the
approval, and `tenuo-openshell-agent install-approval -` installs it.

The [NeMo Agent Toolkit example](../examples/nemo-agent-toolkit/README.md)
runs this flow with a ReAct agent.

With result evaluation on, OpenShell can also withhold a result above the
sandbox's `max_result_bytes`. The code is `tenuo_result_too_large` or
`tenuo_result_unmeasurable`, and the message says the call already ran. Do not
retry a non-idempotent tool on those codes. See
[Tool results](architecture.md#tool-results).

## Sub-agents

An agent can pass part of its authority to a sub-agent that has its own holder
key. The child warrant is attenuated from the agent's warrant, signed by the
agent's holder key, and appended to the chain, so the middleware verifies both
links. Neither key leaves its process or sandbox; only public keys and warrants
move.

### In the same sandbox

The sub-agent uses its own key, warrant, and approvals directory, selected with
`TENUO_HOLDER_KEY_FILE`, `TENUO_WARRANT_FILE`, and `TENUO_APPROVALS_DIR`:

```bash
export TENUO_HOLDER_KEY_FILE=~/.tenuo-subagent/holder.key \
  TENUO_WARRANT_FILE=~/.tenuo-subagent/warrant \
  TENUO_APPROVALS_DIR=~/.tenuo-subagent/approvals
child="$(tenuo-openshell-agent keygen)"
chain="$(env -u TENUO_HOLDER_KEY_FILE -u TENUO_WARRANT_FILE -u TENUO_APPROVALS_DIR \
  tenuo-openshell-agent delegate --child-pub "$child" --tools read_logs --ttl 300 --terminal)"
tenuo-openshell-agent install-warrant "$chain"
```

The sub-agent runs its own `proxy` on another `--listen` port with the same
environment.

### In another sandbox

From the operator side, `delegate` runs the same three steps across two
sandboxes:

```bash
tenuo-openshell delegate \
  --from-sandbox planner \
  --to-sandbox worker \
  --tools read_logs \
  --ttl 600 \
  --terminal
```

It generates the key in `worker`, has the agent in `planner` sign the child
warrant, checks that the child names `worker`'s key, and installs it there. The
trust policy must list `worker` with the same trusted root as `planner`; the
chain still ends at that root. OpenShell has no sandbox-to-sandbox channel
([NVIDIA/OpenShell#1049](https://github.com/NVIDIA/OpenShell/issues/1049)),
so the operator CLI relays the public material.

### What a child gets

- `--tools` names the tools to pass on. Each keeps the parent's argument
  constraints. Naming a tool the parent does not hold is refused.
- `--ttl` sets the child's lifetime; it cannot outlive the parent.
- `--terminal` sets the child's maximum chain depth to its own depth, so it
  cannot delegate further. Without it, the child may delegate within the
  parent's limit.
- Revoking any warrant in the chain denies every call that carries it. The
  middleware checks each link against the sandbox's signed revocation list, so
  revoking the agent's warrant also stops a sub-agent that is already running.

Narrowing argument constraints further at delegation time waits on a shared
constraint parser in Tenuo core
([tenuo-ai/tenuo#753](https://github.com/tenuo-ai/tenuo/issues/753)). Until
then, issue a narrower warrant from the orchestrator with `provision`.

## Current limits

- The proxy's local check trusts the warrant chain's own root. It exists for
  clear errors; the middleware applies the operator's trust roots and is the
  enforcement point.
- One upstream per proxy instance.
