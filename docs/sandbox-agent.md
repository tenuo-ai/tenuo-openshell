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

Build both from source until release artifacts are published:

```bash
cargo build --release --locked --workspace --bins
```

Copy `target/release/tenuo-openshell-agent` into the sandbox image, for
example at `/usr/local/bin/tenuo-openshell-agent`. The
[demo image](../examples/demo/Dockerfile.sandbox) shows a two-stage build.

## 1. Trust policy

Add the sandbox, the issuer that signs its warrants, and each MCP server it may
reach:

```bash
tenuo-openshell policy add \
  --policy /etc/tenuo/openshell-policy.json \
  --sandbox-id 5ba15c63-8170-4e78-a4aa-df0f94f49642 \
  --trusted-root issuer.pub \
  --mcp https://mcp.internal/mcp \
  --tools read_logs,restart_service \
  --single-use restart_service
```

The command creates the file if needed, merges into an existing sandbox entry,
increments `version`, and refuses to write a policy the middleware would reject.
Running middleware replicas pick up the new version on their next poll.

## 2. OpenShell configuration

```bash
tenuo-openshell register \
  --middleware-endpoint https://tenuo-middleware.example:50051 \
  --ca /etc/openshell/tenuo-middleware-ca.pem \
  --mcp-host mcp.internal
```

This prints the gateway registration block and the sandbox policy
`network_middlewares` block. In the sandbox policy's `network_policies` entry
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
  "code": -32001, "message": "Authorization denied",
  "data": {"tenuo": {"code": "tool-not-authorized",
                     "message": "Tool not authorized by warrant",
                     "source": "agent"}}}}
```

`source` is `agent` for a local denial and `openshell` for a middleware denial,
whose `code` is the middleware reason code, such as `tenuo_constraint_denied`.
Approval-gated calls use `-32002`.

With result evaluation on, OpenShell can also withhold a result above the
sandbox's `max_result_bytes`. The code is `tenuo_result_too_large` or
`tenuo_result_unmeasurable`, and the message says the call already ran. Do not
retry a non-idempotent tool on those codes. See
[Tool results](architecture.md#tool-results).

## Current limits

- The proxy does not attach approvals. A tool gated on approval is denied with
  `-32002` until approval delivery is added.
- The proxy's local check trusts the warrant chain's own root. It exists for
  clear errors; the middleware applies the operator's trust roots and is the
  enforcement point.
- One upstream per proxy instance.
