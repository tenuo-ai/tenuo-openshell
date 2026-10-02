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
| `{"subpath": "/root"}` | Absolute path inside the root, after lexical `.`/`..` normalization. Symlinks are not resolved. |
| `{"url_safe": true}` | URL that is not private, loopback, metadata, or reserved. |
| `{"url_safe": {"allow_domains": [domains]}}` | The same, limited to the domains; `*.example.com` admits subdomains. |
| `{"wildcard": true}` | Any value. |

Once a tool lists any constraint, the tool is closed: arguments that are not
listed are rejected, and every listed argument must be present, including a
`{"wildcard": true}` one. A call that leaves out an optional argument the
tool lists is therefore denied. For tools whose optional arguments cannot
widen what the call reaches (pagination, a git ref, output limits), add
`"_allow_unknown": true` to admit unlisted arguments while the listed ones
stay enforced. An attenuated child does not inherit `_allow_unknown`. A tool
with `{}` accepts any arguments, so prefer listing each argument. Tenuo core
documents every constraint type in
[`docs/constraints.md`](https://github.com/tenuo-ai/tenuo/blob/main/docs/constraints.md);
this CLI accepts the ones in the table.

### Templates

Templates are ready-made capabilities for MCP servers that OpenShell users
commonly admit. List them with their parameters:

```bash
tenuo-openshell warrant templates
```

Issue or provision from a template in place of `--capabilities`:

```bash
tenuo-openshell provision --sandbox <name> --issuer-key issuer.key \
  --template github-readonly --param owner=tenuo-ai --param repos=tenuo,tenuo-openshell
```

| Template | Server | Scope |
| --- | --- | --- |
| `github-readonly` | github/github-mcp-server | Read tools on listed repositories of one owner. No search tools: their scope is inside a free-text query. |
| `github-contributor` | github/github-mcp-server | The read tools plus `create_branch`, `push_files`, `create_pull_request`, and `add_issue_comment`, writing only to branches under `branch_prefix`. No merge or delete. |
| `filesystem-readonly` | modelcontextprotocol filesystem | Read and list tools under one root. |
| `fetch-allowlist` | modelcontextprotocol fetch | `fetch` for listed domains, with private and metadata addresses blocked. |
| `kubernetes-readonly` | containers/kubernetes-mcp-server | Pod, event, and workload reads in listed namespaces; no Secret or ConfigMap reads; no multi-cluster `context`. |
| `slack-channels` | Slack reference server | History, replies, posts, and reactions in listed channel IDs. |

#### Open tools are the operator's choice

Most template tools set `_allow_unknown`, because MCP servers take optional
arguments that agents send inconsistently, and a listed argument is required.
On those tools the listed arguments (owner, repo, path, URL, namespace,
channel) are enforced, and **every other argument is never checked**,
including arguments a later server version adds. `warrant templates` names the
open tools of each template.

Add `--closed` to drop every `_allow_unknown`. Each tool then admits only its
listed arguments and requires all of them, so a call that adds `ref` or
`perPage`, or leaves out a listed argument, is denied. Choose closed when you
pin the MCP server version and control the client's arguments; choose open
when agents call the tools freely. Pin the server version either way, and
review the templates when you upgrade it. Core may later replace this choice
with declared defaults for optional arguments
([tenuo-ai/tenuo#770](https://github.com/tenuo-ai/tenuo/issues/770)).

Rendering is strict: a missing, unknown, repeated, or unused `--param` is an
error. `--template @file.json` loads a template in the same format as those
in [`templates/`](../templates). Tool and argument names were taken from each
server's source; check them against the server version you run, since a
renamed tool is denied rather than silently admitted.

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
`source` is `agent` for a local denial and `openshell` for a middleware denial,
whose `code` is the middleware reason code, such as `tenuo_constraint_denied`.
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

An approver reviews and signs it from outside the sandbox:

```bash
tenuo-openshell approve --sandbox my-sandbox --request 88c676b2 --approver-key approver.key
```

`approve` reads the pending request from the sandbox, shows the tool,
arguments, and warrant, and recomputes the request hash from them before
signing, so the approval covers exactly what was shown. It refuses a key the
warrant does not list as an approver and asks for confirmation unless `--yes`
is passed. The approval is installed in the sandbox, valid for `--ttl` seconds
(300 by default).

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

## Current limits

- The proxy's local check trusts the warrant chain's own root. It exists for
  clear errors; the middleware applies the operator's trust roots and is the
  enforcement point.
- One upstream per proxy instance.
