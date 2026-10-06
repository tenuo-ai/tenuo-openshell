# Quickstart

Your OpenShell sandbox policy decides which binaries in a sandbox may reach an
MCP server, and which tools they may call there. If it allows
`restart_service`, the agent can restart any service, in any environment, as
often as it likes. Tenuo decides which service, for which task, and asks a
human first. Each sandbox holds a warrant for its current task, and the Tenuo
middleware in OpenShell checks every `tools/call` against it.

This guide adds Tenuo to the OpenShell gateway you already run, in development
mode, and shows the difference in about 5 minutes. It uses fixed demo calls,
so it needs no model or API key.

| Call from the sandbox | Without Tenuo | With Tenuo |
| --- | --- | --- |
| `read_logs` for `payments` in `staging` | Runs | Runs |
| `read_logs` for `identity` in `production` | Runs | Denied: outside the task |
| `restart_service` for `payments` in `staging` | Runs | Held until you approve it, then runs once |
| Any call that skips the Tenuo agent | Runs | Denied by the middleware |

## Before you start

- OpenShell installed with its install script, and its local gateway running:
  `openshell sandbox create` works. The gateway uses the Docker driver.
- On macOS, Docker Desktop with host networking on (Settings → Resources →
  Network). OpenShell needs it for any sandbox, with or without Tenuo.
- macOS on Apple silicon, or Linux on x86_64 or arm64.
- About 300 MB of image downloads.

## 1. Install the Tenuo CLI

```bash
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64) target=aarch64-apple-darwin ;;
  Linux/x86_64) target=x86_64-unknown-linux-musl ;;
  Linux/aarch64) target=aarch64-unknown-linux-musl ;;
esac
mkdir -p ~/.local/bin
curl -fsSL "https://github.com/tenuo-ai/tenuo-openshell/releases/download/v0.1.6/tenuo-openshell-v0.1.6-$target.tar.gz" \
  | tar -xz -C ~/.local/bin tenuo-openshell
tenuo-openshell --version
```

`~/.local/bin` must be on your `PATH`. To verify the binary's signature first,
see [Verifying a release binary](releasing.md#verifying-a-release-binary).

## 2. Start Tenuo next to your gateway

```bash
tenuo-openshell dev up
```

`dev up` starts two containers, both published on 127.0.0.1 only:

| Container | What it is |
| --- | --- |
| `tenuo-openshell-dev` | The Tenuo middleware, on port 18651 |
| `tenuo-openshell-dev-mcp` | A demo MCP server with `read_logs` and `restart_service`, on port 18680. It has no Tenuo code and runs every call it receives. |

It keeps an issuer key, an approver key, and the middleware's trust policy in
`~/.local/state/tenuo-openshell/dev`. The policy starts out trusting no
sandboxes. Development mode has no TLS, no caller authentication, an unsigned
policy, and single-use state in memory. Running `dev up` again changes
nothing.

It then prints a registration block for your gateway, and names the file to
add it to: `~/.config/openshell/gateway.toml`, or when that does not exist,
`/opt/homebrew/var/openshell/gateway.toml` with Homebrew and
`/var/snap/openshell/common/gateway.toml` with the snap:

```toml
[[openshell.supervisor.middleware]]
name = "tenuo/authorization"
grpc_endpoint = "http://127.0.0.1:18651"
allow_insecure_transport = true
audience = "urn:openshell:extension:middleware:tenuo/authorization"
max_payload_bytes = 262144
timeout = "2s"
```

Add the block to the end of that file, then restart the gateway so it loads
the middleware. The deb and rpm packages install no `gateway.toml`; `dev up`
then says to create it, with an `[openshell]` table holding `version = 2`
before the block. The snap's file belongs to root, so edit it with `sudo`.
`dev up` never edits your OpenShell installation.

| Platform | Restart the gateway |
| --- | --- |
| macOS (Homebrew) | `brew services restart openshell` |
| Linux (deb or rpm) | `systemctl --user restart openshell-gateway` |
| Linux (snap) | `sudo snap restart openshell.gateway` |

<!-- check: register-gateway -->

The gateway log then warns that extension authentication is disabled for this
registration. That is development mode: the middleware accepts calls without
OpenShell's credential. [Going to production](production-quickstart.md)
registers it over TLS with the gateway's JWT.

The gateway contacts the middleware when it starts, so start Tenuo first.

## 3. Create a sandbox and give it a task

`dev up` also wrote an OpenShell sandbox policy for the demo,
`~/.local/state/tenuo-openshell/dev/demo-policy.yaml`. It is an ordinary
policy: the agent may call `read_logs` and `restart_service` on the demo MCP
server, with any arguments. The only Tenuo addition is the
`network_middlewares` entry that attaches the middleware to that host:

```yaml
network_middlewares:
  tenuo:
    middleware: tenuo/authorization
    on_error: fail_closed
    endpoints:
      include:
        - host.openshell.internal
```

Create the sandbox. The demo image holds the Tenuo agent, and the sandbox runs
the agent's MCP proxy. An agent's MCP client points at the proxy, which signs
each `tools/call` with a key that never leaves the sandbox:

```bash
openshell sandbox create --name tenuo-demo \
  --from ghcr.io/tenuo-ai/tenuo-openshell-demo:v0.1.6 \
  --policy ~/.local/state/tenuo-openshell/dev/demo-policy.yaml \
  --no-tty --detach -- tenuo-openshell-agent proxy --upstream http://host.openshell.internal:18680/mcp
```

With the OpenShell snap, pass
`--policy ~/snap/openshell/common/tenuo-openshell/demo-policy.yaml` instead.
The snap's `openshell` cannot read hidden directories such as `~/.local`, so
`dev up` also writes the policy there, and prints the command with it.

Give it a task. `provision --dev` adds the sandbox to the dev policy, has the
agent create its holder key, and installs a warrant signed by the dev issuer:

```bash
tenuo-openshell provision --dev --sandbox tenuo-demo --preset demo
```

```text
trusted sandbox tenuo-demo (f93f8b2b-4981-4327-ac4c-075a72e46b9d) in the dev policy, version 2
sandbox  tenuo-demo
holder   7469287b01a9cec652bfae7366c24670427eeafbca23933ffd3cee31e2d6d46f
warrant  tnu_wrt_01a10adf5a937576b63088480b84ceb3
tools    read_logs, restart_service
approval restart_service needs 1 of 1 approver(s)
```

The `demo` preset grants:

- `read_logs` for `payments` in `staging` or `dev`; and
- `restart_service` for `payments` in `staging` with at most 5 replicas, once
  the dev approver signs each call.

Without the preset, the same warrant is:

```text
tenuo-openshell provision --dev --sandbox tenuo-demo \
  --capabilities '{"read_logs": {"service": "payments", "environment": {"one_of": ["staging", "dev"]}},
                   "restart_service": {"service": "payments", "environment": "staging", "replicas": {"range": {"max": 5}}}}' \
  --require-approval restart_service
```

## 4. See the difference

`demo call` sends one `tools/call` from inside the sandbox through the agent's
proxy, and prints what happened to it.

A call inside the task runs:

```bash
tenuo-openshell demo call read_logs service=payments environment=staging
```

```text
allowed  read_logs(service=payments, environment=staging): payments/staging: 3 lines, last: GET /health 200
```

A call outside it is denied. The agent checks the warrant first and does not
sign the call, so it never leaves the sandbox:

```bash
tenuo-openshell demo call read_logs service=identity environment=production
```

```text
denied   read_logs(service=identity, environment=production) by the Tenuo agent, before it left the sandbox: constraint-violation
```

A restart waits for a human:

```bash
tenuo-openshell demo call restart_service service=payments environment=staging replicas=3
```

```text
held     restart_service(service=payments, environment=staging, replicas=3): waiting for approval, request c6f07d0b95a7
         approve it with: tenuo-openshell approve --dev --sandbox tenuo-demo --request c6f07d0b95a7
```

Approve it. `approve` checks the pending request against the warrant, shows
the call, and asks before it signs; `--yes` skips the question in a script.
With one request pending, `--request` can be left out:

```bash
tenuo-openshell approve --dev --sandbox tenuo-demo
```

```text
tool      restart_service
arguments {"environment":"staging","replicas":3,"service":"payments"}
message   Approval required for tool 'restart_service'
warrant   tnu_wrt_01a10adf5a937576b63088480b84ceb3
request   c6f07d0b95a7d9b8fb88bb75232ef0d1735eb45883449d79db7310d377c60e46
expires   in 300 seconds
approve this call? [y/N] y
approved c6f07d0b95a7d9b8fb88bb75232ef0d1735eb45883449d79db7310d377c60e46 in sandbox tenuo-demo
```

Retry the same call. It runs, and the approval is spent: the next identical
call waits for a new one.

```bash
tenuo-openshell demo call restart_service service=payments environment=staging replicas=3
```

```text
allowed  restart_service(service=payments, environment=staging, replicas=3): restarted payments in staging with 3 replicas
```

The agent's check gives clear errors, but the middleware is what enforces. A
call that skips the agent carries no warrant, and the middleware denies it
before it reaches the MCP server. `--unsigned` sends one with curl from the
same sandbox, as a compromised agent could:

```bash
tenuo-openshell demo call --unsigned read_logs service=payments environment=staging
```

```text
denied   read_logs(service=payments, environment=staging) by the Tenuo middleware in OpenShell: tenuo_missing_warrant
```

The MCP server ran exactly the two allowed calls:

```bash
docker logs tenuo-openshell-dev-mcp 2>&1 | grep RAN
```

```text
RAN read_logs {"environment": "staging", "service": "payments"}
RAN restart_service {"environment": "staging", "replicas": 3, "service": "payments"}
```

`tenuo-openshell dev status` shows the policy version and the gateway
registration. The middleware logs one line per decision:
`docker logs tenuo-openshell-dev 2>&1 | grep tenuo_decision`. Its reason codes
are defined in [`src/reason.rs`](../src/reason.rs).

## 5. Clean up

```bash
openshell sandbox delete tenuo-demo
tenuo-openshell dev down
```

`dev down` keeps the keys and policy for the next `dev up`. Remove the
`tenuo/authorization` block from your gateway configuration and restart the
gateway, or the gateway will not start without the middleware.

<!-- check: unregister-gateway -->

## Next steps

| Goal | Guide |
| --- | --- |
| Run a NeMo Agent Toolkit agent in the sandbox, with a scripted model or NIM | [A NAT agent in an OpenShell sandbox](nat-agent.md) |
| Put your own agent under Tenuo | [Running an agent under Tenuo](sandbox-agent.md) |
| Run the middleware with TLS, the gateway's JWT, and a signed policy | [Going to production](production-quickstart.md) |
| Deploy it with Redis and Helm | [Deployment](deployment.md) and the [Helm chart](../deploy/helm/tenuo-openshell/README.md) |
| Issue warrants from your own service or Tenuo Cloud | [Production issuance](production-issuance.md) |
| See the base sandbox policy and task authority compose across every scenario | [Demo](../examples/demo/README.md) (`make demo`, builds from source) |

To point the dev middleware at your own MCP server, add a destination to the
dev policy with `tenuo-openshell policy add --policy
~/.local/state/tenuo-openshell/dev/policy/policy.json`, and attach the
middleware to that host in your sandbox policy. `tenuo-openshell register
--only sandbox --mcp-host <host>` prints the attachment.
