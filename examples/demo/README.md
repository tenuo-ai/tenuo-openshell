# Authenticated OpenShell demo

The demo runs a real, pinned OpenShell gateway with the Tenuo middleware
registered over authenticated HTTPS. Each scenario goes through sandboxes
twice: once with Tenuo and once with OpenShell alone. The demo checks that
every call Tenuo denies is absent from the MCP server's effect log, and it
verifies every signed receipt offline.

```bash
make demo
```

The result is `results/outcome-matrix.md`, with one row per scenario. Each row
gives both outcomes, the enforcement point, the reason code, and the decision
time.

## Setup

Every sandbox policy admits both `read_logs` and `restart_service`. The
warrants are what differ.

| Holder | Warrant |
| --- | --- |
| Task A | `read_logs` and `restart_service` for `payments` in `staging`. `replicas` is at most 5, and restarts need one signed approval. |
| Task B | `read_logs` for `payments` in `staging` only. |
| Narrowed child, in the second sandbox | Task A's warrant attenuated to `read_logs`, with a 120-second lifetime. |
| Sandbox agent, in the first sandbox | Task A's authority, delegated by `tenuo-openshell provision` to a key generated in the sandbox. The key never leaves it. |

Most scenarios use requests signed ahead of time on the host, so each denial
is reproducible. Each of those holder keys is created by its own process and
stored in its own file. Sandboxes receive only the signed bodies. The issuer
secret is never written.

The [sandbox agent scenarios](#the-agent-in-the-sandbox) use the production
path instead: an unmodified MCP Python SDK client talks to
`tenuo-openshell-agent proxy` on loopback, which signs each call.

## Scenarios

With OpenShell alone, every call below that reaches OpenShell runs.

### Task authority

| # | Call | With Tenuo |
| --- | --- | --- |
| 1 | Task A reads staging payments logs | Allowed |
| 2 | Task B reads staging payments logs | Allowed |
| 3 | Task A restarts staging payments with 3 replicas and an approval | Allowed. Sending the same approval again is denied `tenuo_approval_replayed`. |
| 4 | The same restart without the approval | Denied `tenuo_approval_required` |
| 5 | The 3-replica approval presented with 5 replicas | Denied `tenuo_invalid_authority` |
| 6 | Task B restarts with its own warrant | Denied `tenuo_tool_denied` |
| 7 | Task B signs with Task A's warrant | Denied `tenuo_invalid_authority`; the holder proof does not verify |
| 8 | Task A reads identity logs in production | Denied `tenuo_constraint_denied` |
| 9 | Task A restarts with 8 replicas | Denied `tenuo_constraint_denied` |
| 10 | Task A restarts `auth` in staging | Denied `tenuo_constraint_denied`. OpenShell admits `restart_service`, but the warrant names `payments`. |
| 11 | A restart with no warrant | Denied `tenuo_missing_warrant` |

### Delegation

| # | Call | With Tenuo |
| --- | --- | --- |
| 12 | The narrowed child reads staging payments logs | Allowed |
| 13 | The narrowed child restarts | Denied `tenuo_tool_denied` |
| 14 | The narrowed child mints a warrant that adds `restart_service` back | Refused by attenuation |

### The agent in the sandbox

| # | Call | With Tenuo |
| --- | --- | --- |
| 15 | The MCP SDK client lists tools and reads staging payments logs through the signing proxy | Allowed. Checked by the middleware and again by the MCP server. |
| 16 | The client asks for a restart | Held in the sandbox with `approval-required`. After an approver signs it with `tenuo-openshell approve`, the retry runs once. |
| 17 | A policy update caps the sandbox's results at 64 bytes, and the agent reads again | The read runs, and OpenShell withholds the larger result with `tenuo_result_too_large`. |
| 18 | The agent delegates `read_logs`, terminally, to a sub-agent with its own key in the same sandbox | The sub-agent's read is allowed on a three-link chain. Its restart is refused in the sandbox with `tool-not-authorized`, and its attempt to delegate further is refused by attenuation. |
| 19 | `tenuo-openshell delegate` passes `read_logs` from the first sandbox's agent to a key generated in the second sandbox | The second sandbox's read is allowed. Only public keys and warrants cross. |
| 20 | A signed revocation list that names only Task A's warrant is installed | The second sandbox's next read carries Task A's warrant as an ancestor, and is denied `tenuo_revoked`. |

Scenario 17 blocks after the call has run. It limits what reaches the agent,
not what the tool does.

### Other enforcement points

| # | Call | Result |
| --- | --- | --- |
| 21 | The Agent Toolkit middleware, on the host, checks Task B's restart | Denied before the function runs |
| 22 | A Tenuo A2A worker receives a parent and child warrant stack over JSON-RPC HTTP, with the child's proof of possession | `read_logs` runs. A read-only child's `restart_service` is denied before the skill runs. |
| 23 | Task B's restart, a restart with no warrant, and the narrowed restart are sent straight to the MCP server, around OpenShell | All three are denied with JSON-RPC `-32001`. A direct read with Task A's warrant runs. |

The demo policy sets `forward_proof` to `preserve`. The MCP server verifies
the warrant with Tenuo's `MCPVerifier` before it runs any tool. That check
does not depend on OpenShell being in front. The A2A step is in
[`examples/interoperability`](../interoperability/README.md) and writes
`results/evidence/a2a-handoff.json`.

## Evidence

Each enforcement point signs receipts with its own key: the OpenShell
middleware, the MCP server, and the Agent Toolkit plugin. The first two
record the JSON-RPC id as `request_id`. [`audit_receipts.py`](audit_receipts.py)
checks all three sets offline against the issuer and receipt-signer public
keys. It confirms that:

- every expected allow and denial was recorded at the expected point;
- delegated calls record both the parent warrant and the child; and
- every result receipt names an allow receipt for the same id and tool.

The middleware runs with `--evaluate-results`, so each allowed call through
OpenShell also gets a result receipt with the status, byte count, and SHA-256
of the result. Scenario 17's receipt records the block instead of a digest.

A missing warrant has no chain to commit to, so that denial has no receipt. A
receipt records a decision, and the effect logs record which calls ran.

Both receipt logs are also exported as JSON lines, in the format described in
[Receipts](../../docs/receipts.md):

- `results/evidence/openshell-receipts.json`
- `results/evidence/openshell-results.json`

The scheduled and manually dispatched GitHub workflow uploads a 30-day Actions
artifact. It contains:

- the outcome matrix and observations;
- the effect logs;
- the public receipt material;
- the audit report; and
- the version manifest.

Private keys are never copied into it.

## Requirements and pinning

The demo needs:

- Docker Desktop or Engine 28.0+, or Podman 5.x+;
- Rust 1.91+ and Python 3.11+; and
- `git`, `curl`, `jq`, `nc`, `openssl`, and `make`.

The launcher checks the container runtime version before it builds anything.
The first run takes 10–20 minutes.

The launcher pins NVIDIA OpenShell v0.1.2 at commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. It:

- builds the gateway and CLI from that commit;
- pulls NVIDIA's multi-architecture supervisor and sandbox-runtime images by
  immutable digest;
- builds a non-root workload from NVIDIA's Ubuntu base, also pinned by digest;
- generates temporary TLS and gateway JWT material;
- installs Python `tenuo` 0.3.2 into a temporary environment for the MCP
  server; and
- removes the sandboxes and processes afterwards.

On Docker Desktop, the supervisor's host network is the Linux VM. The launcher
therefore publishes the gateway on the machine's address and sets the
driver's `grpc_endpoint` to it.

| Variable | Effect |
| --- | --- |
| `OPENSHELL_SOURCE` | Use an existing pinned OpenShell checkout instead of downloading one. |
| `TENUO_DEMO_DRIVER=podman` | Use Podman instead of Docker. |
| `TENUO_DEMO_PYTHON` | Use an interpreter that already has `tenuo` installed. |
| `TENUO_DEMO_SUPERVISOR_IMAGE`, `TENUO_DEMO_SANDBOX_RUNTIME_IMAGE`, `TENUO_DEMO_WORKLOAD_IMAGE` | Use private mirrors; keep them pinned by digest. A workload override must already contain curl and a `sandbox` account with UID and GID 1000. |

`results/` is local output and is not part of the source tree.
