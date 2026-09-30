# Authenticated OpenShell demo

The demo sends two tasks through one OpenShell sandbox and a narrowed child
warrant through a second sandbox. Both use the Tenuo
`HTTP_REQUEST/PRE_CREDENTIALS` middleware. Each sandbox policy admits both
`read_logs` and `restart_service`. Task A's warrant grants those tools for
`payments` in `staging`, and limits `restart_service` to `replicas` of at most
5. Task B's warrant grants only the staging payments read. `restart_service`
on Task A's warrant requires one approval. The approver is a local fixture
key, created in its own process and not copied into a sandbox. Task A then
attenuates that warrant to a read-only child, with a 120 second lifetime, for
a third holder.

The negative scenarios use requests signed ahead of time on the host, so each
denial is reproducible. Each of those holder keys is created by its own
process and stored in its own file, and the sandbox receives only the signed
body. The issuer secret is not written. The attenuation process reads Task A's
key and the child public key. It does not read the child secret.

Step 16 uses the production path instead. `tenuo-openshell provision`
generates the holder key inside the sandbox and installs a warrant that Task A
delegates to it. An unmodified MCP Python SDK client, with no Tenuo code, talks
to `tenuo-openshell-agent proxy` on loopback, which signs each call. That
private key never leaves the sandbox. See
[Running an agent under Tenuo](../../docs/sandbox-agent.md).

1. Task A reads staging payments logs. Allowed.
2. Task B reads staging payments logs with its own warrant. Allowed.
3. Task A restarts staging payments with `replicas` 3. The request carries
   an approval signed by the local fixture approver for those arguments.
   Allowed. The same approval is sent again and denied
   `tenuo_approval_replayed` by the middleware's atomic nonce store.
4. Task A requests that restart without the approval. Denied
   `tenuo_approval_required`.
5. Task A presents the `replicas` 3 approval with `replicas` 5. Denied
   `tenuo_invalid_authority`.
6. Task B requests that restart with its own warrant. Denied
   `tenuo_tool_denied`.
7. Task B signs Task A's warrant for that restart. The holder proof does
   not verify, so it is denied `tenuo_invalid_authority`.
8. Task A reads identity logs in production. Denied
   `tenuo_constraint_denied`.
9. Task A restarts with `replicas` 8. Denied `tenuo_constraint_denied`.
10. A restart without a warrant is denied `tenuo_missing_warrant`.
11. The third holder, in the second sandbox, reads staging payments logs with
    the narrowed warrant. Allowed.
12. That holder requests a restart with the same warrant. Denied
    `tenuo_tool_denied`.
13. That holder tries to mint a further warrant that adds `restart_service`
    back. Attenuation refuses the wider warrant.
14. The Agent Toolkit middleware, on the host, checks Task B's warrant for
    the same restart. It denies the call before the function runs. That
    denial is in the receipt report and has no OpenShell or destination
    receipt.
15. A Tenuo A2A worker receives a full parent/child warrant stack over JSON-RPC
    HTTP with child-holder proof of possession. It executes `read_logs`; a
    separately minted read-only child warrant is denied before the
    `restart_service` skill runs. The machine-readable result is retained as
    `results/evidence/a2a-handoff.json`.

16. `tenuo-openshell provision` gives the first sandbox a read-only warrant
    for its own key. The MCP SDK client lists tools, reads staging payments
    logs through the signing proxy (allowed, checked by the middleware and the
    destination), and asks for a restart, which the proxy denies inside the
    sandbox with `tool-not-authorized`. The sandbox policy lets only curl and
    the proxy reach the MCP server.

17. A higher policy version limits the first sandbox's tool results to 64
    bytes. Inside the sandbox, `tenuo-openshell-agent sign` signs another read
    with the provisioned key and warrant, and curl sends it as JSON-RPC id 17.
    The middleware allows it, the read runs, and OpenShell withholds its
    larger result with
    `tenuo_result_too_large`. The block happens after the call, so it limits
    what reaches the agent; it does not undo the read.

The middleware runs with `--evaluate-results`. Each allowed call through
OpenShell also gets a result receipt: the status, byte count, and SHA-256 of
the returned body, linked to the call's allow receipt by hash. Step 17's
receipt records the block instead of a digest.

The A2A step is maintained under
[`examples/interoperability`](../interoperability/README.md). It is an
interoperability proof with a documented Tenuo 0.3.1 compatibility bridge, not
part of the OpenShell middleware package surface.

The effect server verifies the preserved warrant with `MCPVerifier` before it
runs a tool. After the sandbox calls, the suite sends three requests directly to
that server, bypassing OpenShell: Task B's restart, a restart with no warrant,
and the narrowed warrant's restart. All three are JSON-RPC `-32001` and none
are executed. One direct read with Task A's warrant is executed, which shows
the destination check does not depend on OpenShell being in front.

Each enforcement point signs its own receipt. The OpenShell middleware and
the effect server use different receipt keys, and both put the JSON-RPC id
in `request_id`. `examples/demo/audit_receipts.py` checks those receipts
with the issuer public keys and the two receipt-signer public keys. It does
not use the network. A missing warrant has no chain to commit to, so that
denial has no receipt. The narrowed calls record both the parent warrant and
the child. The Agent Toolkit denial is a third signer in that report. A
receipt does not show that the tool ran.

The auditor verifies the result log with the middleware's
`receipts export --verify-with openshell.pub`, then checks that every result
names an allow receipt for the same JSON-RPC id and tool. The suite also
writes both logs as JSON lines to `results/evidence/openshell-receipts.json`
and `results/evidence/openshell-results.json`, the format described in
[Receipts](../../docs/receipts.md).

The launcher installs Python package `tenuo` 0.3.1 into a temporary environment
for that server. Set `TENUO_DEMO_PYTHON` to an existing interpreter when that
package is already installed.

From the repository root:

```bash
make demo
```

The same launcher then repeats the calls through a second gateway that does
not register the middleware. That sandbox policy keeps the same tool
admission rules and omits the middleware block. `results/outcome-matrix.md`
is the live comparison, including enforcement-decision time next to the middleware
timeout. Matching outcomes are marked baseline with the reason. `results/`
is local output and is not part of the source tree. The scheduled and manually
dispatched GitHub workflow uploads the matrix, observations, effect logs,
public receipt material, offline audit report, and immutable-version manifest
as a 30-day Actions artifact. Private holder, issuer, JWT, TLS, and receipt
signing keys are never copied into that artifact.

The launcher pins NVIDIA OpenShell v0.1.2 at commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`, builds its gateway and CLI, pulls
NVIDIA's v0.1.2 multi-architecture supervisor and sandbox-runtime images by
immutable index digest,
builds a non-root demo workload from NVIDIA's Ubuntu base pinned by digest,
generates temporary TLS and gateway JWT material, and cleans up the sandbox and
processes afterward. Docker Desktop/Engine 28.0+ or Podman 5.x+, `cargo`,
`curl`, `jq`, `openssl`, and Python 3 are required. The launcher checks the
container runtime version before doing any builds. On Docker Desktop the
supervisor's host network is the Linux VM, so the launcher publishes the
gateway on the machine address and sets the driver's `grpc_endpoint` to it.

Set `OPENSHELL_SOURCE` to an existing pinned OpenShell checkout to skip the
bootstrap download. Set `TENUO_DEMO_DRIVER=podman` to use Podman instead of
Docker. `TENUO_DEMO_SUPERVISOR_IMAGE`, `TENUO_DEMO_SANDBOX_RUNTIME_IMAGE`, and
`TENUO_DEMO_WORKLOAD_IMAGE` are explicit escape hatches for private mirrors;
keep them pinned by digest. When a workload override is supplied, the launcher
assumes it already contains curl and a `sandbox` UID/GID 1000 account.
