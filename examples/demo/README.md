# Authenticated OpenShell demo

The demo sends three identical `read_logs` tool calls through a real OpenShell
sandbox and the Tenuo `HTTP_REQUEST/PRE_CREDENTIALS` middleware:

1. `payments` in `staging` is allowed and reaches the MCP effect server.
2. `identity` in `production` has a valid warrant and proof-of-possession but
   violates the warrant's argument constraints, so it is denied.
3. A call without a warrant is denied.

OpenShell's policy admits the `read_logs` tool name. Tenuo makes the narrower,
task-specific argument decision. The suite verifies that the effect server saw
exactly the first call.

From the repository root:

```bash
make demo
```

The launcher pins NVIDIA OpenShell v0.1.2 at commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`, builds its gateway and CLI, pulls
NVIDIA's v0.1.2 multi-architecture supervisor and sandbox-runtime images by
immutable index digest,
builds a non-root demo workload from NVIDIA's Ubuntu base pinned by digest,
generates temporary TLS and gateway JWT material, and cleans up the sandbox and
processes afterward. Docker Desktop/Engine 28.0+ or Podman 5.x+, `cargo`,
`curl`, `jq`, `openssl`, and Python 3 are required. The launcher checks the
container runtime version before doing any builds.

Set `OPENSHELL_SOURCE` to an existing pinned OpenShell checkout to skip the
bootstrap download. Set `TENUO_DEMO_DRIVER=podman` to use Podman instead of
Docker. `TENUO_DEMO_SUPERVISOR_IMAGE`, `TENUO_DEMO_SANDBOX_RUNTIME_IMAGE`, and
`TENUO_DEMO_WORKLOAD_IMAGE` are explicit escape hatches for private mirrors;
keep them pinned by digest. When a workload override is supplied, the launcher
assumes it already contains curl and a `sandbox` UID/GID 1000 account.
