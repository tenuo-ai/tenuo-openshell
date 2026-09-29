# Authenticated OpenShell demo

The demo sends two tasks through one OpenShell sandbox and the Tenuo
`HTTP_REQUEST/PRE_CREDENTIALS` middleware. The sandbox policy admits both
`read_logs` and `restart_service`. Task A's warrant grants those tools for
`payments` in `staging`, and limits `restart_service` to `replicas` of at most
5. Task B's warrant grants only the staging payments read.

Each holder key is created by its own process and stored in its own file. The
sandbox command receives the signed request body only. Neither holder key is
copied into the sandbox. The issuer secret is not written.

1. Task A reads staging payments logs. Allowed.
2. Task B reads staging payments logs with its own warrant. Allowed.
3. Task A restarts staging payments with `replicas` 3. Allowed.
4. Task B requests that restart with its own warrant. Denied
   `tenuo_tool_denied`.
5. Task B signs Task A's warrant for that restart. The holder proof does
   not verify, so it is denied `tenuo_invalid_authority`.
6. Task A reads identity logs in production. Denied
   `tenuo_constraint_denied`.
7. Task A restarts with `replicas` 8. Denied `tenuo_constraint_denied`.
8. A restart without a warrant is denied `tenuo_missing_warrant`.

The suite checks that the effect server saw exactly the three allowed calls.

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
