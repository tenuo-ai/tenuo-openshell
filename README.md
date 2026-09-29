# tenuo-openshell

Tenuo authorization for OpenShell supervisor middleware.

The service implements `openshell.middleware.v1.SupervisorMiddleware` for `HTTP_REQUEST` / `PRE_CREDENTIALS`. On each covered MCP `tools/call` it checks the warrant, proof-of-possession, and arguments in `params._meta.tenuo` before OpenShell injects provider credentials. Other MCP lifecycle methods in the built-in allowlist are returned without a warrant check. WebSocket sessions and extension bearer authentication are not implemented.

Build against a local checkout of [tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo) at `b0dcfe571c0bd9dbb41cde102053d648301c67a8`, placed next to this repository as `../tenuo`. The `tenuo` package lives in `tenuo-core/` and that repository has no root package manifest, so the dependency is a path.

```bash
cargo test
cargo run -- --policy examples/policy.json --listen 127.0.0.1:50051 --insecure-dev
```

`--insecure-dev` accepts unauthenticated callers. The process refuses to start without it. Do not use that flag on a reachable network.

The OpenShell registration for that local process sets `allow_insecure_transport = true`. The registration name must not use the reserved `openshell/` prefix.

## Pin

| Upstream | Pin |
|---|---|
| OpenShell proto | v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`, vendored under `proto/openshell/v0.1.2/` |
| Tenuo crate | `b0dcfe571c0bd9dbb41cde102053d648301c67a8`, features `sdk` and `mcp-transport` |

Contract notes: [`docs/upstream-verification.md`](docs/upstream-verification.md). MCP policy limit: [`docs/openshell-gap-analysis.md`](docs/openshell-gap-analysis.md).

The Agent Toolkit function middleware is a separate Python package in [`python/tenuo-nat`](python/tenuo-nat). This service does not import it.

## License

Apache-2.0. Vendored OpenShell protos keep NVIDIA's copyright and SPDX headers.
