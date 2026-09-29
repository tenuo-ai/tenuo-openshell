# Upstream verification

Date: 2026-09-28  
Status: increment 0, sufficient to start the OpenShell middleware  
Pin: NVIDIA OpenShell **v0.1.2**, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` (2026-09-28)

`proto/supervisor_middleware.proto` at that commit is byte-identical to `main` at `9cb72baa2e61a1b5f12407e6e82da7fdba0aa722` (2026-09-29). The vendored copies in `proto/openshell/v0.1.2/` are the v0.1.2 files. A newer OpenShell release requires a new pin before the compatibility range moves.

This file records what the pinned source and the public docs actually say. Where they differ, the pinned proto wins for implementation.

## OpenShell supervisor middleware

Confirmed in `proto/supervisor_middleware.proto` at v0.1.2.

| Contract | Pinned source |
|---|---|
| Package | `openshell.middleware.v1` |
| Service | `SupervisorMiddleware` |
| Discover | `Describe(MiddlewareDescribeRequest) returns (MiddlewareManifest)` |
| Config | `ValidateConfig(ValidateConfigRequest) returns (ValidateConfigResponse)` |
| HTTP hook | `EvaluateHttpRequest(HttpRequestEvaluation) returns (HttpRequestResult)` |
| Phase | `SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS = 1` |
| Operation | `SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST = 1` |
| Identity | `RequestContext.sandbox_id` (field 2). Comment: use it for authorization, persistence, durable correlation, and identity. |
| Display only | `RequestContext.sandbox` (field 4) and `RequestContext.workspace` (field 5) |
| Correlation | `RequestContext.request_id` (field 1) |
| Decision | `DECISION_ALLOW = 1`, `DECISION_DENY = 2`. `DECISION_UNSPECIFIED` follows `on_error`. |
| Body replacement | `HttpRequestResult.body` plus `has_body`. `has_body` true replaces the body, including with an empty body. |
| Denial code | `HttpRequestResult.reason_code`: starts with a lowercase ASCII letter, then lowercase ASCII letters, digits, and underscores, maximum 64 bytes. OpenShell may return this code to the requester. |
| Free-form reason | `HttpRequestResult.reason` is not relayed into denied responses or security logs. |
| Credentials | Request headers on `HttpRequestEvaluation` are taken before credential injection. Protected credential headers are omitted. |

`Describe` does not take `google.protobuf.Empty`. The request is `MiddlewareDescribeRequest`, which carries `openshell.extension.v1.PeerMetadata`. That message lives in `proto/extension.proto`, which is vendored beside the middleware proto. `MiddlewareManifest.expected_audience` is the exact JWT audience the service verifies. An empty value skips OpenShell's post-authentication consistency check.

`ValidateConfigRequest.middleware_name` is documented as the built-in middleware name or the operator-owned registration name. The spec's `middleware: tenuo/authorization` attachment matches this proto. RFC 0009 text that says policy selects a binding ID returned by `Describe`, independent of the registration name, is stale relative to v0.1.2.

Gateway registration fields in `proto/sandbox.proto` `SupervisorMiddlewareService` match the spec's TOML shape: `name`, `grpc_endpoint`, `max_payload_bytes`, `timeout` (`10ms` through `30s`, default `500ms`), `tls_ca_cert_pem`, `audience`, and `allow_insecure_transport`. The `openshell/` registration prefix remains reserved. `tenuo/authorization` does not use it.

Binding-level timeout on `MiddlewareBinding` is `google.protobuf.Duration request_timeout = 104`. The old string field `timeout` is reserved. The gateway TOML timeout and this duration are different layers. A binding duration may shorten the operator timeout and cannot extend it.

Public docs checked on 2026-09-28:

- https://docs.nvidia.com/openshell/dev/extensibility/supervisor-middleware
- https://github.com/NVIDIA/OpenShell/blob/main/rfc/0009-supervisor-middleware/README.md

Those docs agree with the pin on `pre_credentials`, `sandbox_id`, `fail_closed` as the default, body re-check after replacement, and `error: middleware_denied` plus `reason_code`. They name the display field `sandbox_name`. The proto field is `sandbox`. Implementation reads `sandbox_id` for policy selection and may log `sandbox` as a display label.

### In scope for increment 1

Advertise one binding: `HTTP_REQUEST` / `PRE_CREDENTIALS`. Implement `Describe`, `ValidateConfig`, and `EvaluateHttpRequest`.

### Present in the proto and out of the demo slice

- `EvaluateWebSocketSession`. The proto includes a `binary` payload variant. The supervisor middleware docs say binary frames are not delivered to middleware and pass through. Do not advertise WebSocket coverage.
- `HTTP_RESPONSE` and the separate `HttpResponsePreReturn` service. Response inspection runs after the upstream request has already executed. It is not an authorization point for the tool effect.
- mTLS client authentication. `SupervisorMiddlewareService` comments say v1 supports plaintext and server-authenticated TLS gRPC. Production remains TLS plus the extension bearer. `allow_insecure_transport` is the local demo switch.

### Uncovered paths

Fail-closed middleware still does not inspect `tls: skip`, non-HTTP TCP, or binary WebSocket frames. The hardening note in the demo slice has to deny those routes with network policy. This was not re-tested at runtime in increment 0. It is taken from the supervisor middleware docs and stays a runtime check in increment 1.

## MCP policy surface

Confirmed in v0.1.2:

- `proto/sandbox.proto`, `L7Allow.params` and `L7DenyRule.params`: "Currently only params.name is supported for tools/call filtering."
- `crates/openshell-supervisor-network/src/l7/jsonrpc.rs`: policy-visible MCP params expose only `params.name`. The test `mcp_mode_ignores_tool_arguments_when_extracting_policy_params` asserts that a `tools/call` with nested `arguments` yields a one-entry params map whose only key is `name`.
- `McpOptions.strict_tool_names` checks tool-name syntax `^[A-Za-z0-9_.-]{1,128}$`. It does not constrain argument values.
- `crates/openshell-core/src/mcp.rs` owns protocol revisions, not argument authorization. The default revision is `2025-11-25`.

The scenario consequences are in `docs/openshell-gap-analysis.md`.

## NeMo Agent Toolkit

The in-process plugin is increment 2. It is not required to demonstrate H1.

Checked against the 1.8 public docs on 2026-09-28:

- https://docs.nvidia.com/nemo/agent-toolkit/1.8/extend/plugin-api.html
- https://docs.nvidia.com/nemo/agent-toolkit/1.8/extend/third-party-plugins.html
- https://docs.nvidia.com/nemo/agent-toolkit/1.8/build-workflows/advanced/middleware.html

Third-party packages import `nat.plugin_api` and register through the `nat.plugins` entry point. `register_middleware` is on that public surface. `FunctionMiddleware.function_middleware_invoke` receives `call_next` and can return without calling it. `DynamicFunctionMiddleware` is the documented default and its base class drives the chain. Increment 2 must confirm, by reading the installed package, that `DynamicFunctionMiddleware` can skip `call_next` before using it. Until then the plugin subclasses `FunctionMiddleware`.

PyPI package `nvidia-nat` version **1.9.0** was current on 2026-09-28. The 1.9 middleware documentation URL returned 404. This repository does not claim 1.9 compatibility. The first plugin change installs a pinned `nvidia-nat` and records the import result here.

## Links from the specification

| Link | Result on 2026-09-28 |
|---|---|
| NeMo Agent Toolkit plugin API (1.8) | Resolves |
| NeMo Agent Toolkit middleware (1.8) | Resolves |
| OpenShell supervisor middleware docs | Resolves |
| OpenShell supervisor middleware RFC | Resolves |
| `github.com/NVIDIA/OpenShell` `docs/extensibility/supervisor-middleware.mdx` | 404. The spec now cites the docs site and the RFC. |
| OpenShell `architecture/security-policy.md` | Present at the v0.1.2 tree. Not re-read for this pin. |
| NIM API reference | Not required for this repository. |

## What increment 0 did not run

No OpenShell gateway was started. No gRPC call was made. No `nvidia-nat` package was imported. Those are increment 1 and increment 2 runtime checks. The proto, the MCP policy source, and the 1.8 plugin docs are enough to start the middleware without inventing the RPC shape.
