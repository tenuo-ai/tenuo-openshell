# Upstream verification

Date: 2026-09-28  
Status: contract record for the vendored proto  
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

`ValidateConfigRequest.middleware_name` is documented as the built-in middleware name or the operator-owned registration name. An attachment such as `middleware: tenuo/authorization` matches this proto. RFC 0009 text that says policy selects a binding ID returned by `Describe`, independent of the registration name, is stale relative to v0.1.2.

Gateway registration fields in `proto/sandbox.proto` `SupervisorMiddlewareService` match the spec's TOML shape: `name`, `grpc_endpoint`, `max_payload_bytes`, `timeout` (`10ms` through `30s`, default `500ms`), `tls_ca_cert_pem`, `audience`, and `allow_insecure_transport`. The `openshell/` registration prefix remains reserved. `tenuo/authorization` does not use it.

Binding-level timeout on `MiddlewareBinding` is `google.protobuf.Duration request_timeout = 104`. The old string field `timeout` is reserved. The gateway TOML timeout and this duration are different layers. A binding duration may shorten the operator timeout and cannot extend it.

Public docs checked on 2026-09-28:

- https://docs.nvidia.com/openshell/dev/extensibility/supervisor-middleware
- https://github.com/NVIDIA/OpenShell/blob/main/rfc/0009-supervisor-middleware/README.md

Those docs agree with the pin on `pre_credentials`, `sandbox_id`, `fail_closed` as the default, body re-check after replacement, and `error: middleware_denied` plus `reason_code`. They name the display field `sandbox_name`. The proto field is `sandbox`. Implementation reads `sandbox_id` for policy selection and may log `sandbox` as a display label.

### Implemented

- `HTTP_REQUEST` / `PRE_CREDENTIALS`, via `Describe`, `ValidateConfig`, and `EvaluateHttpRequest`.
- With `--evaluate-results`, `HTTP_RESPONSE` / `PRE_RETURN`, via the separate `HttpResponsePreReturn.Evaluate` stream on the same listener and credentials.

### Response binding

Confirmed in the pinned source under `crates/`:

| Contract | Pinned source |
|---|---|
| Binding selection | `openshell-supervisor-middleware/src/lib.rs` `supported_binding` (line 870) accepts `HTTP_RESPONSE` only with `PRE_RETURN`. `describe_chain_for` (line 1542) builds each operation/phase chain from the same policy attachments; an attachment whose manifest lacks the pair is left out of that chain. Advertising the pair therefore puts every attachment of the registration on the response path, with the attachment's `config` and `on_error`. |
| Payload limit | `validate_manifest_bindings` (line 899) rejects a registration whose `max_payload_bytes` exceeds any advertised binding's limit, so both bindings advertise 262144. |
| Request/response correlation | `openshell-supervisor-network/src/l7/middleware.rs` `HttpMiddlewareExchange` (line 33) holds one `request_id` for a request and its response; `response_relay` (line 80) copies it into the response `RequestContext`. For MCP, `l7/relay.rs` `relay_jsonrpc` (line 2153) creates a UUID v4 `request_id` (line 2315), evaluates the request chain with it, and passes it to the response relay. |
| Transport | `openshell-supervisor-middleware/src/remote.rs` (lines 153 and 156) builds the request and response clients on one channel with one bearer interceptor, so both RPCs carry the same extension JWT and reach the same endpoint. |
| Preflight input | `response/preflight.rs` sends the attachment `config` (line 90), the effective `max_payload_bytes`, and the permitted modes per stage. |
| Body modes | `response/validation.rs` `body_restriction` (line 246) returns `HEADERS_ONLY` alone for `HEAD`, 204, 304, 206, `Content-Range`, `multipart/byteranges`, `Cache-Control: no-transform`, and any non-identity `Content-Encoding`. `permitted_body_modes` (line 292) omits `WHOLE_BODY_BYTES` for a declared length above the limit and for `text/event-stream` or `multipart/x-mixed-replace` (`is_open_ended_response`, line 314), and offers `STREAM_BYTES` whenever the limit is nonzero. Server-Sent Events responses are therefore streamed, not headers-only. |
| Request headers | `l7/middleware.rs` `safe_middleware_headers` (line 828) forwards every request header except credential, routing, framing, and hop-by-hop fields. W3C `traceparent` reaches `HttpRequestEvaluation.headers`. |

The proto states that a response block does not roll back the upstream request. Before response commitment OpenShell returns its canonical 403 with the `reason_code`; after commitment it aborts delivery without one.

### Present in the proto and not implemented

- `EvaluateWebSocketSession`. The proto includes a `binary` payload variant. The supervisor middleware docs say binary frames are not delivered to middleware and pass through.
- Response header and body transforms. The response binding only passes through, skips, or blocks.
- Extension client-certificate authentication. OpenShell v0.1.2 supports
  server-authenticated TLS plus an extension bearer JWT, but does not provision
  client certificates. The production listener implements that exact contract;
  plaintext and unauthenticated operation require the explicit
  `--insecure-dev` flag.

### Uncovered paths

Fail-closed middleware does not inspect `tls: skip` endpoints, non-HTTP TCP, or binary WebSocket frames. A protected tool is still reachable on those routes unless network policy denies them. `WEBSOCKET_MESSAGE / PRE_CREDENTIALS` covers complete client text messages only, and this service does not implement that RPC. `HTTP_RESPONSE` runs after the upstream call and is not an authorization point. The repository's `make e2e` suite exercises the request and response paths through a real pinned gateway and sandbox.

## MCP policy surface

Confirmed in v0.1.2:

- `proto/sandbox.proto`, `L7Allow.params` and `L7DenyRule.params`: "Currently only params.name is supported for tools/call filtering."
- `crates/openshell-supervisor-network/src/l7/jsonrpc.rs`: policy-visible MCP params expose only `params.name`. The test `mcp_mode_ignores_tool_arguments_when_extracting_policy_params` asserts that a `tools/call` with nested `arguments` yields a one-entry params map whose only key is `name`.
- `McpOptions.strict_tool_names` checks tool-name syntax `^[A-Za-z0-9_.-]{1,128}$`. It does not constrain argument values.
- `crates/openshell-core/src/mcp.rs` owns protocol revisions, not argument authorization. The default revision is `2025-11-25`.

The scenario consequences are in `docs/openshell-gap-analysis.md`.

## NeMo Agent Toolkit

The in-process plugin is a separate package. This service does not import it.

The supported dependency is `nvidia-nat-core>=1.8,<1.10`. The partner-owned distribution is `nemo-agent-toolkit-tenuo`, with the NVIDIA namespace-preserving import `nat.plugins.tenuo` and entry point `nat_tenuo`. The plugin code is the same on both releases.

### 1.8

Checked against the 1.8 public docs on 2026-09-28:

- https://docs.nvidia.com/nemo/agent-toolkit/1.8/extend/plugin-api.html
- https://docs.nvidia.com/nemo/agent-toolkit/1.8/extend/third-party-plugins.html
- https://docs.nvidia.com/nemo/agent-toolkit/1.8/build-workflows/advanced/middleware.html

Third-party packages import `nat.plugin_api` and register through the `nat.plugins` entry point. `register_middleware` is on that public surface. `FunctionMiddleware.function_middleware_invoke` receives `call_next` and can return without calling it. The plugin intentionally subclasses `FunctionMiddleware` so denial can return before invoking the protected function.

### 1.9

Checked on 2026-10-04 against the `nvidia-nat-core` 1.9.0 wheel from PyPI (released 2026-09-10, sha256 `4a5192f094a115e62a1a6db84df96e5cc18c4f556df2252a43ff998689b30a8d`), diffed file by file against the 1.8.0 wheel. NVIDIA had not published versioned 1.9 docs: the `1.9/` paths return 404 and `latest/` still reports 1.8.

Unchanged between 1.8.0 and 1.9.0 (byte-identical):

| Surface | File |
|---|---|
| `register_middleware` (line 337) | `nat/cli/register_workflow.py` |
| Type registry | `nat/cli/type_registry.py` |
| Entry-point discovery; `discover_entrypoints` (line 128) reads `nat.plugins` (line 140) | `nat/runtime/loader.py` |
| `FunctionMiddlewareBaseConfig` | `nat/data_models/middleware.py` |
| `Function.configure_middleware` (line 133) and the invoke path, which awaits the middleware chain in the caller's task (line 200) | `nat/builder/function.py` |
| Builders | `nat/builder/builder.py`, `workflow_builder.py`, `child_builder.py`, `per_user_workflow_builder.py` |

Changed, all additive for this plugin:

| Change | File | Effect on the plugin |
|---|---|---|
| `InvocationAction.SKIP` and `InvocationContext.action` | `nat/middleware/middleware.py` (line 73) | Read only by the default `function_middleware_invoke` and `function_middleware_stream` after `pre_invoke`. The plugin overrides both, so it never consults them. |
| Default stream drops a chunk whose `post_invoke` output is `None` | `nat/middleware/function_middleware.py` (line 208) | Default implementation only; the plugin overrides it. |
| `validate_middleware` (line 367) drops repeated instances of the same middleware, keeping the first | `nat/middleware/function_middleware.py` | The plugin builds one instance per configured middleware, so it runs once per call as before. |
| `nat.plugin_api` adds `Context`, `ContextState`, `InvocationAction`, circuit-breaker, HITL, and interactive-prompt exports | `nat/plugin_api/__init__.py` | Every symbol the plugin imports (`Builder`, `FunctionMiddleware`, `FunctionMiddlewareBaseConfig`, `FunctionMiddlewareContext`, `register_middleware`) is still exported. |
| Run, trace, and function IDs come from `nat.utils.providers` instead of `uuid4` | `nat/runtime/runner.py`, `nat/builder/context.py` | None. The plugin's warrant binding is its own `ContextVar` and does not read NAT context. |
| `cryptography>=48,<49` (1.8 pinned `>=46.0.6,<47`) | package metadata | Transitive only. |

`FunctionMiddlewareContext` has the same fields, and `FunctionMiddleware.function_middleware_invoke` (line 149) has the same signature and still receives `call_next`. `nvidia-nat-core` 1.9 still imports `packaging` without declaring it, so the plugin keeps that dependency.

Outside the core package, `nvidia-nat-langchain` 1.9 moved its model-provider integrations (`langchain-openai`, `langchain-nvidia-ai-endpoints`, and others) from dependencies to extras. The repository example installs `nvidia-nat-langchain[openai,nvidia]`. The plugin does not depend on `nvidia-nat-langchain`.

### Executable checks

CI runs the plugin tests and `nat info components` discovery in the locked environment (Agent Toolkit 1.9.0) on Python 3.11, 3.12, and 3.13, and against Agent Toolkit 1.8.0 on Python 3.11 and 3.13 through `ci/nat-compat.sh 1.8`. `examples/nemo-agent-toolkit/run.sh` runs the ReAct agent, approval, and single-use approval flow on Agent Toolkit 1.9.0.

## Links from the specification

| Link | Result on 2026-09-28 |
|---|---|
| NeMo Agent Toolkit plugin API (1.8) | Resolves |
| NeMo Agent Toolkit middleware (1.8) | Resolves |
| NeMo Agent Toolkit 1.9 docs (`/agent-toolkit/1.9/...`) | 404 on 2026-10-04. Verified against the 1.9.0 package source instead. |
| OpenShell supervisor middleware docs | Resolves |
| OpenShell supervisor middleware RFC | Resolves |
| `github.com/NVIDIA/OpenShell` `docs/extensibility/supervisor-middleware.mdx` | 404. The spec now cites the docs site and the RFC. |
| OpenShell `architecture/security-policy.md` | Present at the v0.1.2 tree. Not re-read for this pin. |

## Executable verification

`make e2e` builds the pinned OpenShell gateway, CLI, middleware, and workload;
uses NVIDIA's pinned supervisor and sandbox-runtime images; creates an
authenticated HTTPS middleware registration; and runs the complete outcome
matrix through real sandboxes. Four protected sandbox calls execute in the
middleware-enabled run; denied calls do not reach the effect. The run enables
the response binding: allowed calls get result receipts linked to their
authorization receipts, and a policy reload with `max_result_bytes` shows a
read that runs while OpenShell withholds its result. `make check`
covers Rust formatting, linting, tests and release builds, JWT negative cases, signed
fixture generation, Agent Toolkit 1.9 plugin tests, entry-point discovery, and
package builds. The full gateway suite requires a supported container runtime
and is therefore a separate manual/weekly CI job.

## Upstream tracking

The pin is the release gate. `.github/workflows/upstream-drift.yml` watches
OpenShell `main` nightly (04:41 UTC, or on dispatch with another ref) so a
breaking change, such as the streaming request hook proposed in
NVIDIA/OpenShell#3307, shows up before a re-pin. It is not a required check:
branch protection requires jobs from `ci.yml` only. The same workflow checks
the NeMo Agent Toolkit and Tenuo releases; the
[compatibility matrix](compatibility-matrix.md) lists every job. The
OpenShell jobs:

| Job | What it does |
|---|---|
| `proto-drift` | `scripts/openshell-upstream.sh proto-drift main` downloads the upstream copy of each file the vendored `NOTICE` lists and fails with a Markdown table and unified diff when any differs or is gone. It also notes, without failing, when `proto/sandbox.proto`, which holds the middleware registration fields, changed since the pin. It needs no build and finishes in seconds. |
| `e2e` | `OPENSHELL_REF=main make e2e`: the full authenticated demo against upstream source. While OpenShell's newest release is newer than the pin, it also runs against that release tag. |
| `report` | Runs after every job with `issues: write`, the only job with that permission. A failure opens an issue labeled `upstream-drift`, or comments on the open one; a later passing run comments and closes it. |

**Ref selection.** With `OPENSHELL_REF` set, `scripts/bootstrap-openshell.sh`
fetches that branch, tag, or commit into `.cache/openshell/upstream`, separate
from the pinned checkout, and records the ref and resolved commit in
`.cache/openshell/upstream.commit`. Without it, the bootstrap is unchanged: the
pinned tag, verified against the pinned commit.

**Images.** OpenShell's `Release Dev` workflow pushes
`ghcr.io/nvidia/openshell/supervisor` and `ghcr.io/nvidia/openshell/sandbox`
tagged with the full commit SHA for every `main` commit, and moves the `dev`
tag only after its own integration suite passes. There is no `main` tag. The
release tags follow the same scheme: the `6648bd0…` tags carry the same
digests as `0.1.2`. `scripts/openshell-upstream.sh resolve main` therefore
walks back from the tip, up to 30 commits, to the newest commit with both
images, and the e2e builds that commit and runs those images pinned by digest,
so the gateway, supervisor, and sandbox runtime always come from one commit.
A tip pushed minutes earlier simply resolves to its parent. Setting both
`TENUO_DEMO_SUPERVISOR_IMAGE` and `TENUO_DEMO_SANDBOX_RUNTIME_IMAGE` skips
resolution and builds the ref itself, for example with images built locally
from that checkout. `dev` is not used: it lags `main` by however long upstream
integration takes and would pair new source with older images.

The run's `results/evidence/manifest.json` records the resolved commit, the
requested ref, and both image references.
