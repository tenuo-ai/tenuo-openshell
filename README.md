# tenuo-openshell

Task-scoped Tenuo authorization for NVIDIA OpenShell and NeMo Agent Toolkit.

OpenShell admits what a sandbox can reach. This repository adds a supervisor middleware that checks a Tenuo warrant, proof-of-possession, and the concrete MCP arguments before OpenShell injects provider credentials. An in-process NeMo Agent Toolkit plugin is the early check on the same warrant. The model that proposes a tool call is not part of the authorization decision. `make demo` will use a deterministic tool-call driver. NIM is not required.

## Status

Increment 0 is recorded against OpenShell **v0.1.2** (`6648bd0c290efbc41ba131ee9831ee45cd431f94`):

- [`docs/upstream-verification.md`](docs/upstream-verification.md)
- [`docs/openshell-gap-analysis.md`](docs/openshell-gap-analysis.md)

The next build is increment 1: an HTTP `PRE_CREDENTIALS` middleware that denies a covered `tools/call` with no `_meta.tenuo`, and denies `restart_service` when the call carries only the log-summarization warrant.

## Pin

| Upstream | Pin |
|---|---|
| OpenShell | v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` |
| Middleware proto | `proto/openshell/v0.1.2/` |
| NeMo Agent Toolkit | Public plugin API as documented for 1.8. PyPI `nvidia-nat` is 1.9.0; do not claim 1.9 compatibility until a local import confirms `FunctionMiddleware`. |

## License

Apache-2.0. Vendored OpenShell protos keep NVIDIA's copyright and SPDX headers.
