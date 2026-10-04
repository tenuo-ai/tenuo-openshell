# Contributing

Thank you for improving Tenuo's NVIDIA integrations. Security-boundary changes
need both a clear threat-model rationale and executable negative tests.

## Development setup

Install Rust 1.91+, Python 3.11+, `uv`, `jq`, and `protoc` dependencies (the
Rust build uses a vendored compiler). Then run:

```bash
make check
```

This is the local merge gate: Rust format, lint, test and release build;
fixture validation; Python tests and plugin discovery; and wheel/sdist builds.
When Helm is installed it also lints the production chart. Set
`TENUO_TEST_REDIS_URL` to run the shared replay-store integration test.
Use `make e2e` for changes to protocols, policy evaluation, authentication,
container behavior, demo assets, or the OpenShell pin.

`make check` also formats and lints the fuzz targets, and runs
`cargo deny check` when `cargo-deny` is installed. `deny.toml` holds the
advisory, license, and source policy. Add an advisory ignore only with the
reason it does not apply and the condition for removing it.

## Fuzzing

`fuzz/` is a cargo-fuzz crate in the root workspace and shares its
`Cargo.lock`. It has three targets: `mcp_parse` (MCP body parsing),
`policy_load` (policy documents), and `evaluate` (the full decision against a
fixed policy). It is not a default member, so `cargo test` and `cargo build`
skip its libFuzzer mains, which never exit; `cargo clippy --workspace` and
`cargo fmt --all` still check it. Run a target with a nightly toolchain:

```bash
cd fuzz
cargo +nightly fuzz run evaluate corpus/evaluate seeds/evaluate -- -max_total_time=300
```

`seeds/` holds committed starting inputs; `corpus/` and `artifacts/` stay
local. On macOS, add `--sanitizer none` if AddressSanitizer hangs at startup.
Fix a crash with a regression test in the main crate, not only in the fuzz
target.

## Pull requests

- Keep changes focused and add tests for allow and deny behavior.
- Explain which component is the security boundary and what fails closed.
- Do not weaken TLS, JWT, sandbox identity, argument, lifetime, PoP, or replay
  checks to simplify a demo.
- Update compatibility tables and `docs/upstream-verification.md` when changing
  OpenShell, Agent Toolkit, or Tenuo pins.
- Update `CHANGELOG.md` for user-visible behavior.
- Do not commit generated results, build outputs, credentials, or private keys.

Protocol files under `proto/` are pinned upstream inputs. Preserve their
copyright and SPDX headers, and document the exact upstream revision when they
change.

Security reports belong in the private process described in
[SECURITY.md](SECURITY.md), not in a public pull request.
