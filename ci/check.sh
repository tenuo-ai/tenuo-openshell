#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
bash -n scripts/bootstrap-openshell.sh scripts/openshell-e2e.sh
python3 -m py_compile examples/demo/mcp_server.py

fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT
cargo run --quiet --bin tenuo-demo-fixture -- --output "$fixture_dir" --sandbox-id test-sandbox
jq -e '.sandboxes["test-sandbox"]' "$fixture_dir/policy.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/allowed.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/constraint-denied.json" >/dev/null
jq -e '.params._meta.tenuo == null' "$fixture_dir/missing-warrant.json" >/dev/null

uv run --project python/nemo-agent-toolkit-tenuo --extra test \
  pytest python/nemo-agent-toolkit-tenuo/tests -q
uv run --project python/nemo-agent-toolkit-tenuo --extra test nat info components \
  | grep -F tenuo >/dev/null
