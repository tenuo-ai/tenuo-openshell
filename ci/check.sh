#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
bash -n scripts/bootstrap-openshell.sh scripts/openshell-e2e.sh
python3 -m py_compile examples/demo/mcp_server.py examples/demo/audit_receipts.py examples/demo/test_destination.py examples/demo/local_denial.py

fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT
cargo run --quiet --bin tenuo-demo-fixture -- --output "$fixture_dir" --sandbox-id test-sandbox
jq -e '.sandboxes["test-sandbox"]' "$fixture_dir/policy.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/task-a-read.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/task-b-restart.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/copied-warrant.json" >/dev/null
jq -e '.params._meta.tenuo == null' "$fixture_dir/missing-warrant.json" >/dev/null
test "$(wc -c <"$fixture_dir/signers/task-a/key" | tr -d ' ')" = 32
test "$(wc -c <"$fixture_dir/signers/task-b/key" | tr -d ' ')" = 32
! cmp -s "$fixture_dir/signers/task-a/key" "$fixture_dir/signers/task-b/key"
if python3 -c 'import tenuo; parts=tuple(int(p) for p in tenuo.__version__.split(".")[:3]); raise SystemExit(0 if parts>=(0,3,1) else 1)'; then
  TENUO_DEMO_EFFECT_LOG=/tmp/unused python3 examples/demo/test_destination.py --fixture "$fixture_dir"
fi

uv run --project python/nemo-agent-toolkit-tenuo --extra test \
  pytest python/nemo-agent-toolkit-tenuo/tests -q
uv run --project python/nemo-agent-toolkit-tenuo --extra test nat info components \
  | grep -F tenuo >/dev/null
