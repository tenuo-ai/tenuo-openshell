#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
# fmt and clippy cover the fuzz crate; test and build use the default members,
# which leave out its libFuzzer mains.
cargo test --all-targets --locked
cargo build --release --locked
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check --hide-inclusion-graph
fi
bash -n scripts/bench.sh scripts/bootstrap-openshell.sh scripts/onboarding-smoke.sh scripts/openshell-e2e.sh scripts/quickstart-check.sh examples/nemo-agent-toolkit/run.sh ci/nat-compat.sh ci/release-binary.sh scripts/production-quickstart-check.sh scripts/build-demo-image.sh
TENUO_SMOKE_SKIP_BUILD=1 scripts/onboarding-smoke.sh
if command -v helm >/dev/null 2>&1; then
  helm lint deploy/helm/tenuo-openshell
fi
python3 -m py_compile \
  deploy/demo-image/tenuo-demo-mcp \
  examples/nemo-agent-toolkit/scripted_llm.py \
  examples/demo/mcp_client.py \
  examples/demo/mcp_server.py \
  examples/demo/audit_receipts.py \
  examples/demo/test_destination.py \
  examples/demo/local_denial.py \
  examples/demo/outcome_matrix.py \
  examples/interoperability/a2a_handoff.py \
  examples/issuance/issuer_service.py \
  examples/issuance/test_issuer_service.py

fixture_dir="$(mktemp -d)"
dist_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir" "$dist_dir"' EXIT
cargo run --quiet --locked --bin tenuo-demo-fixture -- --output "$fixture_dir" --sandbox-id test-sandbox
jq -e '.sandboxes["test-sandbox"]' "$fixture_dir/policy.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/task-a-read.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/task-b-restart.json" >/dev/null
jq -e '.params._meta.tenuo' "$fixture_dir/copied-warrant.json" >/dev/null
jq -e '.params._meta.tenuo == null' "$fixture_dir/missing-warrant.json" >/dev/null
test "$(wc -c <"$fixture_dir/signers/task-a/key" | tr -d ' ')" = 32
test "$(wc -c <"$fixture_dir/signers/task-b/key" | tr -d ' ')" = 32
! cmp -s "$fixture_dir/signers/task-a/key" "$fixture_dir/signers/task-b/key"
# The plugin's locked environment provides the tenuo package the demo MCP
# server needs, so the destination check always runs here.
TENUO_DEMO_EFFECT_LOG=/tmp/unused uv run --locked --project python/nemo-agent-toolkit-tenuo \
  python examples/demo/test_destination.py --fixture "$fixture_dir"
uv run --locked --project python/nemo-agent-toolkit-tenuo \
  python examples/issuance/test_issuer_service.py --agent target/release/tenuo-openshell-agent

uv run --locked --project python/nemo-agent-toolkit-tenuo --extra test \
  pytest python/nemo-agent-toolkit-tenuo/tests -q
uv run --locked --project python/nemo-agent-toolkit-tenuo --extra test nat info components \
  | grep -F tenuo >/dev/null
uv build --project python/nemo-agent-toolkit-tenuo --out-dir "$dist_dir"
test "$(find "$dist_dir" -maxdepth 1 -name '*.whl' | wc -l | tr -d ' ')" = 1
test "$(find "$dist_dir" -maxdepth 1 -name '*.tar.gz' | wc -l | tr -d ' ')" = 1
! tar -tzf "$dist_dir"/*.tar.gz | grep -F 'tests/test_outcome_matrix.py' >/dev/null
