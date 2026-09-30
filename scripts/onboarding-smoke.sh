#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for command in cargo curl python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing prerequisite: $command" >&2
    exit 2
  fi
done

work_dir="$(mktemp -d)"
middleware_pid=""
cleanup() {
  if [[ -n "$middleware_pid" ]] && kill -0 "$middleware_pid" 2>/dev/null; then
    kill "$middleware_pid" 2>/dev/null || true
    wait "$middleware_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

if [[ "${TENUO_SMOKE_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --release --locked --bins
fi

fixture="$work_dir/fixture"
target/release/tenuo-demo-fixture --output "$fixture" --sandbox-id onboarding-smoke \
  >"$work_dir/fixture.log" 2>&1

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

grpc_port="$(free_port)"
admin_port="$(free_port)"
while [[ "$admin_port" == "$grpc_port" ]]; do
  admin_port="$(free_port)"
done

env \
  -u TENUO_CONNECT_TOKEN \
  -u TENUO_CONTROL_PLANE_URL \
  -u TENUO_API_KEY \
  target/release/tenuo-openshell-middleware \
    --policy "$fixture/policy.json" \
    --listen "127.0.0.1:$grpc_port" \
    --admin-listen "127.0.0.1:$admin_port" \
    --insecure-dev \
    --allow-in-memory-replay \
    --receipt-key "$work_dir/receipt.key" \
    --receipt-log "$work_dir/receipts.jsonl" \
    >"$work_dir/middleware.log" 2>&1 &
middleware_pid="$!"

ready_url="http://127.0.0.1:$admin_port/ready"
for _ in $(seq 1 50); do
  if curl --silent --fail "$ready_url" >"$work_dir/ready"; then
    break
  fi
  if ! kill -0 "$middleware_pid" 2>/dev/null; then
    cat "$work_dir/middleware.log" >&2
    echo "middleware exited before becoming ready" >&2
    exit 1
  fi
  sleep 0.1
done

grep -Fx "ready" "$work_dir/ready" >/dev/null
test "$(curl --silent --fail "http://127.0.0.1:$admin_port/live")" = "ok"
curl --silent --fail "http://127.0.0.1:$admin_port/metrics" \
  | grep -F "tenuo_openshell_policy_version 1" >/dev/null
test -s "$work_dir/receipt.key"
test -s "$work_dir/receipts.pub"

echo "standalone onboarding smoke test passed"
