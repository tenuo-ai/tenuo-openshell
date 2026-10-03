#!/usr/bin/env bash
# NeMo Agent Toolkit ReAct agent under Tenuo, with a human approval step.
#
# The agent's MCP tools go through `tenuo-openshell-agent proxy`. Its warrant
# allows a staging read and a restart that needs one approval.
#
#   1. The agent reads the logs (allowed) and asks for a restart, which comes
#      back "Approval required" with a request hash.
#   2. An approver reviews the tool and arguments and approves them with
#      `tenuo-openshell approve`.
#   3. The agent runs again; the restart goes through with the approval.
#   4. A third run needs a new approval: each one authorizes one call.
#
# The MCP server verifies the warrant and approval again before it acts.
# Runs on the host without OpenShell; scripts/openshell-e2e.sh covers the
# sandbox path. Set NVIDIA_API_KEY and TENUO_EXAMPLE_LIVE=1 to use a hosted
# model (workflow.yml) instead of the scripted one; the model then decides
# which calls to make, so only the scripted run is asserted.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MCP_PORT="${TENUO_EXAMPLE_MCP_PORT:-18932}"
LLM_PORT=18080
PROXY_PORT=7415
WORK="$(mktemp -d)"
PIDS=()

cleanup() {
  local status=$?
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ "$status" == 0 ]]; then
    rm -rf "$WORK"
  else
    echo "logs retained in $WORK" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAIL $1" >&2
  for log in "$WORK"/*.log; do
    printf '\n--- %s ---\n' "$log" >&2
    tail -40 "$log" >&2
  done
  exit 1
}

for port in "$MCP_PORT" "$LLM_PORT" "$PROXY_PORT"; do
  if nc -z 127.0.0.1 "$port" 2>/dev/null; then
    fail "port $port is in use"
  fi
done

if [[ -z "${TENUO_SKIP_BUILD:-}" ]]; then
  cargo build --quiet --locked --manifest-path "$ROOT/Cargo.toml" --workspace --bins
fi
TARGET="$(cd "$ROOT" && cargo metadata --format-version=1 --no-deps | jq -er '.target_directory')/debug"
AGENT="$TARGET/tenuo-openshell-agent"
CLI="$TARGET/tenuo-openshell"

echo "INFO preparing a Python environment with NeMo Agent Toolkit 1.8"
uv venv --quiet --python 3.12 "$WORK/py"
uv pip install --quiet --python "$WORK/py/bin/python" \
  'nvidia-nat-core==1.8.0' 'nvidia-nat-mcp==1.8.0' 'nvidia-nat-langchain==1.8.0' 'tenuo==0.3.2'
NAT="$WORK/py/bin/nat"

# Issuer, orchestrator (task A), and approver keys, plus the trust policy.
"$TARGET/tenuo-demo-fixture" --output "$WORK/fixture" --sandbox-id example \
  --mcp-host 127.0.0.1 --mcp-port "$MCP_PORT" >"$WORK/fixture.log" 2>&1

export TENUO_HOLDER_KEY_FILE="$WORK/agent/holder.key"
export TENUO_WARRANT_FILE="$WORK/agent/warrant"
export TENUO_APPROVALS_DIR="$WORK/agent/approvals"
holder="$("$AGENT" keygen)"
"$CLI" warrant issue --holder "$holder" \
  --parent-key "$WORK/fixture/signers/task-a/key" \
  --parent-warrant "$WORK/fixture/warrants/task-a.cbor" \
  --ttl 600 \
  --capabilities '{
    "read_logs": {"service": "payments", "environment": "staging"},
    "restart_service": {"service": "payments", "environment": "staging",
                        "replicas": {"range": {"max": 5}}}
  }' | "$AGENT" install-warrant - >/dev/null
"$AGENT" status

EFFECTS="$WORK/effects.jsonl"
: >"$EFFECTS"
TENUO_DEMO_EFFECT_LOG="$EFFECTS" "$WORK/py/bin/python" "$ROOT/examples/demo/mcp_server.py" \
  --host 127.0.0.1 --port "$MCP_PORT" --policy "$WORK/fixture/policy.json" >"$WORK/mcp-server.log" 2>&1 &
PIDS+=($!)
python3 "$HERE/scripted_llm.py" --port "$LLM_PORT" >"$WORK/llm.log" 2>&1 &
PIDS+=($!)
"$AGENT" proxy --listen "127.0.0.1:$PROXY_PORT" \
  --upstream "http://127.0.0.1:$MCP_PORT/mcp" >"$WORK/proxy.log" 2>&1 &
PIDS+=($!)
for port in "$MCP_PORT" "$LLM_PORT" "$PROXY_PORT"; do
  for _ in $(seq 1 50); do
    nc -z 127.0.0.1 "$port" 2>/dev/null && break
    sleep 0.2
  done
  nc -z 127.0.0.1 "$port" 2>/dev/null || fail "service on port $port did not start"
done

config="$HERE/workflow-scripted.yml"
if [[ -n "${TENUO_EXAMPLE_LIVE:-}" ]]; then
  [[ -n "${NVIDIA_API_KEY:-}" ]] || fail "TENUO_EXAMPLE_LIVE needs NVIDIA_API_KEY"
  config="$HERE/workflow.yml"
fi

run_agent() {
  "$NAT" run --config_file "$config" --input "Payments is failing in staging. Investigate and fix it." \
    >"$WORK/$1.log" 2>&1 || fail "agent run $1"
}
restarts() {
  grep -c '"tool": "restart_service"' "$EFFECTS" || true
}

echo "INFO run 1: the agent reads the logs and asks for a restart"
run_agent run1
[[ -n "${TENUO_EXAMPLE_LIVE:-}" ]] && { echo "PASS live run completed; see $WORK/run1.log"; exit 0; }
grep -q '"tool": "read_logs"' "$EFFECTS" || fail "the read reached the MCP server"
[[ "$(restarts)" == 0 ]] || fail "the restart ran without an approval"
grep -q 'Approval required: request' "$WORK/run1.log" || fail "the agent saw the approval request"
echo "PASS read allowed; restart held for approval"

echo "INFO approver reviews the pending request"
"$AGENT" pending --json >"$WORK/pending.json"
request="$(jq -er '.[0].request_hash' "$WORK/pending.json")"
"$CLI" approve --pending "$WORK/pending.json" --request "$request" \
  --approver-key "$WORK/fixture/signers/approver/key" \
  --trusted-root "$(jq -er '.sandboxes.example.trusted_roots[0]' "$WORK/fixture/policy.json")" \
  --yes | "$AGENT" install-approval -

echo "INFO run 2: the same restart with the approval"
run_agent run2
[[ "$(restarts)" == 1 ]] || fail "the approved restart ran once"
echo "PASS approved restart ran"

echo "INFO run 3: the approval was single use"
run_agent run3
[[ "$(restarts)" == 1 ]] || fail "a used approval authorized another restart"
grep -q 'Approval required: request' "$WORK/run3.log" || fail "the third run needed a new approval"
echo "PASS a used approval does not authorize another restart"
echo "ALL PASS"
