#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/demo"
OPENSHELL_ROOT="${OPENSHELL_SOURCE:-$($ROOT/scripts/bootstrap-openshell.sh)}"
COMPUTE_DRIVER="${TENUO_DEMO_DRIVER:-docker}"
AUDIENCE="urn:openshell:extension:middleware:tenuo/authorization"
PINNED_SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor:0.1.2@sha256:d7b5264bb6bc56f4796e6fa3617b8e4a8d785be0b7293542efd8cc250b0fb67a"
PINNED_SANDBOX_RUNTIME_IMAGE="ghcr.io/nvidia/openshell/sandbox:0.1.2@sha256:bf4797b6c511f2d8ba02955dbba4bf76c1f0dd6d83531420c5408d5f1fb9d72f"

case "$COMPUTE_DRIVER" in
  docker | podman) ;;
  *)
    echo "TENUO_DEMO_DRIVER must be docker or podman" >&2
    exit 2
    ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_supported_runtime() {
  local version major
  if [[ "$COMPUTE_DRIVER" == "docker" ]]; then
    version="$(docker version --format '{{.Server.Version}}' 2>/dev/null)" || {
      echo "Docker daemon is not reachable" >&2
      exit 1
    }
    major="${version%%.*}"
    if [[ ! "$major" =~ ^[0-9]+$ || "$major" -lt 28 ]]; then
      echo "OpenShell requires Docker Desktop or Docker Engine 28.0+; found ${version:-unknown}" >&2
      exit 1
    fi
  else
    version="$(podman version --format '{{.Client.Version}}' 2>/dev/null)" || {
      echo "Podman service is not reachable" >&2
      exit 1
    }
    major="${version%%.*}"
    if [[ ! "$major" =~ ^[0-9]+$ || "$major" -lt 5 ]]; then
      echo "OpenShell requires Podman 5.x+; found ${version:-unknown}" >&2
      exit 1
    fi
  fi
}

detect_service_host() {
  local interface address
  if [[ -n "${TENUO_DEMO_HOST:-}" ]]; then
    printf '%s\n' "$TENUO_DEMO_HOST"
    return
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v route >/dev/null 2>&1 && command -v ipconfig >/dev/null 2>&1; then
    interface="$(route -n get default 2>/dev/null | awk '/interface:/ { print $2; exit }')"
    if [[ -n "$interface" ]]; then
      address="$(ipconfig getifaddr "$interface" 2>/dev/null || true)"
      if [[ -n "$address" ]]; then
        printf '%s\n' "$address"
        return
      fi
    fi
  fi
  if command -v ip >/dev/null 2>&1; then
    address="$(ip route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')"
    if [[ -n "$address" ]]; then
      printf '%s\n' "$address"
      return
    fi
  fi
  echo "could not detect a non-loopback IPv4 address; set TENUO_DEMO_HOST" >&2
  exit 1
}

port_is_free() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    ! lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1
  fi
}

choose_port_block() {
  local start offset ok
  for _ in {1..200}; do
    start=$((20000 + RANDOM % 20000))
    ok=1
    for ((offset = 0; offset < 6; offset++)); do
      if ! port_is_free "$((start + offset))"; then
        ok=0
        break
      fi
    done
    if [[ "$ok" == 1 ]]; then
      printf '%s\n' "$start"
      return
    fi
  done
  echo "failed to find six free ports" >&2
  exit 1
}

cargo_target_dir() {
  cargo metadata --format-version=1 --no-deps --manifest-path "$1" | jq -er '.target_directory'
}

openshell_cargo() {
  # Rustup selects OpenShell's pinned toolchain from its checkout only when the
  # command's working directory is inside that checkout.
  (cd "$OPENSHELL_ROOT" && cargo "$@")
}

SERVICE_HOST="$(detect_service_host)"
if [[ "$SERVICE_HOST" == "localhost" || "$SERVICE_HOST" == "::1" || "$SERVICE_HOST" == 127.* || "$SERVICE_HOST" == *:* ]]; then
  echo "TENUO_DEMO_HOST must be a non-loopback IPv4 address: $SERVICE_HOST" >&2
  exit 1
fi

PORT_BASE="$(choose_port_block)"
MIDDLEWARE_PORT="$PORT_BASE"
GATEWAY_PORT="$((PORT_BASE + 1))"
HEALTH_PORT="$((PORT_BASE + 2))"
UPSTREAM_PORT="$((PORT_BASE + 3))"
A2A_PORT="$((PORT_BASE + 4))"
ADMIN_PORT="$((PORT_BASE + 5))"
GATEWAY_ENDPOINT="http://127.0.0.1:$GATEWAY_PORT"
GATEWAY_BIND_ADDRESS="127.0.0.1"
SUPERVISOR_GRPC_ENDPOINT=""

RUN_DIR="$(mktemp -d)"
LOG_DIR="$RUN_DIR/logs"
JWT_DIR="$RUN_DIR/jwt"
TLS_DIR="$RUN_DIR/tls"
FIXTURE_DIR="$RUN_DIR/fixtures"
GATEWAY_CONFIG="$RUN_DIR/gateway.toml"
SANDBOX_POLICY="$RUN_DIR/openshell-policy.yaml"
EFFECT_LOG="$RUN_DIR/effects.jsonl"
OBS="$RUN_DIR/observations.jsonl"
GATEWAY_DB="$RUN_DIR/gateway.db"
SETUP_LOG="$LOG_DIR/setup.log"
GATEWAY_LOG="$LOG_DIR/gateway.log"
MIDDLEWARE_LOG="$LOG_DIR/middleware.log"
UPSTREAM_LOG="$LOG_DIR/upstream.log"
FIXTURE_LOG="$LOG_DIR/fixture.log"
RUN_ID="tenuo-demo-$$-$RANDOM"
RESULTS_DIR="$ROOT/results"
SANDBOX_NAME="tn-$$-$RANDOM"
SUPERVISOR_IMAGE="${TENUO_DEMO_SUPERVISOR_IMAGE:-$PINNED_SUPERVISOR_IMAGE}"
SANDBOX_RUNTIME_IMAGE="${TENUO_DEMO_SANDBOX_RUNTIME_IMAGE:-$PINNED_SANDBOX_RUNTIME_IMAGE}"
WORKLOAD_IMAGE="${TENUO_DEMO_WORKLOAD_IMAGE:-localhost/tenuo-openshell/workload:$RUN_ID}"
SANDBOX_CREATED=0
RECEIPT_DIR="$RUN_DIR/receipts"
RECEIPT_KEY="$RUN_DIR/secrets/openshell-receipt.key"
mkdir -p "$LOG_DIR" "$JWT_DIR" "$TLS_DIR" "$FIXTURE_DIR" "$RECEIPT_DIR" "$RUN_DIR/secrets"
mkdir -p "$RESULTS_DIR/evidence"
: >"$EFFECT_LOG"
: >"$OBS"
: >"$GATEWAY_LOG"

dump_logs() {
  local label log_file
  for label in setup gateway middleware upstream fixture; do
    case "$label" in
      setup) log_file="$SETUP_LOG" ;;
      gateway) log_file="$GATEWAY_LOG" ;;
      middleware) log_file="$MIDDLEWARE_LOG" ;;
      upstream) log_file="$UPSTREAM_LOG" ;;
      fixture) log_file="$FIXTURE_LOG" ;;
    esac
    printf '\n--- %s: %s ---\n' "$label" "$log_file" >&2
    [[ -f "$log_file" ]] && tail -200 "$log_file" >&2
  done
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$SANDBOX_CREATED" == 1 && -n "${CLI+x}" ]]; then
    "${CLI[@]}" sandbox delete "$SANDBOX_NAME" >>"$SETUP_LOG" 2>&1 || true
    if [[ -n "${CHILD_SANDBOX_NAME:-}" ]]; then
      "${CLI[@]}" sandbox delete "$CHILD_SANDBOX_NAME" >>"$SETUP_LOG" 2>&1 || true
    fi
  fi
  for pid_name in GATEWAY_PID MIDDLEWARE_PID UPSTREAM_PID; do
    local pid="${!pid_name:-}"
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  # The workload image is tagged per run. Remove it unless the caller supplied
  # one; a sandbox still being torn down can hold it, so failure is ignored.
  if [[ -z "${TENUO_DEMO_WORKLOAD_IMAGE:-}" ]]; then
    "$COMPUTE_DRIVER" rmi "$WORKLOAD_IMAGE" >/dev/null 2>&1 || true
  fi
  if [[ "$status" == 0 ]]; then
    rm -rf "$RUN_DIR"
  else
    echo "demo artifacts retained in $RUN_DIR" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAIL $1" >&2
  dump_logs
  exit 1
}

run_step() {
  local label="$1"
  shift
  printf 'INFO %s\n' "$label"
  printf '\n== %s ==\n+' "$label" >>"$SETUP_LOG"
  printf ' %q' "$@" >>"$SETUP_LOG"
  printf '\n' >>"$SETUP_LOG"
  "$@" >>"$SETUP_LOG" 2>&1 || fail "$label"
}

generate_security_material() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=Tenuo demo CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$TLS_DIR/ca-key.pem" \
    -out "$TLS_DIR/ca.pem" >/dev/null 2>&1
  cat >"$TLS_DIR/server.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions = server
prompt = no
[dn]
CN = $SERVICE_HOST
[server]
subjectAltName = IP:$SERVICE_HOST
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
  openssl req -new -newkey rsa:2048 -nodes \
    -config "$TLS_DIR/server.cnf" \
    -keyout "$TLS_DIR/server-key.pem" \
    -out "$TLS_DIR/server.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 \
    -in "$TLS_DIR/server.csr" \
    -CA "$TLS_DIR/ca.pem" \
    -CAkey "$TLS_DIR/ca-key.pem" \
    -CAcreateserial \
    -extfile "$TLS_DIR/server.cnf" \
    -extensions server \
    -out "$TLS_DIR/server.pem" >/dev/null 2>&1
}

write_gateway_config() {
  local with_middleware="${1:-1}"
  cat >"$GATEWAY_CONFIG" <<EOF
[openshell]
version = 2

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT_DIR/signing.pem"
public_key_path = "$JWT_DIR/public.pem"
kid_path = "$JWT_DIR/kid"
gateway_id = "$RUN_ID"
ttl_secs = 300
EOF
  if [[ "$with_middleware" == 1 ]]; then
    cat >>"$GATEWAY_CONFIG" <<EOF

[[openshell.supervisor.middleware]]
name = "tenuo/authorization"
grpc_endpoint = "https://$SERVICE_HOST:$MIDDLEWARE_PORT"
tls_ca_cert_path = "$TLS_DIR/ca.pem"
audience = "$AUDIENCE"
max_payload_bytes = 262144
timeout = "2s"
EOF
  fi
  cat >>"$GATEWAY_CONFIG" <<EOF

[openshell.drivers.$COMPUTE_DRIVER]
supervisor_image = "$SUPERVISOR_IMAGE"
sandbox_runtime_image = "$SANDBOX_RUNTIME_IMAGE"
default_image = "$WORKLOAD_IMAGE"
EOF
  if [[ -n "$SUPERVISOR_GRPC_ENDPOINT" ]]; then
    printf 'grpc_endpoint = "%s"\n' "$SUPERVISOR_GRPC_ENDPOINT" >>"$GATEWAY_CONFIG"
  fi
  sed "s/__UPSTREAM_PORT__/$UPSTREAM_PORT/g" "$EXAMPLE_DIR/openshell-policy.yaml" >"$SANDBOX_POLICY"
}

configure_supervisor_reachability() {
  if [[ "$COMPUTE_DRIVER" != "docker" ]]; then
    return
  fi
  local operating_system
  operating_system="$(docker info --format '{{.OperatingSystem}}')"
  if [[ "$operating_system" != *"Docker Desktop"* ]]; then
    return
  fi
  # The supervisor container uses host networking. On Docker Desktop that
  # network is the Linux VM, so the gateway's loopback is not reachable.
  # OpenShell uses grpc_endpoint for that callback.
  GATEWAY_BIND_ADDRESS="0.0.0.0"
  SUPERVISOR_GRPC_ENDPOINT="http://$SERVICE_HOST:$GATEWAY_PORT"
}

start_middleware() {
  TENUO_DECISION_LOG=1 "$MIDDLEWARE_BIN" \
    --policy "$FIXTURE_DIR/policy.json" \
    --listen "0.0.0.0:$MIDDLEWARE_PORT" \
    --tls-cert "$TLS_DIR/server.pem" \
    --tls-key "$TLS_DIR/server-key.pem" \
    --openshell-jwt-public-key "$JWT_DIR/public.pem" \
    --openshell-gateway-id "$RUN_ID" \
    --openshell-jwt-key-id "$RUN_ID" \
    --allow-in-memory-replay \
    --audience "$AUDIENCE" \
    --admin-listen "127.0.0.1:$ADMIN_PORT" \
    --evaluate-results \
    --receipt-key "$RECEIPT_KEY" \
    --receipt-log "$RECEIPT_DIR/openshell.jsonl" >>"$MIDDLEWARE_LOG" 2>&1 &
  MIDDLEWARE_PID=$!
}

wait_for_port() {
  local pid="$1" host="$2" port="$3" label="$4"
  for _ in {1..90}; do
    kill -0 "$pid" 2>/dev/null || fail "$label exited"
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      printf 'INFO %s is ready\n' "$label"
      return
    fi
    sleep 1
  done
  fail "$label is not reachable"
}

prepare_destination_python() {
  if [[ -n "${TENUO_DEMO_PYTHON:-}" ]]; then
    DEMO_PYTHON="$TENUO_DEMO_PYTHON"
    return
  fi
  python3 -m venv "$RUN_DIR/py"
  "$RUN_DIR/py/bin/python" -m pip install -q 'tenuo[a2a]==0.3.1' 'uvicorn>=0.30,<1' 'nvidia-nat-core>=1.8,<1.9'
  "$RUN_DIR/py/bin/python" -m pip install -q --no-deps "$ROOT/python/nemo-agent-toolkit-tenuo"
  DEMO_PYTHON="$RUN_DIR/py/bin/python"
}

start_upstream() {
  env TENUO_DEMO_EFFECT_LOG="$EFFECT_LOG" \
    TENUO_DEMO_RECEIPT_DIR="$RECEIPT_DIR" \
    "$DEMO_PYTHON" "$EXAMPLE_DIR/mcp_server.py" \
    --port "$UPSTREAM_PORT" \
    --policy "$FIXTURE_DIR/policy.json" >"$UPSTREAM_LOG" 2>&1 &
  UPSTREAM_PID=$!
}

start_gateway() {
  env -u OPENSHELL_DRIVERS -u OPENSHELL_COMPUTE_DRIVER "$GATEWAY_BIN" \
    --compute-driver "$COMPUTE_DRIVER" \
    --config "$GATEWAY_CONFIG" \
    --bind-address "$GATEWAY_BIND_ADDRESS" \
    --port "$GATEWAY_PORT" \
    --health-port "$HEALTH_PORT" \
    --metrics-port 0 \
    --log-level info \
    --disable-tls \
    --db-url "sqlite://$GATEWAY_DB" >>"$GATEWAY_LOG" 2>&1 &
  GATEWAY_PID=$!
}

wait_for_gateway() {
  for _ in {1..90}; do
    kill -0 "$GATEWAY_PID" 2>/dev/null || fail "OpenShell gateway exited"
    if curl -fsS "http://127.0.0.1:$HEALTH_PORT/healthz" >/dev/null 2>&1; then
      printf 'INFO authenticated OpenShell gateway is ready\n'
      return
    fi
    sleep 1
  done
  fail "OpenShell gateway is not ready"
}

now_us() {
  python3 -c 'import time; print(int(time.time() * 1000000))'
}

decision_us_for() {
  local id="$1" log="$2" line
  line="$(grep -F "tenuo_decision request_id=${id} " "$log" 2>/dev/null | tail -1 || true)"
  [[ -n "$line" ]] || return 1
  sed -n 's/.*decision_us=\([0-9][0-9]*\).*/\1/p' <<<"$line"
}

record_obs() {
  jq -nc \
    --arg scenario "$1" \
    --arg run "$2" \
    --arg outcome "$3" \
    --arg point "$4" \
    --arg reason "$5" \
    --argjson decision_us "$6" \
    --argjson e2e_us "$7" \
    '{scenario:$scenario,run:$run,outcome:$outcome,point:$point,reason:$reason,decision_us:$decision_us,e2e_us:$e2e_us}' >>"$OBS"
}

send_request() {
  local fixture="$1"
  local sandbox="${2:-$SANDBOX_NAME}"
  local body start end
  body="$(jq -c . "$fixture")"
  start="$(now_us)"
  "${CLI[@]}" sandbox exec --name "$sandbox" --no-tty -- \
    curl -sS -i --max-time 20 "http://host.openshell.internal:$UPSTREAM_PORT/mcp" \
      --header 'content-type: application/json' \
      --header 'accept: application/json, text/event-stream' \
      --header 'mcp-protocol-version: 2025-11-25' \
      --data-binary "$body"
  end="$(now_us)"
  LAST_E2E_US=$((end - start))
}

expect_allow() {
  local fixture="$1"
  local marker="$2"
  local label="$3"
  local sandbox="${4:-$SANDBOX_NAME}"
  local scenario="${5:-}"
  local output="$RUN_DIR/$(basename "$fixture").out"
  local id decision_us
  send_request "$fixture" "$sandbox" >"$output" 2>>"$SETUP_LOG" || fail "$label completes"
  grep -Fq '200 OK' "$output" || fail "$label returns 200"
  grep -Fq "$marker" "$output" || fail "$label effect response is returned"
  printf 'PASS %s\n' "$label"
  if [[ -n "$scenario" ]]; then
    id="$(jq -r .id "$fixture")"
    decision_us="$(decision_us_for "$id" "$MIDDLEWARE_LOG")" || fail "$scenario has no decision timing"
    record_obs "$scenario" "openshell+tenuo" "allow" "openshell" "" "$decision_us" "$LAST_E2E_US"
  fi
}

expect_deny() {
  local fixture="$1"
  local reason="$2"
  local label="$3"
  local sandbox="${4:-$SANDBOX_NAME}"
  local scenario="${5:-}"
  local output="$RUN_DIR/$(basename "$fixture").out"
  local id decision_us
  send_request "$fixture" "$sandbox" >"$output" 2>>"$SETUP_LOG" || fail "$label returns a response"
  grep -Fq '403 Forbidden' "$output" || fail "$label is denied"
  grep -Fq "$reason" "$output" || fail "$label reason is $reason"
  printf 'PASS %s\n' "$label"
  if [[ -n "$scenario" ]]; then
    id="$(jq -r .id "$fixture")"
    decision_us="$(decision_us_for "$id" "$MIDDLEWARE_LOG")" || fail "$scenario has no decision timing"
    record_obs "$scenario" "openshell+tenuo" "deny" "openshell" "$reason" "$decision_us" "$LAST_E2E_US"
  fi
}

# The production path. `tenuo-openshell provision` generates the holder key in
# the sandbox and installs a read-only warrant that Task A delegates to it. An
# unmodified MCP SDK client then talks to the loopback signing proxy. The
# sandbox policy lets only curl and the proxy reach the MCP server.
mcp_client_run() {
  local sandbox="$1"
  local run="$2"
  local output="$RUN_DIR/mcp-client-$sandbox.json"
  local before start end decision_us line
  if [[ "$run" == "openshell+tenuo" ]]; then
    env -u OPENSHELL_SANDBOX_POLICY "$TENUO_TARGET/debug/tenuo-openshell" provision \
      --sandbox "$sandbox" \
      --parent-key "$FIXTURE_DIR/signers/task-a/key" \
      --parent-warrant "$FIXTURE_DIR/warrants/task-a.cbor" \
      --capabilities '{"read_logs": {"service": "payments", "environment": "staging"}}' \
      --ttl 300 \
      --openshell "$CLI_BIN" \
      --gateway-endpoint "$GATEWAY_ENDPOINT" >>"$SETUP_LOG" 2>&1 || fail "provision the sandbox holder"
    before="$(wc -l <"$MIDDLEWARE_LOG")"
    start="$(now_us)"
    "${CLI[@]}" sandbox exec --name "$sandbox" --no-tty -- sh -c '
      tenuo-openshell-agent proxy --upstream "http://host.openshell.internal:$1/mcp" 2>"$HOME/proxy.log" &
      proxy=$!
      sleep 1
      NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
        /usr/local/lib/tenuo-demo/bin/python /usr/local/lib/tenuo-demo/mcp_client.py http://127.0.0.1:7415/mcp
      status=$?
      kill "$proxy"
      exit "$status"
    ' sh "$UPSTREAM_PORT" 2>>"$SETUP_LOG" | tr -d '\r' | tail -1 >"$output" || fail "MCP client in the sandbox"
    end="$(now_us)"
  else
    start="$(now_us)"
    "${CLI[@]}" sandbox exec --name "$sandbox" --no-tty -- \
      /usr/local/lib/tenuo-demo/bin/python /usr/local/lib/tenuo-demo/mcp_client.py \
      "http://host.openshell.internal:$UPSTREAM_PORT/mcp" 2>>"$SETUP_LOG" \
      | tr -d '\r' | tail -1 >"$output" || fail "comparison MCP client in the sandbox"
    end="$(now_us)"
  fi
  LAST_E2E_US=$((end - start))
  jq -e '.read_logs.outcome == "allow" and .read_logs.text == "read payments logs in staging"' "$output" >/dev/null \
    || fail "$run MCP client read reached the effect"
  if [[ "$run" == "openshell+tenuo" ]]; then
    jq -e '.restart_service.outcome == "deny" and .restart_service.reason == "tool-not-authorized" and .restart_service.source == "agent"' \
      "$output" >/dev/null || fail "MCP client restart was denied in the sandbox"
    line="$(tail -n +"$((before + 1))" "$MIDDLEWARE_LOG" | grep -F 'tenuo_decision ' | grep -F 'outcome=allow' | tail -1 || true)"
    [[ -n "$line" ]] || fail "MCP client read has no middleware decision"
    decision_us="$(sed -n 's/.*decision_us=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    record_obs "MCP client read" "$run" "allow" "openshell" "" "$decision_us" "$LAST_E2E_US"
    record_obs "MCP client restart" "$run" "deny" "sandbox agent" "tool-not-authorized" 0 0
    printf 'PASS unmodified MCP client read through the signing proxy\n'
    printf 'PASS unmodified MCP client restart was denied in the sandbox\n'
  else
    jq -e '.restart_service.outcome == "allow"' "$output" >/dev/null \
      || fail "comparison MCP client restart reached the effect"
    record_obs "MCP client read" "$run" "allow" "openshell" "" 0 "$LAST_E2E_US"
    record_obs "MCP client restart" "$run" "allow" "sandbox agent" "" 0 0
    printf 'PASS openshell-only MCP client read and restart\n'
  fi
}

# Sign a staging payments read with JSON-RPC id $2 inside the sandbox, using
# the holder key and warrant `mcp_client_run` provisioned, and send it with
# curl. The explicit id keeps receipts matchable.
sandbox_signed_call() {
  local sandbox="$1" id="$2"
  "${CLI[@]}" sandbox exec --name "$sandbox" --no-tty -- sh -c '
    set -e
    work="$(mktemp -d)"
    printf "%s" "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_logs\",\"arguments\":{\"service\":\"payments\",\"environment\":\"staging\"}}}" \
      | tenuo-openshell-agent sign >"$work/body.json"
    curl -sS -i --max-time 20 "http://host.openshell.internal:$2/mcp" \
      --header "content-type: application/json" \
      --header "accept: application/json, text/event-stream" \
      --header "mcp-protocol-version: 2025-11-25" \
      --data-binary @"$work/body.json"
  ' sh "$id" "$UPSTREAM_PORT"
}

# A higher policy version limits results in the first sandbox to 64 bytes. The
# sandbox signs a read whose result is larger. The read runs and OpenShell
# withholds its result, because the upstream call happens before the response.
result_size_limit() {
  local id=17 output="$RUN_DIR/result-limit.out" version
  jq --arg sandbox "$SANDBOX_ID" \
    '.version = ((.version // 1) + 1) | .sandboxes[$sandbox].max_result_bytes = 64' \
    "$FIXTURE_DIR/policy.json" >"$FIXTURE_DIR/policy.next.json"
  mv "$FIXTURE_DIR/policy.next.json" "$FIXTURE_DIR/policy.json"
  version="$(jq -r .version "$FIXTURE_DIR/policy.json")"
  for _ in {1..30}; do
    if curl -fsS "http://127.0.0.1:$ADMIN_PORT/metrics" 2>/dev/null \
      | grep -Fxq "tenuo_openshell_policy_version $version"; then
      break
    fi
    sleep 1
  done
  curl -fsS "http://127.0.0.1:$ADMIN_PORT/metrics" | grep -Fxq "tenuo_openshell_policy_version $version" \
    || fail "the result limit policy was loaded"
  sandbox_signed_call "$SANDBOX_NAME" "$id" \
    >"$output" 2>>"$SETUP_LOG" || fail "oversized result returns a response"
  grep -Fq '403 Forbidden' "$output" || fail "oversized result was withheld"
  grep -Fq 'tenuo_result_too_large' "$output" || fail "oversized result reason is tenuo_result_too_large"
  grep -Fq "read payments logs in staging" "$output" && fail "oversized result reached the sandbox"
  jq -se 'length == 7 and (last | .tool == "read_logs")' "$EFFECT_LOG" >/dev/null \
    || fail "the read behind the withheld result ran"
  grep -Fq "tenuo_result request_id=$id " "$MIDDLEWARE_LOG" || fail "oversized result has a result decision"
  printf 'PASS oversized result was withheld after the read ran\n'
}

record_widen() {
  local line decision_us
  line="$(grep -F "tenuo_decision request_id=widen " "$FIXTURE_LOG" | tail -1 || true)"
  [[ -n "$line" ]] || fail "attenuation has no decision timing"
  decision_us="$(sed -n 's/.*decision_us=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
  record_obs "wider child" "openshell+tenuo" "refused" "attenuation" "attenuation-refused" "$decision_us" 0
}

stop_one() {
  local name="$1"
  local pid="${!name:-}"
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    unset "$name"
  fi
}

start_accept_all() {
  env TENUO_DEMO_EFFECT_LOG="$CONTROL_EFFECT" \
    "$DEMO_PYTHON" "$EXAMPLE_DIR/mcp_server.py" \
    --accept-all \
    --port "$UPSTREAM_PORT" \
    --policy "$FIXTURE_DIR/policy.json" >"$LOG_DIR/upstream-control.log" 2>&1 &
  UPSTREAM_PID=$!
}

run_suite() {
  # Scenario names match examples/demo/outcome_matrix.py.
  record_widen
  expect_allow "$FIXTURE_DIR/task-a-read.json" "read payments logs in staging" \
    "task A read reached the effect" "" "task A read"
  expect_allow "$FIXTURE_DIR/task-b-read.json" "read payments logs in staging" \
    "task B read reached the effect" "" "task B read"
  expect_allow "$FIXTURE_DIR/task-a-restart.json" "restarted payments in staging" \
    "task A approved restart reached the effect" "" "approved restart"
  expect_deny "$FIXTURE_DIR/task-a-restart-repeat.json" "tenuo_approval_replayed" \
    "repeated approved restart was denied" "" "repeated approved restart"
  expect_deny "$FIXTURE_DIR/task-a-unapproved.json" "tenuo_approval_required" \
    "restart without its approval was denied" "" "restart without approval"
  expect_deny "$FIXTURE_DIR/task-a-approval-mismatch.json" "tenuo_invalid_authority" \
    "approval for replicas=3 did not cover replicas=5" "" "approval does not cover replicas 5"
  expect_deny "$FIXTURE_DIR/task-b-restart.json" "tenuo_tool_denied" \
    "task B restart was denied" "" "task B restart"
  expect_deny "$FIXTURE_DIR/copied-warrant.json" "tenuo_invalid_authority" \
    "task A's warrant signed by task B was denied" "" "copied warrant"
  expect_deny "$FIXTURE_DIR/task-a-constraint.json" "tenuo_constraint_denied" \
    "task A production read was denied" "" "production read"
  expect_deny "$FIXTURE_DIR/task-a-replicas.json" "tenuo_constraint_denied" \
    "task A replicas=8 restart was denied" "" "replicas 8"
  expect_deny "$FIXTURE_DIR/missing-warrant.json" "tenuo_missing_warrant" \
    "missing authority was denied" "" "missing warrant"
  expect_allow "$FIXTURE_DIR/delegated-read.json" "read payments logs in staging" \
    "narrowed warrant read reached the effect" "$CHILD_SANDBOX_NAME" "narrowed read"
  expect_deny "$FIXTURE_DIR/delegated-restart.json" "tenuo_tool_denied" \
    "narrowed warrant restart was denied" "$CHILD_SANDBOX_NAME" "narrowed restart"
  grep -Fxq 'attenuation refused' "$FIXTURE_DIR/widen-refused.txt" \
    || fail "the narrowed warrant could be widened"
  mcp_client_run "$SANDBOX_NAME" "openshell+tenuo"

  jq -se '
    length == 5
    and ([.[] | select(.tool == "read_logs" and .arguments.service == "payments" and .arguments.environment == "staging")] | length == 4)
    and ([.[] | select(.tool == "restart_service" and .arguments.service == "payments" and .arguments.environment == "staging" and .arguments.replicas == 3)] | length == 1)
    and ([.[] | select(.arguments.service == "identity" or .arguments.environment == "production" or .arguments.replicas == 8 or .arguments.replicas == 5)] | length == 0)
  ' "$EFFECT_LOG" >/dev/null || fail "effect server observed only the five authorized calls"

  expect_destination_deny "$FIXTURE_DIR/task-b-restart.json" "direct task B restart" "direct task B restart"
  expect_destination_deny "$FIXTURE_DIR/missing-warrant.json" "direct missing warrant" "direct missing warrant"
  expect_destination_deny "$FIXTURE_DIR/delegated-restart.json" "direct narrowed restart" "direct narrowed restart"
  jq -se 'length == 5' "$EFFECT_LOG" >/dev/null || fail "direct denials must not reach the effect"
  direct_allow="$(curl -sS --max-time 20 "http://127.0.0.1:$UPSTREAM_PORT/mcp" \
    --header 'content-type: application/json' \
    --data-binary @"$FIXTURE_DIR/task-a-read.json")"
  jq -e '.result.content[0].text == "read payments logs in staging"' <<<"$direct_allow" >/dev/null \
    || fail "direct task A read is authorized by the destination"
  jq -se 'length == 6' "$EFFECT_LOG" >/dev/null || fail "direct authorized read must reach the effect"
  result_size_limit
  local denial_out="$RUN_DIR/local-denial.out" denial_line denial_us
  "$DEMO_PYTHON" "$EXAMPLE_DIR/local_denial.py" \
    --policy "$FIXTURE_DIR/policy.json" \
    --warrant "$FIXTURE_DIR/warrants/task-b.cbor" \
    --holder-key "$FIXTURE_DIR/signers/task-b/key" \
    --receipt-dir "$RECEIPT_DIR" \
    --request-id 14 | tee "$denial_out" || fail "in-process denial"
  denial_line="$(grep -F "tenuo_decision request_id=14 " "$denial_out" | tail -1)"
  [[ -n "$denial_line" ]] || fail "in-process denial has no decision timing"
  denial_us="$(sed -n 's/.*decision_us=\([0-9][0-9]*\).*/\1/p' <<<"$denial_line")"
  record_obs "in-process task B restart" "openshell+tenuo" "deny" "agent-toolkit" "tool_denied" "$denial_us" 0
  "$DEMO_PYTHON" "$EXAMPLE_DIR/audit_receipts.py" \
    --dir "$RECEIPT_DIR" \
    --policy "$FIXTURE_DIR/policy.json" \
    --exporter "$MIDDLEWARE_BIN" \
    --demo | tee "$RESULTS_DIR/evidence/receipt-audit.txt" || fail "offline receipt verification"
  "$MIDDLEWARE_BIN" receipts export \
    --log "$RECEIPT_DIR/openshell.jsonl" \
    --verify-with "$RECEIPT_DIR/openshell.pub" >"$RESULTS_DIR/evidence/openshell-receipts.json" \
    || fail "authorization receipt export"
  "$MIDDLEWARE_BIN" receipts export \
    --log "$RECEIPT_DIR/openshell.results.jsonl" \
    --verify-with "$RECEIPT_DIR/openshell.pub" >"$RESULTS_DIR/evidence/openshell-results.json" \
    || fail "result receipt export"
  jq -se '
    ([.[] | select(.outcome == "delivered")] | length == 5)
    and ([.[] | select(.outcome == "blocked" and .decision_code == "tenuo_result_too_large" and .request_id == "17")] | length == 1)
  ' "$RESULTS_DIR/evidence/openshell-results.json" >/dev/null || fail "result receipts cover the allowed calls"
  printf 'PASS receipts export as JSON lines for log pipelines\n'
  "$DEMO_PYTHON" "$ROOT/examples/interoperability/a2a_handoff.py" \
    --port "$A2A_PORT" \
    --output "$RESULTS_DIR/evidence/a2a-handoff.json" || fail "A2A authority handoff"
  run_control
  run_timing
  printf 'ALL PASS both runs were recorded and the receipts verify offline\n'
}

expect_destination_deny() {
  local fixture="$1"
  local label="$2"
  local scenario="${3:-}"
  local start end body id line decision_us reason
  start="$(now_us)"
  body="$(curl -sS --max-time 20 "http://127.0.0.1:$UPSTREAM_PORT/mcp" \
    --header 'content-type: application/json' \
    --data-binary @"$fixture")"
  end="$(now_us)"
  LAST_E2E_US=$((end - start))
  jq -e '.error.code == -32001 and .error.message == "Authorization denied" and (.error | keys | length == 2)' <<<"$body" >/dev/null \
    || fail "$label is denied by the destination"
  printf 'PASS %s\n' "$label"
  if [[ -n "$scenario" ]]; then
    id="$(jq -r .id "$fixture")"
    line="$(grep -F "tenuo_decision request_id=${id} " "$UPSTREAM_LOG" | tail -1 || true)"
    [[ -n "$line" ]] || fail "$scenario has no destination timing"
    decision_us="$(sed -n 's/.*decision_us=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    reason="$(sed -n 's/.*reason=\([^ ]*\).*/\1/p' <<<"$line")"
    record_obs "$scenario" "openshell+tenuo" "deny" "destination" "$reason" "$decision_us" "$LAST_E2E_US"
  fi
}

control_allow() {
  local scenario="$1"
  local fixture="$2"
  local marker="$3"
  local sandbox="${4:-$SANDBOX_NAME}"
  local point="${5:-openshell}"
  local output="$RUN_DIR/control-$(basename "$fixture").out"
  send_request "$fixture" "$sandbox" >"$output" 2>>"$SETUP_LOG" || fail "control $scenario completes"
  grep -Fq '200 OK' "$output" || fail "control $scenario returns 200"
  grep -Fq "$marker" "$output" || fail "control $scenario reaches the effect"
  record_obs "$scenario" "openshell-only" "allow" "$point" "" 0 "$LAST_E2E_US"
  printf 'PASS openshell-only %s\n' "$scenario"
}

control_direct() {
  local scenario="$1"
  local fixture="$2"
  local start end body
  start="$(now_us)"
  body="$(curl -sS --max-time 20 "http://127.0.0.1:$UPSTREAM_PORT/mcp" \
    --header 'content-type: application/json' \
    --data-binary @"$fixture")"
  end="$(now_us)"
  jq -e '.result.content[0].text != null' <<<"$body" >/dev/null \
    || fail "control $scenario reaches the effect"
  record_obs "$scenario" "openshell-only" "allow" "destination" "" 0 "$((end - start))"
  printf 'PASS openshell-only %s\n' "$scenario"
}

run_control() {
  printf 'INFO repeating the calls with warrant checks removed\n'
  "${CLI[@]}" sandbox delete "$SANDBOX_NAME" >>"$SETUP_LOG" 2>&1 || fail "delete the first sandbox"
  "${CLI[@]}" sandbox delete "$CHILD_SANDBOX_NAME" >>"$SETUP_LOG" 2>&1 || fail "delete the second sandbox"
  stop_one GATEWAY_PID
  stop_one MIDDLEWARE_PID
  stop_one UPSTREAM_PID

  CONTROL_EFFECT="$RUN_DIR/control-effects.jsonl"
  : >"$CONTROL_EFFECT"
  start_accept_all
  wait_for_port "$UPSTREAM_PID" "$SERVICE_HOST" "$UPSTREAM_PORT" "accept-all effect server"
  write_gateway_config 0
  GATEWAY_DB="$RUN_DIR/gateway-control.db"
  start_gateway
  wait_for_gateway
  if grep -Fq 'tenuo/authorization' "$GATEWAY_CONFIG"; then
    fail "the comparison gateway still registers Tenuo"
  fi
  # The tool rules stay. The middleware block has to go with the registration:
  # OpenShell rejects a sandbox policy that names an unregistered middleware.
  python3 - "$EXAMPLE_DIR/openshell-policy.yaml" "$RUN_DIR/openshell-only-policy.yaml" "$UPSTREAM_PORT" <<'PY'
import sys
from pathlib import Path
source, dest, port = sys.argv[1:]
lines = Path(source).read_text(encoding="utf-8").splitlines()
kept = []
skip = False
for line in lines:
    if line.startswith("network_middlewares:"):
        skip = True
        continue
    if skip and line and not line.startswith(" "):
        skip = False
    if not skip:
        kept.append(line.replace("__UPSTREAM_PORT__", port))
        # Without Tenuo there is no signing proxy; the client calls MCP itself.
        if line.strip() == "- path: /usr/local/bin/tenuo-openshell-agent":
            kept.append(line.replace("/usr/local/bin/tenuo-openshell-agent", "/usr/bin/python3*"))
Path(dest).write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")
PY
  if grep -Fq 'tenuo/authorization' "$RUN_DIR/openshell-only-policy.yaml"; then
    fail "the comparison sandbox policy still names Tenuo"
  fi
  SANDBOX_POLICY="$RUN_DIR/openshell-only-policy.yaml"

  SANDBOX_NAME="n2-$$-$RANDOM"
  CHILD_SANDBOX_NAME="c2-$$-$RANDOM"
  "${CLI[@]}" sandbox create --name "$SANDBOX_NAME" --policy "$SANDBOX_POLICY" --output json --no-tty --detach -- sleep infinity >>"$SETUP_LOG" 2>&1 \
    || fail "comparison sandbox creation"
  "${CLI[@]}" sandbox create --name "$CHILD_SANDBOX_NAME" --policy "$SANDBOX_POLICY" --output json --no-tty --detach -- sleep infinity >>"$SETUP_LOG" 2>&1 \
    || fail "comparison child sandbox creation"

  control_allow "task A read" "$FIXTURE_DIR/task-a-read.json" "read payments logs in staging"
  control_allow "task B read" "$FIXTURE_DIR/task-b-read.json" "read payments logs in staging"
  control_allow "approved restart" "$FIXTURE_DIR/task-a-restart.json" "restarted payments in staging"
  control_allow "repeated approved restart" "$FIXTURE_DIR/task-a-restart-repeat.json" "restarted payments in staging"
  control_allow "restart without approval" "$FIXTURE_DIR/task-a-unapproved.json" "restarted payments in staging"
  control_allow "approval does not cover replicas 5" "$FIXTURE_DIR/task-a-approval-mismatch.json" "restarted payments in staging"
  control_allow "task B restart" "$FIXTURE_DIR/task-b-restart.json" "restarted payments in staging"
  control_allow "copied warrant" "$FIXTURE_DIR/copied-warrant.json" "restarted payments in staging"
  control_allow "production read" "$FIXTURE_DIR/task-a-constraint.json" "read payments logs in staging"
  control_allow "replicas 8" "$FIXTURE_DIR/task-a-replicas.json" "restarted payments in staging"
  control_allow "missing warrant" "$FIXTURE_DIR/missing-warrant.json" "restarted payments in staging"
  control_allow "narrowed read" "$FIXTURE_DIR/delegated-read.json" "read payments logs in staging" "$CHILD_SANDBOX_NAME"
  control_allow "narrowed restart" "$FIXTURE_DIR/delegated-restart.json" "restarted payments in staging" "$CHILD_SANDBOX_NAME"
  mcp_client_run "$SANDBOX_NAME" "openshell-only"
  control_direct "direct task B restart" "$FIXTURE_DIR/task-b-restart.json"
  control_direct "direct missing warrant" "$FIXTURE_DIR/missing-warrant.json"
  control_direct "direct narrowed restart" "$FIXTURE_DIR/delegated-restart.json"
  record_obs "wider child" "openshell-only" "not checked" "attenuation" "" 0 0
  printf 'PASS openshell-only wider child was not checked\n'

  jq -se '
    length == 18
    and ([.[] | select(.arguments.environment == "production")] | length >= 1)
    and ([.[] | select(.arguments.replicas == 8)] | length >= 1)
  ' "$CONTROL_EFFECT" >/dev/null || fail "comparison effect log is missing calls Tenuo denied"
}

run_timing() {
  local bench="$RUN_DIR/openshell-bench.json"
  local -a requests=()
  local path
  for path in "$FIXTURE_DIR"/*.json; do
    [[ "$(basename "$path")" == "policy.json" ]] && continue
    requests+=(--request "$path")
  done
  "$TENUO_TARGET/debug/tenuo-demo-fixture" bench \
    --policy "$FIXTURE_DIR/policy.json" \
    --sandbox-id "$SANDBOX_ID" \
    --iterations 1000 \
    "${requests[@]}" >"$bench" || fail "OpenShell timing sample"
  "$DEMO_PYTHON" "$EXAMPLE_DIR/outcome_matrix.py" \
    --observations "$OBS" \
    --policy "$FIXTURE_DIR/policy.json" \
    --requests "$FIXTURE_DIR" \
    --warrant "$FIXTURE_DIR/warrants/task-b.cbor" \
    --holder-key "$FIXTURE_DIR/signers/task-b/key" \
    --openshell-bench "$bench" \
    --timeout-ms 2000 \
    --output-dir "$RESULTS_DIR" || fail "outcome matrix"
  cp "$OBS" "$RESULTS_DIR/evidence/observations.jsonl"
  cp "$EFFECT_LOG" "$RESULTS_DIR/evidence/authorized-effects.jsonl"
  cp "$CONTROL_EFFECT" "$RESULTS_DIR/evidence/openshell-only-effects.jsonl"
  find "$RECEIPT_DIR" -maxdepth 1 -type f \( -name '*.jsonl' -o -name '*.pub' \) \
    -exec cp {} "$RESULTS_DIR/evidence/" \;
  jq -n \
    --arg commit "$(git -C "$ROOT" rev-parse HEAD)" \
    --arg openshell_ref "$(git -C "$OPENSHELL_ROOT" rev-parse HEAD)" \
    --arg supervisor_image "$SUPERVISOR_IMAGE" \
    --arg sandbox_runtime_image "$SANDBOX_RUNTIME_IMAGE" \
    '{commit:$commit,openshell_ref:$openshell_ref,supervisor_image:$supervisor_image,sandbox_runtime_image:$sandbox_runtime_image}' \
    >"$RESULTS_DIR/evidence/manifest.json"
}

for command in cargo curl git jq nc openssl python3 "$COMPUTE_DRIVER"; do
  require_command "$command"
done
require_supported_runtime
configure_supervisor_reachability

OPEN_TARGET="$(cd "$OPENSHELL_ROOT" && cargo metadata --format-version=1 --no-deps | jq -er '.target_directory')"
TENUO_TARGET="$(cargo_target_dir "$ROOT/Cargo.toml")"
GATEWAY_BIN="$OPEN_TARGET/debug/openshell-gateway"
CLI_BIN="$OPEN_TARGET/debug/openshell"
MIDDLEWARE_BIN="$TENUO_TARGET/debug/tenuo-openshell-middleware"

run_step "building Tenuo middleware and fixture generator" cargo build --manifest-path "$ROOT/Cargo.toml" --bins
run_step "building OpenShell gateway" openshell_cargo build --quiet -p openshell-gateway --bin openshell-gateway
run_step "building OpenShell CLI" openshell_cargo build --quiet -p openshell-cli --bin openshell
if [[ -z "${TENUO_DEMO_WORKLOAD_IMAGE:-}" ]]; then
  run_step "building pinned demo workload image" \
    "$COMPUTE_DRIVER" build \
    --file "$EXAMPLE_DIR/Dockerfile.sandbox" \
    --tag "$WORKLOAD_IMAGE" \
    "$ROOT"
fi
generate_security_material
prepare_destination_python
"$TENUO_TARGET/debug/tenuo-demo-fixture" \
  --output "$FIXTURE_DIR" \
  --sandbox-id bootstrap \
  --mcp-port "$UPSTREAM_PORT" \
  --openshell-jwt-dir "$JWT_DIR" \
  --openshell-jwt-key-id "$RUN_ID" >"$FIXTURE_LOG" 2>&1
write_gateway_config
start_upstream
wait_for_port "$UPSTREAM_PID" "$SERVICE_HOST" "$UPSTREAM_PORT" "MCP effect server"
start_middleware
wait_for_port "$MIDDLEWARE_PID" "$SERVICE_HOST" "$MIDDLEWARE_PORT" "Tenuo middleware"
start_gateway
wait_for_gateway

CLI=(env -u OPENSHELL_SANDBOX_POLICY "$CLI_BIN" --gateway-endpoint "$GATEWAY_ENDPOINT")
SANDBOX_CREATED=1
printf 'INFO creating OpenShell sandboxes\n'
SANDBOX_JSON="$("${CLI[@]}" sandbox create --name "$SANDBOX_NAME" --policy "$SANDBOX_POLICY" --output json --no-tty --detach -- sleep infinity 2>>"$SETUP_LOG")" || fail "sandbox creation"
SANDBOX_ID="$(jq -er '.id' <<<"$SANDBOX_JSON")" || fail "sandbox id extraction"
CHILD_SANDBOX_NAME="c-$$-$RANDOM"
CHILD_SANDBOX_JSON="$("${CLI[@]}" sandbox create --name "$CHILD_SANDBOX_NAME" --policy "$SANDBOX_POLICY" --output json --no-tty --detach -- sleep infinity 2>>"$SETUP_LOG")" || fail "second sandbox creation"
CHILD_SANDBOX_ID="$(jq -er '.id' <<<"$CHILD_SANDBOX_JSON")" || fail "second sandbox id extraction"

jq --arg parent "$SANDBOX_ID" --arg child "$CHILD_SANDBOX_ID" \
  '.sandboxes = {($parent): .sandboxes.bootstrap, ($child): .sandboxes["bootstrap-delegate"]}' \
  "$FIXTURE_DIR/policy.json" >"$FIXTURE_DIR/policy.next.json"
mv "$FIXTURE_DIR/policy.next.json" "$FIXTURE_DIR/policy.json"
kill "$MIDDLEWARE_PID"
wait "$MIDDLEWARE_PID" 2>/dev/null || true
unset MIDDLEWARE_PID
start_middleware
wait_for_port "$MIDDLEWARE_PID" "$SERVICE_HOST" "$MIDDLEWARE_PORT" "sandbox-bound Tenuo middleware"

run_suite
