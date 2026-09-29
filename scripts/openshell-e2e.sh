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
    for ((offset = 0; offset < 4; offset++)); do
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
  echo "failed to find four free ports" >&2
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
GATEWAY_ENDPOINT="http://127.0.0.1:$GATEWAY_PORT"

RUN_DIR="$(mktemp -d)"
LOG_DIR="$RUN_DIR/logs"
JWT_DIR="$RUN_DIR/jwt"
TLS_DIR="$RUN_DIR/tls"
FIXTURE_DIR="$RUN_DIR/fixtures"
GATEWAY_CONFIG="$RUN_DIR/gateway.toml"
SANDBOX_POLICY="$RUN_DIR/openshell-policy.yaml"
EFFECT_LOG="$RUN_DIR/effects.jsonl"
SETUP_LOG="$LOG_DIR/setup.log"
GATEWAY_LOG="$LOG_DIR/gateway.log"
MIDDLEWARE_LOG="$LOG_DIR/middleware.log"
UPSTREAM_LOG="$LOG_DIR/upstream.log"
RUN_ID="tenuo-demo-$$-$RANDOM"
SANDBOX_NAME="tn-$$-$RANDOM"
SUPERVISOR_IMAGE="${TENUO_DEMO_SUPERVISOR_IMAGE:-$PINNED_SUPERVISOR_IMAGE}"
SANDBOX_RUNTIME_IMAGE="${TENUO_DEMO_SANDBOX_RUNTIME_IMAGE:-$PINNED_SANDBOX_RUNTIME_IMAGE}"
WORKLOAD_IMAGE="${TENUO_DEMO_WORKLOAD_IMAGE:-localhost/tenuo-openshell/workload:$RUN_ID}"
SANDBOX_CREATED=0
mkdir -p "$LOG_DIR" "$JWT_DIR" "$TLS_DIR" "$FIXTURE_DIR"
: >"$EFFECT_LOG"

dump_logs() {
  local label log_file
  for label in setup gateway middleware upstream; do
    case "$label" in
      setup) log_file="$SETUP_LOG" ;;
      gateway) log_file="$GATEWAY_LOG" ;;
      middleware) log_file="$MIDDLEWARE_LOG" ;;
      upstream) log_file="$UPSTREAM_LOG" ;;
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
  fi
  for pid_name in GATEWAY_PID MIDDLEWARE_PID UPSTREAM_PID; do
    local pid="${!pid_name:-}"
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
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

[[openshell.supervisor.middleware]]
name = "tenuo/authorization"
grpc_endpoint = "https://$SERVICE_HOST:$MIDDLEWARE_PORT"
tls_ca_cert_path = "$TLS_DIR/ca.pem"
audience = "$AUDIENCE"
max_payload_bytes = 262144
timeout = "2s"

[openshell.drivers.$COMPUTE_DRIVER]
supervisor_image = "$SUPERVISOR_IMAGE"
sandbox_runtime_image = "$SANDBOX_RUNTIME_IMAGE"
default_image = "$WORKLOAD_IMAGE"
EOF
  sed "s/__UPSTREAM_PORT__/$UPSTREAM_PORT/g" "$EXAMPLE_DIR/openshell-policy.yaml" >"$SANDBOX_POLICY"
}

start_middleware() {
  "$MIDDLEWARE_BIN" \
    --policy "$FIXTURE_DIR/policy.json" \
    --listen "0.0.0.0:$MIDDLEWARE_PORT" \
    --tls-cert "$TLS_DIR/server.pem" \
    --tls-key "$TLS_DIR/server-key.pem" \
    --openshell-jwt-public-key "$JWT_DIR/public.pem" \
    --openshell-gateway-id "$RUN_ID" \
    --openshell-jwt-key-id "$RUN_ID" \
    --audience "$AUDIENCE" >>"$MIDDLEWARE_LOG" 2>&1 &
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

start_upstream() {
  env TENUO_DEMO_EFFECT_LOG="$EFFECT_LOG" \
    python3 "$EXAMPLE_DIR/mcp_server.py" --port "$UPSTREAM_PORT" >"$UPSTREAM_LOG" 2>&1 &
  UPSTREAM_PID=$!
}

start_gateway() {
  env -u OPENSHELL_DRIVERS -u OPENSHELL_COMPUTE_DRIVER "$GATEWAY_BIN" \
    --compute-driver "$COMPUTE_DRIVER" \
    --config "$GATEWAY_CONFIG" \
    --bind-address 127.0.0.1 \
    --port "$GATEWAY_PORT" \
    --health-port "$HEALTH_PORT" \
    --metrics-port 0 \
    --log-level info \
    --disable-tls \
    --db-url "sqlite://$RUN_DIR/gateway.db" >"$GATEWAY_LOG" 2>&1 &
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

send_request() {
  local fixture="$1"
  local body
  body="$(jq -c . "$fixture")"
  "${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
    curl -sS -i --max-time 20 "http://host.openshell.internal:$UPSTREAM_PORT/mcp" \
      --header 'content-type: application/json' \
      --header 'accept: application/json, text/event-stream' \
      --header 'mcp-protocol-version: 2025-11-25' \
      --data-binary "$body"
}

expect_allow() {
  local fixture="$1"
  local marker="$2"
  local label="$3"
  local output="$RUN_DIR/$(basename "$fixture").out"
  send_request "$fixture" >"$output" 2>>"$SETUP_LOG" || fail "$label completes"
  grep -Fq '200 OK' "$output" || fail "$label returns 200"
  grep -Fq "$marker" "$output" || fail "$label effect response is returned"
  printf 'PASS %s\n' "$label"
}

expect_deny() {
  local fixture="$1"
  local reason="$2"
  local label="$3"
  local output="$RUN_DIR/$(basename "$fixture").out"
  send_request "$fixture" >"$output" 2>>"$SETUP_LOG" || fail "$label returns a response"
  grep -Fq '403 Forbidden' "$output" || fail "$label is denied"
  grep -Fq "$reason" "$output" || fail "$label reason is $reason"
  printf 'PASS %s\n' "$label"
}

run_suite() {
  expect_allow "$FIXTURE_DIR/task-a-read.json" "read payments logs in staging" \
    "task A read reached the effect"
  expect_allow "$FIXTURE_DIR/task-b-read.json" "read payments logs in staging" \
    "task B read reached the effect"
  expect_allow "$FIXTURE_DIR/task-a-restart.json" "restarted payments in staging" \
    "task A restart reached the effect"
  expect_deny "$FIXTURE_DIR/task-b-restart.json" "tenuo_tool_denied" \
    "task B restart was denied"
  expect_deny "$FIXTURE_DIR/copied-warrant.json" "tenuo_invalid_authority" \
    "task A's warrant signed by task B was denied"
  expect_deny "$FIXTURE_DIR/task-a-constraint.json" "tenuo_constraint_denied" \
    "task A production read was denied"
  expect_deny "$FIXTURE_DIR/task-a-replicas.json" "tenuo_constraint_denied" \
    "task A replicas=8 restart was denied"
  expect_deny "$FIXTURE_DIR/missing-warrant.json" "tenuo_missing_warrant" \
    "missing authority was denied"

  jq -se '
    length == 3
    and ([.[] | select(.tool == "read_logs" and .arguments.service == "payments" and .arguments.environment == "staging")] | length == 2)
    and ([.[] | select(.tool == "restart_service" and .arguments.service == "payments" and .arguments.environment == "staging" and .arguments.replicas == 3)] | length == 1)
    and ([.[] | select(.arguments.service == "identity" or .arguments.environment == "production" or .arguments.replicas == 8)] | length == 0)
  ' "$EFFECT_LOG" >/dev/null || fail "effect server observed only the three authorized calls"
  printf 'ALL PASS both tasks used one sandbox; only the authorized calls reached the effect\n'
}

for command in cargo curl git jq nc openssl python3 "$COMPUTE_DRIVER"; do
  require_command "$command"
done
require_supported_runtime

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
"$TENUO_TARGET/debug/tenuo-demo-fixture" \
  --output "$FIXTURE_DIR" \
  --sandbox-id bootstrap \
  --openshell-jwt-dir "$JWT_DIR" \
  --openshell-jwt-key-id "$RUN_ID"
write_gateway_config
start_upstream
wait_for_port "$UPSTREAM_PID" "$SERVICE_HOST" "$UPSTREAM_PORT" "MCP effect server"
start_middleware
wait_for_port "$MIDDLEWARE_PID" "$SERVICE_HOST" "$MIDDLEWARE_PORT" "Tenuo middleware"
start_gateway
wait_for_gateway

CLI=(env -u OPENSHELL_SANDBOX_POLICY "$CLI_BIN" --gateway-endpoint "$GATEWAY_ENDPOINT")
SANDBOX_CREATED=1
printf 'INFO creating OpenShell sandbox\n'
SANDBOX_JSON="$("${CLI[@]}" sandbox create --name "$SANDBOX_NAME" --policy "$SANDBOX_POLICY" --output json --no-tty --detach -- sleep infinity 2>>"$SETUP_LOG")" || fail "sandbox creation"
SANDBOX_ID="$(jq -er '.id' <<<"$SANDBOX_JSON")" || fail "sandbox id extraction"

jq --arg id "$SANDBOX_ID" '.sandboxes = {($id): .sandboxes.bootstrap}' \
  "$FIXTURE_DIR/policy.json" >"$FIXTURE_DIR/policy.next.json"
mv "$FIXTURE_DIR/policy.next.json" "$FIXTURE_DIR/policy.json"
kill "$MIDDLEWARE_PID"
wait "$MIDDLEWARE_PID" 2>/dev/null || true
unset MIDDLEWARE_PID
start_middleware
wait_for_port "$MIDDLEWARE_PID" "$SERVICE_HOST" "$MIDDLEWARE_PORT" "sandbox-bound Tenuo middleware"

run_suite
