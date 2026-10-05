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
POLICY_TEMPLATE="$RUN_DIR/policy.template.json"
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
# Every `openshell sandbox exec` runs under this hard deadline, in seconds.
EXEC_TIMEOUT="${TENUO_DEMO_EXEC_TIMEOUT:-120}"
if [[ ! "$EXEC_TIMEOUT" =~ ^[0-9]+$ || "$EXEC_TIMEOUT" -lt 60 ]]; then
  echo "TENUO_DEMO_EXEC_TIMEOUT must be a whole number of seconds, at least 60" >&2
  exit 2
fi
# A retryable request refuses to start in the sandbox after this many seconds.
# Its curl has a 20-second limit, so by the exec deadline it has either reached
# the middleware or never will. The margin also covers sandbox clock skew.
REQUEST_START_WINDOW=$((EXEC_TIMEOUT - 40))
# Retry only while the middleware is in the request path; see sandbox_request.
REQUEST_RETRY=1
# Keep the caller's stderr for timeout notices; most exec stderr goes to the setup log.
exec 3>&2
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
    if [[ "$status" != 0 ]]; then
      # Keep each sandbox's supervisor log with the retained artifacts.
      run_with_deadline 30 "" "" "${CLI[@]}" logs -n 400 "$SANDBOX_NAME" \
        </dev/null >"$LOG_DIR/sandbox-first.log" 2>&1 || true
      if [[ -n "${CHILD_SANDBOX_NAME:-}" ]]; then
        run_with_deadline 30 "" "" "${CLI[@]}" logs -n 400 "$CHILD_SANDBOX_NAME" \
          </dev/null >"$LOG_DIR/sandbox-second.log" 2>&1 || true
      fi
    fi
    run_with_deadline "$EXEC_TIMEOUT" "" "" "${CLI[@]}" sandbox delete "$SANDBOX_NAME" \
      </dev/null >>"$SETUP_LOG" 2>&1 || true
    if [[ -n "${CHILD_SANDBOX_NAME:-}" ]]; then
      run_with_deadline "$EXEC_TIMEOUT" "" "" "${CLI[@]}" sandbox delete "$CHILD_SANDBOX_NAME" \
        </dev/null >>"$SETUP_LOG" 2>&1 || true
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

# Run a command with a hard deadline: run_with_deadline SECONDS LABEL SANDBOX
# COMMAND... macOS has no timeout(1), so a watchdog kills the command. Returns
# 124 on timeout. With a label, the watchdog first records diagnostics for
# SANDBOX while the command is still hung. The command keeps the caller's stdin.
run_with_deadline() {
  local seconds="$1" label="$2" sandbox="$3"
  shift 3
  local flag="$RUN_DIR/deadline.$$.$RANDOM" pid watchdog status=0
  "$@" <&0 &
  pid=$!
  (
    set +e
    sleep "$seconds" &
    sleeper=$!
    trap 'kill "$sleeper" 2>/dev/null; exit 0' TERM
    wait "$sleeper"
    : >"$flag"
    if [[ -n "$label" ]]; then
      capture_diagnostics "$label" "$sandbox" "$pid" "sandbox exec ran past ${seconds}s"
    fi
    # Signal the children too: a host tool's own openshell child would
    # otherwise outlive it.
    victims="$pid $(pgrep -P "$pid" | tr '\n' ' ')"
    kill -TERM $victims
    for _ in {1..25}; do
      kill -0 "$pid" || exit 0
      sleep 0.2
    done
    kill -KILL $victims
  ) </dev/null >/dev/null 2>&1 &
  watchdog=$!
  wait "$pid" || status=$?
  kill -TERM "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  if [[ -e "$flag" ]]; then
    rm -f "$flag"
    return 124
  fi
  return "$status"
}

# Record what a sandbox exec was waiting on: capture_diagnostics LABEL SANDBOX
# PID REASON, where PID is the hung client, if any. Every probe is bounded,
# since a wedged gateway or container runtime can hang them too.
capture_diagnostics() {
  local label="$1" sandbox="$2" pid="$3" reason="$4" dir container child
  dir="$LOG_DIR/exec-$(date +%H%M%S)-$RANDOM"
  mkdir -p "$dir"
  printf 'STALL %s: %s in %s; diagnostics in %s\n' \
    "$label" "$reason" "${sandbox:-no sandbox}" "$dir" >&3
  {
    printf 'label: %s\nreason: %s\nsandbox: %s\ncaptured: %s\n' \
      "$label" "$reason" "$sandbox" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -n "$pid" ]]; then
      printf '\n# hung client and its children\n'
      ps -o pid,ppid,etime,stat,command -p "$pid"
      for child in $(pgrep -P "$pid"); do
        ps -o pid,ppid,etime,stat,command -p "$child" | tail -n +2
      done
      if command -v lsof >/dev/null 2>&1; then
        # fd 0 shows whether the client still waits on stdin; TCP rows show
        # whether it reached the gateway.
        printf '\n# open files of the hung client\n'
        lsof -nP -p "$pid"
      fi
    fi
  } >"$dir/client.txt" 2>&1
  tail -n 400 "$GATEWAY_LOG" >"$dir/gateway-tail.log" 2>&1
  tail -n 200 "$MIDDLEWARE_LOG" >"$dir/middleware-tail.log" 2>&1
  df -h "$RUN_DIR" >"$dir/disk.txt" 2>&1
  [[ -n "$sandbox" ]] || return 0
  run_with_deadline 30 "" "" "${CLI[@]}" logs -n 400 "$sandbox" </dev/null >"$dir/sandbox.log" 2>&1
  run_with_deadline 30 "" "" "$COMPUTE_DRIVER" ps -a </dev/null >"$dir/containers.txt" 2>&1
  # The sandbox's workload and supervisor containers carry its name.
  for container in $(grep -oE "[^ ]*--$sandbox-[^ ]*" "$dir/containers.txt"); do
    run_with_deadline 30 "" "" "$COMPUTE_DRIVER" logs --timestamps --tail 400 "$container" \
      </dev/null >"$dir/container-$container.log" 2>&1
  done
  return 0
}

# `openshell sandbox exec` under the exec deadline: sandbox_exec LABEL SANDBOX
# COMMAND... Stdin is /dev/null: the CLI reads a piped stdin to EOF before it
# sends the exec, so an inherited pipe that never closes hangs it silently.
sandbox_exec() {
  local label="$1" sandbox="$2"
  shift 2
  run_with_deadline "$EXEC_TIMEOUT" "$label" "$sandbox" \
    "${CLI[@]}" sandbox exec --name "$sandbox" --no-tty -- "$@" </dev/null
}

# sandbox_exec for a command that reads the caller's stdin.
sandbox_exec_stdin() {
  local label="$1" sandbox="$2"
  shift 2
  run_with_deadline "$EXEC_TIMEOUT" "$label" "$sandbox" \
    "${CLI[@]}" sandbox exec --name "$sandbox" --no-tty -- "$@"
}

# A host command that runs `sandbox exec` itself, such as
# `tenuo-openshell provision`: bounded_tool LABEL SANDBOX COMMAND...
bounded_tool() {
  local label="$1" sandbox="$2"
  shift 2
  run_with_deadline "$EXEC_TIMEOUT" "$label" "$sandbox" "$@" </dev/null
}

# Lines in the middleware log that mention JSON-RPC request id $1.
middleware_lines_for() {
  grep -cF "request_id=$1 " "$MIDDLEWARE_LOG" 2>/dev/null || true
}

effect_count() {
  wc -l <"$EFFECT_LOG" | tr -d ' '
}

# The start of a retryable request's remote script. It refuses to start after
# the epoch second in $1, so an exec that hung before starting cannot send its
# request after sandbox_request has checked that it never arrived.
REQUEST_GUARD='[ "$(date +%s)" -le "$1" ] || { echo "request start deadline passed" >&2; exit 125; }
shift
'

# Send one MCP request with JSON-RPC id $1 from sandbox $2 by running shell
# script $3 there, with the remaining arguments as $1 and on. Sets LAST_E2E_US.
#
# An exec that timed out, or whose request refused to start, is retried once,
# and only when the request provably never reached the MCP server: the
# middleware logged nothing for its id and no effect was recorded. The
# middleware fails closed, so a request it never saw had no effect. The demo
# counts effects and some tools are single-use, so any other failure is final.
# That includes curl timing out in the sandbox: its request was sent, and it
# could still be delivered.
sandbox_request() {
  local id="$1" sandbox="$2" script="$3"
  shift 3
  local out="$RUN_DIR/request-$id.$RANDOM.out" attempt status lines effects start end
  for attempt in 1 2; do
    lines="$(middleware_lines_for "$id")"
    effects="$(effect_count)"
    status=0
    start="$(now_us)"
    sandbox_exec "request $id" "$sandbox" \
      sh -c "$REQUEST_GUARD$script" sh "$(($(date +%s) + REQUEST_START_WINDOW))" "$@" \
      >"$out" || status=$?
    end="$(now_us)"
    LAST_E2E_US=$((end - start))
    if [[ "$attempt" == 1 && "$REQUEST_RETRY" == 1 ]] \
      && [[ "$status" == 124 || "$status" == 125 ]] \
      && [[ "$(middleware_lines_for "$id")" == "$lines" && "$(effect_count)" == "$effects" ]]; then
      printf 'RETRY request %s from %s never reached the middleware (exit %s); sending it again\n' \
        "$id" "$sandbox" "$status" >&3
      continue
    fi
    break
  done
  if [[ "$status" == 28 ]]; then
    # curl's own --max-time: the exec worked, but the request got no response.
    capture_diagnostics "request $id" "$sandbox" "" "curl in the sandbox timed out"
  fi
  cat "$out"
  return "$status"
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
  if [[ "$COMPUTE_DRIVER" == "docker" ]]; then
    # A starting Docker gateway force-removes every supervisor container with
    # its label, including those of other gateways on the same daemon. A
    # per-run label keeps concurrent runs from killing each other's sandboxes.
    printf 'sandbox_label = "%s"\n' "$RUN_ID" >>"$GATEWAY_CONFIG"
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

# Production requires a signed policy, and so does the demo. The operator key
# signs every version the harness writes.
sign_policy() {
  "$TENUO_TARGET/debug/tenuo-openshell" policy sign --policy "$1" --key "$POLICY_KEY" >/dev/null \
    || fail "sign $1"
}

start_middleware() {
  sign_policy "$FIXTURE_DIR/policy.json"
  TENUO_DECISION_LOG=1 "$MIDDLEWARE_BIN" \
    --policy "$FIXTURE_DIR/policy.json" \
    --listen "0.0.0.0:$MIDDLEWARE_PORT" \
    --tls-cert "$TLS_DIR/server.pem" \
    --tls-key "$TLS_DIR/server-key.pem" \
    --openshell-jwt-public-key "$JWT_DIR/public.pem" \
    --openshell-gateway-id "$RUN_ID" \
    --openshell-jwt-key-id "$RUN_ID" \
    --allow-in-memory-replay \
    --policy-signing-key "$POLICY_PUBLIC_KEY" \
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
  "$RUN_DIR/py/bin/python" -m pip install -q 'tenuo[a2a]==0.3.3' 'uvicorn>=0.30,<1' 'nvidia-nat-core>=1.8,<1.9'
  "$RUN_DIR/py/bin/python" -m pip install -q --no-deps "$ROOT/python/nemo-agent-toolkit-tenuo"
  DEMO_PYTHON="$RUN_DIR/py/bin/python"
}

start_upstream() {
  env TENUO_DEMO_EFFECT_LOG="$EFFECT_LOG" \
    TENUO_DEMO_RECEIPT_DIR="$RECEIPT_DIR" \
    "$DEMO_PYTHON" "$EXAMPLE_DIR/mcp_server.py" \
    --port "$UPSTREAM_PORT" \
    --policy "$POLICY_TEMPLATE" >"$UPSTREAM_LOG" 2>&1 &
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
  local body
  body="$(jq -c . "$fixture")"
  sandbox_request "$(jq -r .id "$fixture")" "$sandbox" '
    exec curl -sS -i --max-time 20 "$1" \
      --header "content-type: application/json" \
      --header "accept: application/json, text/event-stream" \
      --header "mcp-protocol-version: 2025-11-25" \
      --data-binary "$2"
  ' "http://host.openshell.internal:$UPSTREAM_PORT/mcp" "$body"
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

# Run the unmodified MCP client in the sandbox through the signing proxy.
sandbox_mcp_client() {
  sandbox_exec "MCP client" "$1" sh -c '
    tenuo-openshell-agent proxy --upstream "http://host.openshell.internal:$1/mcp" 2>>"$HOME/proxy.log" &
    proxy=$!
    sleep 1
    NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
      /usr/local/lib/tenuo-demo/bin/python /usr/local/lib/tenuo-demo/mcp_client.py http://127.0.0.1:7415/mcp
    status=$?
    kill "$proxy"
    exit "$status"
  ' sh "$UPSTREAM_PORT" 2>>"$SETUP_LOG" | tr -d '\r' | tail -1
}

# An approver reviews the restart the sandbox is waiting on and approves it
# with `tenuo-openshell approve`, which reads the pending request from the
# sandbox and installs the signed approval there. The client then retries.
mcp_client_approved_run() {
  local sandbox="$1"
  local run="$2"
  local first="$RUN_DIR/mcp-client-$sandbox.json"
  local output="$RUN_DIR/mcp-client-$sandbox-approved.json"
  local request before start end line decision_us
  if [[ "$run" == "openshell+tenuo" ]]; then
    request="$(jq -er '.restart_service.request_hash' "$first")" || fail "the restart has a pending request"
    bounded_tool "tenuo-openshell approve" "$sandbox" \
      env -u OPENSHELL_SANDBOX_POLICY "$TENUO_TARGET/debug/tenuo-openshell" approve \
        --sandbox "$sandbox" \
        --request "$request" \
        --approver-key "$FIXTURE_DIR/signers/approver/key" \
        --trusted-root "$(jq -er --arg sandbox "$SANDBOX_ID" '.sandboxes[$sandbox].trusted_roots[0]' "$FIXTURE_DIR/policy.json")" \
        --yes \
        --openshell "$CLI_BIN" \
        --gateway-endpoint "$GATEWAY_ENDPOINT" >>"$SETUP_LOG" 2>&1 || fail "approve the pending restart"
    before="$(wc -l <"$MIDDLEWARE_LOG")"
    start="$(now_us)"
    sandbox_mcp_client "$sandbox" >"$output" || fail "approved MCP client run"
    end="$(now_us)"
    jq -e '.restart_service.outcome == "allow" and .restart_service.text == "restarted payments in staging"' "$output" >/dev/null \
      || fail "the approved restart reached the effect"
    line="$(tail -n +"$((before + 1))" "$MIDDLEWARE_LOG" | grep -F 'tenuo_decision ' | grep -F 'outcome=allow' | tail -1 || true)"
    [[ -n "$line" ]] || fail "approved restart has no middleware decision"
    decision_us="$(sed -n 's/.*decision_us=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    printf 'PASS approver signed the pending restart and it ran once\n'
  else
    start="$(now_us)"
    sandbox_exec "comparison MCP client" "$sandbox" \
      /usr/local/lib/tenuo-demo/bin/python /usr/local/lib/tenuo-demo/mcp_client.py \
      "http://host.openshell.internal:$UPSTREAM_PORT/mcp" 2>>"$SETUP_LOG" \
      | tr -d '\r' | tail -1 >"$output" || fail "comparison approved MCP client run"
    end="$(now_us)"
    jq -e '.restart_service.outcome == "allow"' "$output" >/dev/null || fail "comparison restart reached the effect"
    decision_us=0
    printf 'PASS openshell-only restart ran without an approval\n'
  fi
  record_obs "MCP client approved restart" "$run" "allow" "openshell" "" "$decision_us" "$((end - start))"
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
    bounded_tool "tenuo-openshell provision" "$sandbox" \
      env -u OPENSHELL_SANDBOX_POLICY "$TENUO_TARGET/debug/tenuo-openshell" provision \
        --sandbox "$sandbox" \
        --parent-key "$FIXTURE_DIR/signers/task-a/key" \
        --parent-warrant "$FIXTURE_DIR/warrants/task-a.cbor" \
        --capabilities '{"read_logs": {"service": "payments", "environment": "staging"}, "restart_service": {"service": "payments", "environment": "staging", "replicas": {"range": {"max": 5}}}}' \
        --ttl 300 \
        --openshell "$CLI_BIN" \
        --gateway-endpoint "$GATEWAY_ENDPOINT" >>"$SETUP_LOG" 2>&1 || fail "provision the sandbox holder"
    before="$(wc -l <"$MIDDLEWARE_LOG")"
    start="$(now_us)"
    sandbox_mcp_client "$sandbox" >"$output" || fail "MCP client in the sandbox"
    end="$(now_us)"
  else
    start="$(now_us)"
    sandbox_exec "comparison MCP client" "$sandbox" \
      /usr/local/lib/tenuo-demo/bin/python /usr/local/lib/tenuo-demo/mcp_client.py \
      "http://host.openshell.internal:$UPSTREAM_PORT/mcp" 2>>"$SETUP_LOG" \
      | tr -d '\r' | tail -1 >"$output" || fail "comparison MCP client in the sandbox"
    end="$(now_us)"
  fi
  LAST_E2E_US=$((end - start))
  jq -e '.read_logs.outcome == "allow" and .read_logs.text == "read payments logs in staging"' "$output" >/dev/null \
    || fail "$run MCP client read reached the effect"
  if [[ "$run" == "openshell+tenuo" ]]; then
    jq -e '.restart_service.outcome == "deny" and .restart_service.code == -32002 and .restart_service.reason == "approval-required" and .restart_service.source == "agent" and (.restart_service.request_hash | length == 64)' \
      "$output" >/dev/null || fail "MCP client restart waited for approval in the sandbox"
    line="$(tail -n +"$((before + 1))" "$MIDDLEWARE_LOG" | grep -F 'tenuo_decision ' | grep -F 'outcome=allow' | tail -1 || true)"
    [[ -n "$line" ]] || fail "MCP client read has no middleware decision"
    decision_us="$(sed -n 's/.*decision_us=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    record_obs "MCP client read" "$run" "allow" "openshell" "" "$decision_us" "$LAST_E2E_US"
    record_obs "MCP client restart" "$run" "deny" "sandbox agent" "approval-required" 0 0
    printf 'PASS unmodified MCP client read through the signing proxy\n'
    printf 'PASS unmodified MCP client restart waited for approval in the sandbox\n'
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
  sandbox_request "$id" "$sandbox" '
    set -e
    work="$(mktemp -d)"
    printf "%s" "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_logs\",\"arguments\":{\"service\":\"payments\",\"environment\":\"staging\"}}}" \
      | tenuo-openshell-agent sign >"$work/body.json"
    curl -sS -i --max-time 20 "http://host.openshell.internal:$2/mcp" \
      --header "content-type: application/json" \
      --header "accept: application/json, text/event-stream" \
      --header "mcp-protocol-version: 2025-11-25" \
      --data-binary @"$work/body.json"
  ' "$id" "$UPSTREAM_PORT"
}

# Run tenuo-openshell-agent in a sandbox. A non-empty directory gives the call
# its own holder key, warrant, and approvals, as a sub-agent process would.
sandbox_agent() {
  local sandbox="$1" dir="$2"
  shift 2
  sandbox_exec "tenuo-openshell-agent $1" "$sandbox" sh -c '
    dir="$1"; shift
    if [ -n "$dir" ]; then
      export TENUO_HOLDER_KEY_FILE="$dir/holder.key" TENUO_WARRANT_FILE="$dir/warrant" TENUO_APPROVALS_DIR="$dir/approvals"
    fi
    exec tenuo-openshell-agent "$@"
  ' sh "$dir" "$@" 2>>"$SETUP_LOG" | tr -d '\r'
}

# Send one tools/call from a sandbox with JSON-RPC id $3. With signing on, the
# holder in directory $2 (default holder when empty) signs it first.
sandbox_tool_call() {
  local sandbox="$1" dir="$2" id="$3" tool="$4" arguments="$5" sign="$6"
  sandbox_request "$id" "$sandbox" '
    set -e
    dir="$1"; id="$2"; tool="$3"; arguments="$4"; sign="$5"; port="$6"
    if [ -n "$dir" ]; then
      export TENUO_HOLDER_KEY_FILE="$dir/holder.key" TENUO_WARRANT_FILE="$dir/warrant" TENUO_APPROVALS_DIR="$dir/approvals"
    fi
    work="$(mktemp -d)"
    body="{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$arguments}}"
    if [ "$sign" = sign ]; then
      printf "%s" "$body" | tenuo-openshell-agent sign >"$work/body.json"
    else
      printf "%s" "$body" >"$work/body.json"
    fi
    curl -sS -i --max-time 20 "http://host.openshell.internal:$port/mcp" \
      --header "content-type: application/json" \
      --header "accept: application/json, text/event-stream" \
      --header "mcp-protocol-version: 2025-11-25" \
      --data-binary @"$work/body.json"
  ' "$dir" "$id" "$tool" "$arguments" "$sign" "$UPSTREAM_PORT"
}

# Sub-agent delegation (#18). The first sandbox's agent holds the warrant Task
# A delegated to it. It delegates read_logs, terminally, to a sub-agent with its
# own key in the same sandbox, and the operator CLI relays a delegation to the
# second sandbox. Only public keys and warrants cross; the parent's key stays put.
subagent_delegation() {
  local run="$1" child_dir=/home/sandbox/.tenuo-subagent output line decision_us chain public
  local read='{"service":"payments","environment":"staging"}'
  local restart='{"service":"payments","environment":"staging","replicas":3}'
  if [[ "$run" == "openshell-only" ]]; then
    output="$RUN_DIR/control-subagent-read.out"
    sandbox_tool_call "$SANDBOX_NAME" "" 19 read_logs "$read" plain >"$output" 2>>"$SETUP_LOG" || fail "control sub-agent read"
    grep -Fq "read payments logs in staging" "$output" || fail "control sub-agent read reached the effect"
    record_obs "sub-agent read" "$run" "allow" "openshell" "" 0 0
    output="$RUN_DIR/control-subagent-restart.out"
    sandbox_tool_call "$SANDBOX_NAME" "" 20 restart_service "$restart" plain >"$output" 2>>"$SETUP_LOG" || fail "control sub-agent restart"
    grep -Fq "restarted payments in staging" "$output" || fail "control sub-agent restart reached the effect"
    record_obs "sub-agent restart" "$run" "allow" "sandbox agent" "" 0 0
    record_obs "sub-agent delegates further" "$run" "not checked" "attenuation" "" 0 0
    output="$RUN_DIR/control-cross-sandbox-read.out"
    sandbox_tool_call "$CHILD_SANDBOX_NAME" "" 21 read_logs "$read" plain >"$output" 2>>"$SETUP_LOG" || fail "control cross-sandbox read"
    grep -Fq "read payments logs in staging" "$output" || fail "control cross-sandbox read reached the effect"
    record_obs "cross-sandbox sub-agent read" "$run" "allow" "openshell" "" 0 0
    printf 'PASS openshell-only sub-agent calls were not checked\n'
    return
  fi

  public="$(sandbox_agent "$SANDBOX_NAME" "$child_dir" keygen | tail -1)"
  [[ "$public" =~ ^[0-9a-f]{64}$ ]] || fail "sub-agent holder key"
  chain="$(sandbox_agent "$SANDBOX_NAME" "" delegate --child-pub "$public" --tools read_logs --ttl 300 --terminal | tail -1)"
  [[ -n "$chain" ]] || fail "parent agent delegated to the sub-agent"
  sandbox_agent "$SANDBOX_NAME" "$child_dir" install-warrant "$chain" >/dev/null || fail "sub-agent warrant install"

  output="$RUN_DIR/subagent-read.out"
  sandbox_tool_call "$SANDBOX_NAME" "$child_dir" 19 read_logs "$read" sign >"$output" 2>>"$SETUP_LOG" || fail "sub-agent read"
  grep -Fq '200 OK' "$output" || fail "sub-agent read returns 200"
  grep -Fq "read payments logs in staging" "$output" || fail "sub-agent read reached the effect"
  decision_us="$(decision_us_for 19 "$MIDDLEWARE_LOG")" || fail "sub-agent read has no decision timing"
  record_obs "sub-agent read" "$run" "allow" "openshell" "" "$decision_us" 0
  printf 'PASS sub-agent in the same sandbox read with a narrowed warrant\n'

  output="$RUN_DIR/subagent-restart.out"
  printf '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"restart_service","arguments":%s}}' "$restart" \
    | sandbox_exec_stdin "sub-agent restart signing" "$SANDBOX_NAME" sh -c '
        export TENUO_HOLDER_KEY_FILE="$1/holder.key" TENUO_WARRANT_FILE="$1/warrant"
        tenuo-openshell-agent sign || true' sh "$child_dir" >"$output" 2>>"$SETUP_LOG" || true
  grep -Fq '"tool-not-authorized"' "$output" || fail "sub-agent restart was refused in the sandbox"
  record_obs "sub-agent restart" "$run" "deny" "sandbox agent" "tool-not-authorized" 0 0
  printf 'PASS sub-agent restart, which its parent did not pass on, was refused\n'

  output="$RUN_DIR/subagent-delegate.out"
  sandbox_agent "$SANDBOX_NAME" "$child_dir" delegate --child-pub "$public" --tools read_logs >"$output" 2>&1 || true
  grep -Fq "attenuation refused" "$SETUP_LOG" || fail "terminal sub-agent could delegate further"
  record_obs "sub-agent delegates further" "$run" "refused" "attenuation" "attenuation-refused" 0 0
  printf 'PASS terminal sub-agent could not delegate further\n'

  bounded_tool "tenuo-openshell delegate" "$CHILD_SANDBOX_NAME" \
    env -u OPENSHELL_SANDBOX_POLICY "$TENUO_TARGET/debug/tenuo-openshell" delegate \
      --from-sandbox "$SANDBOX_NAME" \
      --to-sandbox "$CHILD_SANDBOX_NAME" \
      --tools read_logs \
      --ttl 600 \
      --openshell "$CLI_BIN" \
      --gateway-endpoint "$GATEWAY_ENDPOINT" >>"$SETUP_LOG" 2>&1 || fail "cross-sandbox delegation"
  output="$RUN_DIR/cross-sandbox-read.out"
  sandbox_tool_call "$CHILD_SANDBOX_NAME" "" 21 read_logs "$read" sign >"$output" 2>>"$SETUP_LOG" || fail "cross-sandbox read"
  grep -Fq '200 OK' "$output" || fail "cross-sandbox read returns 200"
  grep -Fq "read payments logs in staging" "$output" || fail "cross-sandbox read reached the effect"
  decision_us="$(decision_us_for 21 "$MIDDLEWARE_LOG")" || fail "cross-sandbox read has no decision timing"
  record_obs "cross-sandbox sub-agent read" "$run" "allow" "openshell" "" "$decision_us" 0
  printf 'PASS a second sandbox read with authority delegated from the first\n'
}

# Revoke Task A's warrant, an ancestor of the second sandbox's running child.
# The list names only Task A; the child's next call is denied.
revoke_ancestor() {
  local run="$1" output decision_us
  local read='{"service":"payments","environment":"staging"}'
  if [[ "$run" == "openshell-only" ]]; then
    output="$RUN_DIR/control-revoked-child.out"
    sandbox_tool_call "$CHILD_SANDBOX_NAME" "" 22 read_logs "$read" plain >"$output" 2>>"$SETUP_LOG" || fail "control revoked-child read"
    grep -Fq "read payments logs in staging" "$output" || fail "control revoked-child read reached the effect"
    record_obs "revoked ancestor, running child" "$run" "allow" "openshell" "" 0 0
    printf 'PASS openshell-only revocation was not checked\n'
    return
  fi
  update_policy '.sandboxes |= with_entries(.value.revocation = {
      signed_list_base64: $srl,
      max_staleness_secs: 3600,
      clock_tolerance_secs: 30,
      rollback_floor_path: ($floors + "/floor-" + .key + ".json")
    })' "the revocation" --arg srl "$(cat "$FIXTURE_DIR/revocations/task-a.srl")" --arg floors "$RUN_DIR"
  output="$RUN_DIR/revoked-child.out"
  sandbox_tool_call "$CHILD_SANDBOX_NAME" "" 22 read_logs "$read" sign >"$output" 2>>"$SETUP_LOG" || fail "revoked-child read returns a response"
  grep -Fq '403 Forbidden' "$output" || fail "running child of a revoked ancestor was denied"
  grep -Fq 'tenuo_revoked' "$output" || fail "running child denial reason is tenuo_revoked"
  decision_us="$(decision_us_for 22 "$MIDDLEWARE_LOG")" || fail "revoked-child read has no decision timing"
  record_obs "revoked ancestor, running child" "$run" "deny" "openshell" "tenuo_revoked" "$decision_us" 0
  printf 'PASS revoking an ancestor denied a running child in another sandbox\n'
}

# A higher policy version limits results in the first sandbox to 64 bytes. The
# sandbox signs a read whose result is larger. The read runs and OpenShell
# withholds its result, because the upstream call happens before the response.
# Apply a jq edit to the policy as a higher version and wait until the
# middleware reports that version.
update_policy() {
  local edit="$1" label="$2" version
  shift 2
  jq --arg sandbox "$SANDBOX_ID" "$@" "(.version = ((.version // 1) + 1)) | $edit" \
    "$FIXTURE_DIR/policy.json" >"$FIXTURE_DIR/policy.next.json"
  # Signature first: until the policy bytes change, the middleware skips the
  # reload, so it never pairs the new policy with the old signature.
  sign_policy "$FIXTURE_DIR/policy.next.json"
  mv "$FIXTURE_DIR/policy.next.json.sig" "$FIXTURE_DIR/policy.json.sig"
  mv "$FIXTURE_DIR/policy.next.json" "$FIXTURE_DIR/policy.json"
  version="$(jq -r .version "$FIXTURE_DIR/policy.json")"
  for _ in {1..30}; do
    if curl -fsS "http://127.0.0.1:$ADMIN_PORT/metrics" 2>/dev/null \
      | grep -Fxq "tenuo_openshell_policy_version $version"; then
      return 0
    fi
    sleep 1
  done
  fail "$label policy was loaded"
}

result_size_limit() {
  local id=17 output="$RUN_DIR/result-limit.out"
  update_policy '.sandboxes[$sandbox].max_result_bytes = 64' "the result limit"
  sandbox_signed_call "$SANDBOX_NAME" "$id" \
    >"$output" 2>>"$SETUP_LOG" || fail "oversized result returns a response"
  grep -Fq '403 Forbidden' "$output" || fail "oversized result was withheld"
  grep -Fq 'tenuo_result_too_large' "$output" || fail "oversized result reason is tenuo_result_too_large"
  grep -Fq "read payments logs in staging" "$output" && fail "oversized result reached the sandbox"
  jq -se 'length == 7 and (last | .tool == "read_logs")' "$EFFECT_LOG" >/dev/null \
    || fail "the read behind the withheld result ran"
  grep -Fq "tenuo_result request_id=$id " "$MIDDLEWARE_LOG" || fail "oversized result has a result decision"
  printf 'PASS oversized result was withheld after the read ran\n'
  # Later scenarios in this sandbox return full results.
  update_policy 'del(.sandboxes[$sandbox].max_result_bytes)' "the restored"
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
  expect_deny "$FIXTURE_DIR/task-a-other-service.json" "tenuo_constraint_denied" \
    "task A restart of auth was denied" "" "restart other service"
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
    and ([.[] | select(.arguments.service == "identity" or .arguments.service == "auth" or .arguments.environment == "production" or .arguments.replicas == 8 or .arguments.replicas == 5)] | length == 0)
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
  subagent_delegation "openshell+tenuo"
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
    ([.[] | select(.outcome == "delivered")] | length == 7)
    and ([.[] | select(.outcome == "blocked" and .decision_code == "tenuo_result_too_large" and .request_id == "17")] | length == 1)
  ' "$RESULTS_DIR/evidence/openshell-results.json" >/dev/null || fail "result receipts cover the allowed calls"
  printf 'PASS receipts export as JSON lines for log pipelines\n'
  "$DEMO_PYTHON" "$ROOT/examples/interoperability/a2a_handoff.py" \
    --port "$A2A_PORT" \
    --output "$RESULTS_DIR/evidence/a2a-handoff.json" || fail "A2A authority handoff"
  mcp_client_approved_run "$SANDBOX_NAME" "openshell+tenuo"
  # Last in this run: it revokes Task A and everything delegated from it.
  revoke_ancestor "openshell+tenuo"
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
  # Without the middleware nothing proves a request never arrived.
  REQUEST_RETRY=0

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
  control_allow "production read" "$FIXTURE_DIR/task-a-constraint.json" "read identity logs in production"
  control_allow "replicas 8" "$FIXTURE_DIR/task-a-replicas.json" "restarted payments in staging"
  control_allow "restart other service" "$FIXTURE_DIR/task-a-other-service.json" "restarted auth in staging"
  control_allow "missing warrant" "$FIXTURE_DIR/missing-warrant.json" "restarted payments in staging"
  control_allow "narrowed read" "$FIXTURE_DIR/delegated-read.json" "read payments logs in staging" "$CHILD_SANDBOX_NAME"
  control_allow "narrowed restart" "$FIXTURE_DIR/delegated-restart.json" "restarted payments in staging" "$CHILD_SANDBOX_NAME"
  mcp_client_run "$SANDBOX_NAME" "openshell-only"
  mcp_client_approved_run "$SANDBOX_NAME" "openshell-only"
  subagent_delegation "openshell-only"
  revoke_ancestor "openshell-only"
  control_direct "direct task B restart" "$FIXTURE_DIR/task-b-restart.json"
  control_direct "direct missing warrant" "$FIXTURE_DIR/missing-warrant.json"
  control_direct "direct narrowed restart" "$FIXTURE_DIR/delegated-restart.json"
  record_obs "wider child" "openshell-only" "not checked" "attenuation" "" 0 0
  printf 'PASS openshell-only wider child was not checked\n'

  jq -se '
    length == 25
    and ([.[] | select(.arguments.environment == "production")] | length >= 1)
    and ([.[] | select(.tool == "restart_service" and .arguments.service == "auth")] | length == 1)
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
# The fixture's sandbox entries, keyed `bootstrap` and `bootstrap-delegate`,
# are templates until the sandboxes exist and have IDs.
"$TENUO_TARGET/debug/tenuo-demo-fixture" \
  --output "$FIXTURE_DIR" \
  --sandbox-id bootstrap \
  --mcp-port "$UPSTREAM_PORT" \
  --openshell-jwt-dir "$JWT_DIR" \
  --openshell-jwt-key-id "$RUN_ID" >"$FIXTURE_LOG" 2>&1
mv "$FIXTURE_DIR/policy.json" "$POLICY_TEMPLATE"
POLICY_KEY="$RUN_DIR/secrets/policy-signing.key"
POLICY_PUBLIC_KEY="$("$TENUO_TARGET/debug/tenuo-openshell" keygen --out "$POLICY_KEY")" \
  || fail "policy signing key"
write_gateway_config
start_upstream
wait_for_port "$UPSTREAM_PID" "$SERVICE_HOST" "$UPSTREAM_PORT" "MCP effect server"
# The middleware starts before any sandbox exists, on a policy that trusts
# none, as an operator's first deployment does.
jq '.version = 1 | .sandboxes = {}' "$POLICY_TEMPLATE" >"$FIXTURE_DIR/policy.json"
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

# The running middleware picks up the sandboxes on its next policy reload.
update_policy '.sandboxes = {($sandbox): $template[0].sandboxes.bootstrap, ($child): $template[0].sandboxes["bootstrap-delegate"]}' \
  "the sandbox-bound" \
  --arg child "$CHILD_SANDBOX_ID" \
  --slurpfile template "$POLICY_TEMPLATE"

run_suite
