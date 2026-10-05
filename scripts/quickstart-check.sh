#!/usr/bin/env bash
# Run docs/quickstart.md end to end against an OpenShell gateway laid out the
# way OpenShell's install.sh installs it, and check its outcomes.
#
# The guide starts with OpenShell installed and its local gateway running.
# This script stands in for the installer without installing anything
# system-wide. In a temporary XDG_CONFIG_HOME and XDG_STATE_HOME it:
#
# - downloads the OpenShell v0.1.2 `openshell` and `openshell-gateway`
#   binaries;
# - writes the default gateway.toml the Homebrew formula writes, and creates
#   the TLS and JWT material with `openshell-gateway generate-certs`, as the
#   Homebrew formula and the Linux user service do;
# - runs `openshell-gateway` with no arguments, as both services do. It reads
#   $XDG_CONFIG_HOME/openshell/gateway.toml, listens on 127.0.0.1:17670 with
#   TLS, and picks the Docker driver; and
# - registers it with `openshell gateway add --local`, as install.sh does.
#
# OpenShell's Docker supervisors reach the gateway on 127.0.0.1. On Docker
# Desktop that needs host networking turned on, which OpenShell requires.
# When this Docker Desktop has it off, a forwarder container on the VM's
# loopback stands in for it.
#
# Then every ```bash block in the guide runs, in order, in one shell. A
# `<!-- check: NAME -->` line in the guide runs the function check_NAME below
# in its place, for the steps a reader does by hand: editing gateway.toml and
# restarting the gateway.
#
# By default it uses the published artifacts the guide names. To check a
# release candidate before it is published, substitute local builds:
#
#   TENUO_QS_CLI               tenuo-openshell binary for this host, copied
#                              into bin/ instead of the release download
#   TENUO_QS_MIDDLEWARE_IMAGE  local image for ghcr.io/tenuo-ai/tenuo-openshell
#   TENUO_QS_DEMO_IMAGE        local image for ghcr.io/tenuo-ai/tenuo-openshell-demo
#                              (scripts/build-demo-image.sh builds one)
#   TENUO_QS_OPENSHELL_BIN     directory that already holds the OpenShell v0.1.2
#                              openshell and openshell-gateway for this host
#
# The guide itself is not changed; only the script run from it is.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUIDE="$ROOT/docs/quickstart.md"
OPENSHELL_VERSION=v0.1.2
GATEWAY_PORT=17670
FORWARDER=tenuo-quickstart-loopback

for command in docker curl jq python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing prerequisite: $command" >&2
    exit 2
  }
done
for name in tenuo-openshell-dev tenuo-openshell-dev-mcp "$FORWARDER"; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    echo "a $name container already exists; run \`tenuo-openshell dev down\` or remove it" >&2
    exit 1
  fi
done
if (exec 3<>"/dev/tcp/127.0.0.1/$GATEWAY_PORT") 2>/dev/null; then
  echo "something already listens on 127.0.0.1:$GATEWAY_PORT, likely an installed OpenShell gateway; stop it first" >&2
  exit 1
fi

WORK="$(mktemp -d)"
WORK="$(cd "$WORK" && pwd -P)"
export WORK
SCRIPT="$WORK/quickstart.sh"
OUTPUT="$WORK/output.log"
export BIN="$WORK/bin"
export XDG_CONFIG_HOME="$WORK/config"
export XDG_STATE_HOME="$WORK/state"
export OPENSHELL_LOCAL_TLS_DIR="$XDG_STATE_HOME/openshell/tls"
export GATEWAY_CONFIG="$XDG_CONFIG_HOME/openshell/gateway.toml"
export GATEWAY_LOG="$WORK/gateway.log"
export GATEWAY_PID_FILE="$WORK/gateway.pid"
export GATEWAY_PORT
export PATH="$BIN:$PATH"
unset OPENSHELL_GATEWAY OPENSHELL_GATEWAY_ENDPOINT TENUO_OPENSHELL_DEV_DIR
# The CLI's default images follow its version. The guide's images replace
# them below, so `dev up` runs what the guide names.
unset TENUO_OPENSHELL_IMAGE TENUO_OPENSHELL_DEMO_IMAGE

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$status" != 0 ]]; then
    echo "--- gateway.log ---" >&2
    tail -30 "$GATEWAY_LOG" >&2 2>/dev/null || true
    echo "--- middleware ---" >&2
    docker logs tenuo-openshell-dev 2>&1 | tail -30 >&2 || true
  fi
  local id
  if id="$(openshell sandbox get tenuo-demo -o json 2>/dev/null | jq -er .id)"; then
    openshell sandbox delete tenuo-demo >/dev/null 2>&1 || true
    docker ps -aq --filter "label=openshell.ai/sandbox-id=$id" | xargs docker rm -f >/dev/null 2>&1 || true
  fi
  if [[ -f "$GATEWAY_PID_FILE" ]]; then
    kill "$(cat "$GATEWAY_PID_FILE")" 2>/dev/null || true
  fi
  docker rm -f tenuo-openshell-dev tenuo-openshell-dev-mcp "$FORWARDER" >/dev/null 2>&1 || true
  if [[ "$status" != 0 ]]; then
    echo "quickstart check failed; output in $OUTPUT" >&2
  else
    rm -rf "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT

# --- The guide, with local substitutions -------------------------------------

{
  echo 'set -eu'
  # The functions a check marker calls.
  sed -n '/^# --- check functions/,/^# --- end check functions/p' "${BASH_SOURCE[0]}"
  awk '
    /^<!-- check: [a-z-]+ -->$/ { name = $3; gsub("-", "_", name); print "check_" name; next }
    /^```bash$/ { block = 1; next }
    /^```$/ { block = 0 }
    block' "$GUIDE"
} >"$SCRIPT"

# Each substitution must match the guide, so a renamed artifact or path fails
# here instead of silently testing something else.
substitute() {
  local name="$1" before
  before="$(cat "$SCRIPT")"
  shift
  "$@" "$SCRIPT" >"$SCRIPT.new"
  mv "$SCRIPT.new" "$SCRIPT"
  if [[ "$(cat "$SCRIPT")" == "$before" ]]; then
    echo "$name: nothing in the guide to substitute" >&2
    exit 1
  fi
}
substitute "CLI install directory" sed "s#~/.local/bin#\"\$BIN\"#g"
substitute "dev state directory" \
  sed "s#~/.local/state/tenuo-openshell/dev#\"\$XDG_STATE_HOME/tenuo-openshell/dev\"#g"
# Nothing answers the approval prompt.
substitute "unattended approval" sed "s#^tenuo-openshell approve --dev #tenuo-openshell approve --yes --dev #"
if [[ -n "${TENUO_QS_CLI:-}" ]]; then
  cli="$(cd "$(dirname "$TENUO_QS_CLI")" && pwd)/$(basename "$TENUO_QS_CLI")"
  [[ -x "$cli" ]] || { echo "TENUO_QS_CLI is not executable: $cli" >&2; exit 1; }
  # Replace the two-line release download with a copy of the local binary.
  substitute "TENUO_QS_CLI=$cli" awk -v cli="$cli" '
    /releases\/download\/.*\/tenuo-openshell-v/ { print "cp \"" cli "\" \"$BIN/tenuo-openshell\""; skip = 1; next }
    skip && /\| tar -xz/ { skip = 0; next }
    { skip = 0; print }'
  echo "using TENUO_QS_CLI=$cli"
fi
DEMO_IMAGE="$(grep -oE 'ghcr\.io/tenuo-ai/tenuo-openshell-demo:v[0-9][^ ]*' "$GUIDE" | head -1)"
MIDDLEWARE_IMAGE="ghcr.io/tenuo-ai/tenuo-openshell:${DEMO_IMAGE##*:}"
if [[ -n "${TENUO_QS_DEMO_IMAGE:-}" ]]; then
  substitute "TENUO_QS_DEMO_IMAGE=$TENUO_QS_DEMO_IMAGE" \
    sed -E "s#ghcr\.io/tenuo-ai/tenuo-openshell-demo:v[0-9][^ ]*#$TENUO_QS_DEMO_IMAGE#g"
  DEMO_IMAGE="$TENUO_QS_DEMO_IMAGE"
  echo "using TENUO_QS_DEMO_IMAGE=$DEMO_IMAGE"
fi
if [[ -n "${TENUO_QS_MIDDLEWARE_IMAGE:-}" ]]; then
  MIDDLEWARE_IMAGE="$TENUO_QS_MIDDLEWARE_IMAGE"
  echo "using TENUO_QS_MIDDLEWARE_IMAGE=$MIDDLEWARE_IMAGE"
fi
export TENUO_OPENSHELL_IMAGE="$MIDDLEWARE_IMAGE" TENUO_OPENSHELL_DEMO_IMAGE="$DEMO_IMAGE"

# --- OpenShell, as install.sh leaves it --------------------------------------

mkdir -p "$BIN" "$XDG_CONFIG_HOME/openshell"
if [[ -n "${TENUO_QS_OPENSHELL_BIN:-}" ]]; then
  cp "$TENUO_QS_OPENSHELL_BIN/openshell" "$TENUO_QS_OPENSHELL_BIN/openshell-gateway" "$BIN/"
else
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) cli_target=aarch64-apple-darwin gateway_target=aarch64-apple-darwin ;;
    Linux/x86_64) cli_target=x86_64-unknown-linux-musl gateway_target=x86_64-unknown-linux-gnu ;;
    Linux/aarch64) cli_target=aarch64-unknown-linux-musl gateway_target=aarch64-unknown-linux-gnu ;;
    *) echo "unsupported platform" >&2; exit 1 ;;
  esac
  release="https://github.com/NVIDIA/OpenShell/releases/download/$OPENSHELL_VERSION"
  curl -fsSL "$release/openshell-$cli_target.tar.gz" | tar -xz -C "$BIN"
  curl -fsSL "$release/openshell-gateway-$gateway_target.tar.gz" | tar -xz -C "$BIN"
fi
openshell --version
openshell-gateway --version

# What the Homebrew formula's post_install writes. The Linux packages ship
# none; the gateway then runs on its defaults.
printf '[openshell]\nversion = 2\n\n[openshell.gateway]\n' >"$GATEWAY_CONFIG"
cp "$GATEWAY_CONFIG" "$WORK/gateway.toml.installed"
# The Linux user service's ExecStartPre steps.
openshell-gateway config preflight
openshell-gateway generate-certs --output-dir "$OPENSHELL_LOCAL_TLS_DIR" \
  --server-san host.openshell.internal

# --- check functions ---------------------------------------------------------
start_gateway() {
  openshell-gateway >>"$GATEWAY_LOG" 2>&1 &
  echo $! >"$GATEWAY_PID_FILE"
  local _
  for _ in $(seq 1 60); do
    kill -0 "$(cat "$GATEWAY_PID_FILE")" 2>/dev/null || {
      echo "the gateway exited; see $GATEWAY_LOG" >&2
      return 1
    }
    if (exec 3<>"/dev/tcp/127.0.0.1/$GATEWAY_PORT") 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "the gateway did not start" >&2
  return 1
}

restart_gateway() {
  local pid
  pid="$(cat "$GATEWAY_PID_FILE")"
  kill "$pid"
  while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done
  openshell-gateway config preflight
  start_gateway
  echo "restarted the gateway"
}

# The reader adds the block `dev up` printed to gateway.toml and restarts the
# gateway. Then `dev up` again must change nothing and find the registration.
check_register_gateway() {
  local printed
  printed="$(tenuo-openshell dev up)"
  echo "$printed" | grep -F "Add this block" >/dev/null
  echo "$printed" | grep -F "$GATEWAY_CONFIG" >/dev/null
  echo "" >>"$GATEWAY_CONFIG"
  echo "$printed" | awk '/^\[\[openshell.supervisor.middleware\]\]$/ { p = 1 } p { print } /^timeout = / { p = 0 }' \
    >>"$GATEWAY_CONFIG"
  echo "--- gateway.toml ---"
  cat "$GATEWAY_CONFIG"
  restart_gateway
  tenuo-openshell dev up | sed 's/^/again: /'
  tenuo-openshell dev status
}

# The reader removes the block and restarts the gateway, which must then start
# without the middleware.
check_unregister_gateway() {
  cp "$WORK/gateway.toml.installed" "$GATEWAY_CONFIG"
  restart_gateway
}
# --- end check functions -----------------------------------------------------

start_gateway
openshell gateway add "https://127.0.0.1:$GATEWAY_PORT" --local --name openshell

if [[ "$(docker info --format '{{.OperatingSystem}}')" == *"Docker Desktop"* ]] \
  && ! docker run --rm --network host --entrypoint python3 "$DEMO_IMAGE" -c \
    "import socket; socket.create_connection(('127.0.0.1', $GATEWAY_PORT), 2)" >/dev/null 2>&1; then
  echo "Docker Desktop host networking is off; forwarding the VM's 127.0.0.1:$GATEWAY_PORT to the gateway"
  docker run -d --name "$FORWARDER" --network host --entrypoint python3 "$DEMO_IMAGE" -c "
import socket, threading
def pipe(a, b):
    try:
        while (data := a.recv(65536)):
            b.sendall(data)
    except OSError:
        pass
    for s in (a, b):
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass
server = socket.create_server(('127.0.0.1', $GATEWAY_PORT))
while True:
    client, _ = server.accept()
    upstream = socket.create_connection(('host.docker.internal', $GATEWAY_PORT))
    for a, b in ((client, upstream), (upstream, client)):
        threading.Thread(target=pipe, args=(a, b), daemon=True).start()
" >/dev/null
fi

# --- Run the guide -----------------------------------------------------------

cd "$WORK"
started="$(date +%s)"
bash "$SCRIPT" 2>&1 | tee "$OUTPUT"
elapsed="$(($(date +%s) - started))"

expect() {
  grep -Fq -- "$1" "$OUTPUT" || {
    echo "FAIL $2" >&2
    exit 1
  }
  echo "PASS $2"
}

expect "middleware  started  http://127.0.0.1:18651  ($MIDDLEWARE_IMAGE)" "dev up started the middleware image"
expect "($DEMO_IMAGE)" "dev up started the demo image"
expect "again: middleware  running" "a second dev up left the middleware running"
expect "already registers this middleware" "a second dev up found the registration"
expect "gateway     registered in $GATEWAY_CONFIG" "dev status found the registration"
expect "approval restart_service needs 1 of 1 approver(s)" "the demo preset gates restart_service"
expect "allowed  read_logs(service=payments, environment=staging): payments/staging" "call inside the task ran"
expect "denied   read_logs(service=identity, environment=production) by the Tenuo agent, before it left the sandbox: constraint-violation" \
  "call outside the task denied in the sandbox"
expect "held     restart_service(service=payments, environment=staging, replicas=3): waiting for approval" "restart held for approval"
expect "approved " "approval installed"
expect "allowed  restart_service(service=payments, environment=staging, replicas=3): restarted payments in staging with 3 replicas" \
  "approved restart ran"
expect "by the Tenuo middleware in OpenShell: tenuo_missing_warrant" "call that skipped the agent denied by the middleware"
[[ "$(grep -c '^RAN ' "$OUTPUT")" == 2 ]] || {
  echo "FAIL the MCP server ran other than the two allowed calls" >&2
  exit 1
}
echo "PASS denied and held calls never reached the MCP server"
expect "restarted the gateway" "the gateway restarted without the middleware"
echo "quickstart passed in ${elapsed}s"
