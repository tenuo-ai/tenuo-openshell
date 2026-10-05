#!/usr/bin/env bash
# Run docs/quickstart.md end to end against an OpenShell gateway laid out the
# way OpenShell's install.sh installs it, and check its outcomes.
#
# TENUO_QS_GUIDE=nat-agent runs docs/nat-agent.md instead, which starts where
# the quickstart's step 2 ends: the quickstart's blocks up to its gateway
# registration run first. The guide's section between
# `<!-- check: manual-begin -->` and `<!-- check: manual-end -->` needs an
# NVIDIA API key and is not run.
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
#   TENUO_QS_NAT_IMAGE         local image for ghcr.io/tenuo-ai/tenuo-openshell-nat-demo,
#                              for the nat-agent guide
#                              (scripts/build-nat-demo-image.sh builds one)
#   TENUO_QS_OPENSHELL_BIN     directory that already holds the OpenShell v0.1.2
#                              openshell and openshell-gateway for this host
#
# TENUO_QS_GATEWAY=installed runs the guide against the OpenShell this host
# already has, installed with install.sh and with its local gateway running,
# instead of the stand-in: the `openshell` on PATH, and the gateway's own
# gateway.toml and restart command. It knows the deb and rpm packages' systemd
# user service (~/.config/openshell/gateway.toml) and the snap
# (/var/snap/openshell/common/gateway.toml, edited with sudo; its sandbox
# policy path is the one the guide gives for the snap). gateway.toml is
# restored, and the gateway restarted, when the check ends. The guide's dev
# state directory is used as written; one already there is moved aside and
# put back. .github/workflows/linux-install.yml runs this mode.
#
# The guide itself is not changed; only the script run from it is.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUICKSTART="$ROOT/docs/quickstart.md"
export GUIDE_NAME="${TENUO_QS_GUIDE:-quickstart}"
case "$GUIDE_NAME" in
  quickstart) SANDBOX=tenuo-demo POLICY_FILE=demo-policy.yaml ;;
  nat-agent) SANDBOX=tenuo-nat POLICY_FILE=nat-policy.yaml ;;
  *)
    echo "TENUO_QS_GUIDE must be quickstart or nat-agent, not $GUIDE_NAME" >&2
    exit 2
    ;;
esac
GUIDE="$ROOT/docs/$GUIDE_NAME.md"
OPENSHELL_VERSION=v0.1.2
GATEWAY_PORT=17670
FORWARDER=tenuo-quickstart-loopback
export MODE="${TENUO_QS_GATEWAY:-standin}"
case "$MODE" in
  standin | installed) ;;
  *)
    echo "TENUO_QS_GATEWAY must be standin or installed, not $MODE" >&2
    exit 2
    ;;
esac

prerequisites=(docker curl jq python3)
[[ "$MODE" == installed ]] && prerequisites+=(openshell)
for command in "${prerequisites[@]}"; do
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
if [[ "$MODE" == standin ]] && (exec 3<>"/dev/tcp/127.0.0.1/$GATEWAY_PORT") 2>/dev/null; then
  echo "something already listens on 127.0.0.1:$GATEWAY_PORT, likely an installed OpenShell gateway; stop it first," >&2
  echo "or check against it with TENUO_QS_GATEWAY=installed" >&2
  exit 1
fi

# The installed gateway: where its gateway.toml is and how it restarts.
export INSTALL=standin
if [[ "$MODE" == installed ]]; then
  if command -v snap >/dev/null 2>&1 && snap list openshell >/dev/null 2>&1; then
    INSTALL=snap
    GATEWAY_CONFIG=/var/snap/openshell/common/gateway.toml
  elif command -v systemctl >/dev/null 2>&1 && systemctl --user cat openshell-gateway >/dev/null 2>&1; then
    INSTALL=systemd
    GATEWAY_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateway.toml"
  else
    echo "no installed OpenShell gateway: neither the openshell snap nor the openshell-gateway" >&2
    echo "systemd user service. Install OpenShell with its install.sh first." >&2
    exit 1
  fi
  if ! NO_COLOR=1 openshell status 2>&1 | grep -q "Version:"; then
    echo "the installed OpenShell gateway is not running or not registered; \`openshell status\` must connect" >&2
    exit 1
  fi
  echo "using the installed OpenShell gateway ($INSTALL), $GATEWAY_CONFIG"
fi

WORK="$(mktemp -d)"
WORK="$(cd "$WORK" && pwd -P)"
export WORK
SCRIPT="$WORK/quickstart.sh"
OUTPUT="$WORK/output.log"
export BIN="$WORK/bin"
if [[ "$MODE" == standin ]]; then
  export XDG_CONFIG_HOME="$WORK/config"
  export XDG_STATE_HOME="$WORK/state"
  export OPENSHELL_LOCAL_TLS_DIR="$XDG_STATE_HOME/openshell/tls"
  GATEWAY_CONFIG="$XDG_CONFIG_HOME/openshell/gateway.toml"
fi
# Where `dev up` keeps its state, which the guide names.
export DEV_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/tenuo-openshell/dev"
export GATEWAY_CONFIG
export GATEWAY_LOG="$WORK/gateway.log"
export GATEWAY_PID_FILE="$WORK/gateway.pid"
export GATEWAY_PORT
export PATH="$BIN:$PATH"
unset OPENSHELL_GATEWAY OPENSHELL_GATEWAY_ENDPOINT TENUO_OPENSHELL_DEV_DIR
# The CLI's default images follow its version. The guide's images replace
# them below, so `dev up` runs what the guide names.
unset TENUO_OPENSHELL_IMAGE TENUO_OPENSHELL_DEMO_IMAGE

# --- check functions ---------------------------------------------------------
# Also defined in the script run from the guide.

# A snap's gateway.toml is root's.
as_config_owner() {
  if [[ "$INSTALL" == snap ]]; then sudo "$@"; else "$@"; fi
}

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

# Wait until the installed gateway answers `openshell status`, as install.sh
# does after it starts the service.
wait_for_installed_gateway() {
  local _ state
  for _ in $(seq 1 90); do
    if NO_COLOR=1 openshell status 2>&1 | grep -q "Version:"; then
      return 0
    fi
    if [[ "$INSTALL" == systemd ]]; then
      state="$(systemctl --user show openshell-gateway -p ActiveState -p SubState)"
      if [[ "$state" == *ActiveState=failed* || "$state" == *SubState=auto-restart* ]]; then
        echo "the openshell-gateway service failed: $state" >&2
        return 1
      fi
    fi
    sleep 1
  done
  echo "the gateway did not come back" >&2
  return 1
}

# The guide's restart command for this install.
restart_gateway() {
  case "$INSTALL" in
    standin)
      local pid
      pid="$(cat "$GATEWAY_PID_FILE")"
      kill "$pid"
      while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done
      openshell-gateway config preflight
      start_gateway
      ;;
    systemd)
      systemctl --user restart openshell-gateway
      wait_for_installed_gateway
      ;;
    snap)
      sudo snap restart openshell.gateway
      wait_for_installed_gateway
      ;;
  esac
  echo "restarted the gateway"
}

# Put gateway.toml back as it was installed. Fails when it had changed.
restore_gateway_config() {
  if [[ -e "$WORK/gateway.toml.installed" ]]; then
    as_config_owner cmp -s "$WORK/gateway.toml.installed" "$GATEWAY_CONFIG" && return 0
    # tee keeps the file's owner and mode.
    as_config_owner tee "$GATEWAY_CONFIG" <"$WORK/gateway.toml.installed" >/dev/null
  else
    as_config_owner test -e "$GATEWAY_CONFIG" || return 0
    as_config_owner rm -f "$GATEWAY_CONFIG"
  fi
  return 1
}

# The reader adds the block `dev up` printed to gateway.toml, creating the
# file as `dev up` says when the install has none, and restarts the gateway.
# Then `dev up` again must change nothing and find the registration.
check_register_gateway() {
  local printed block
  printed="$(tenuo-openshell dev up)"
  echo "$printed" | grep -F "$GATEWAY_CONFIG" >/dev/null
  block="$(echo "$printed" | awk '/^\[\[openshell.supervisor.middleware\]\]$/ { p = 1 } p { print } /^timeout = / { p = 0 }')"
  if echo "$printed" | grep -F "Add this block" >/dev/null; then
    printf '\n%s\n' "$block" | as_config_owner tee -a "$GATEWAY_CONFIG" >/dev/null
  elif [[ "$MODE" == installed ]] && echo "$printed" | grep -F "Create" >/dev/null; then
    mkdir -p "$(dirname "$GATEWAY_CONFIG")"
    printf '[openshell]\nversion = 2\n\n%s\n' "$block" | as_config_owner tee "$GATEWAY_CONFIG" >/dev/null
  else
    echo "dev up printed no instruction for $GATEWAY_CONFIG" >&2
    return 1
  fi
  echo "--- gateway.toml ---"
  as_config_owner cat "$GATEWAY_CONFIG"
  restart_gateway
  tenuo-openshell dev up | sed 's/^/again: /'
  tenuo-openshell dev status
}

# The reader removes the block and restarts the gateway, which must then start
# without the middleware.
check_unregister_gateway() {
  restore_gateway_config || true
  restart_gateway
}
# --- end check functions -----------------------------------------------------

# gateway.toml as it was before the guide, to restore.
if [[ "$MODE" == installed ]]; then
  if as_config_owner test -e "$GATEWAY_CONFIG"; then
    as_config_owner cat "$GATEWAY_CONFIG" >"$WORK/gateway.toml.installed"
  fi
  if [[ -e "$DEV_DIR" ]]; then
    mv "$DEV_DIR" "$WORK/dev.saved"
    echo "moved $DEV_DIR aside; it is put back at the end"
  fi
  # Where `dev up` copies the demo policy for the snap's CLI.
  SNAP_POLICY_DIR="$HOME/snap/openshell/common/tenuo-openshell"
  if [[ "$INSTALL" == snap && -e "$SNAP_POLICY_DIR" ]]; then
    mv "$SNAP_POLICY_DIR" "$WORK/snap-policy.saved"
  fi
fi

gateway_log() {
  case "$INSTALL" in
    standin) tail -30 "$GATEWAY_LOG" 2>/dev/null ;;
    systemd) journalctl --user -u openshell-gateway --no-pager -n 30 2>/dev/null ;;
    snap) sudo journalctl -u snap.openshell.gateway --no-pager -n 30 2>/dev/null ;;
  esac
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$status" != 0 ]]; then
    echo "--- gateway log ---" >&2
    gateway_log >&2 || true
    echo "--- middleware ---" >&2
    docker logs tenuo-openshell-dev 2>&1 | tail -30 >&2 || true
  fi
  local id
  if id="$(openshell sandbox get "$SANDBOX" -o json 2>/dev/null | jq -er .id)"; then
    openshell sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
    docker ps -aq --filter "label=openshell.ai/sandbox-id=$id" | xargs docker rm -f >/dev/null 2>&1 || true
  fi
  if [[ -f "$GATEWAY_PID_FILE" ]]; then
    kill "$(cat "$GATEWAY_PID_FILE")" 2>/dev/null || true
  fi
  if [[ "$MODE" == installed ]]; then
    # Put gateway.toml back, if the guide did not get that far.
    if ! restore_gateway_config; then
      echo "restoring $GATEWAY_CONFIG" >&2
      restart_gateway >&2 || echo "the gateway did not come back; check it" >&2
    fi
    if [[ -e "$DEV_DIR" ]]; then
      mv "$DEV_DIR" "$WORK/dev"
    fi
    if [[ -e "$WORK/dev.saved" ]]; then
      mv "$WORK/dev.saved" "$DEV_DIR"
    fi
    if [[ "$INSTALL" == snap ]]; then
      rm -rf "$SNAP_POLICY_DIR"
      if [[ -e "$WORK/snap-policy.saved" ]]; then
        mv "$WORK/snap-policy.saved" "$SNAP_POLICY_DIR"
      fi
    fi
  fi
  docker rm -f tenuo-openshell-dev tenuo-openshell-dev-mcp "$FORWARDER" >/dev/null 2>&1 || true
  if [[ "$status" != 0 ]]; then
    echo "$GUIDE_NAME check failed; output in $OUTPUT" >&2
  else
    rm -rf "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT

# --- The guide, with local substitutions -------------------------------------

# A guide's ```bash blocks and check markers, in order. With stop=NAME, the
# blocks end at the marker check: NAME.
guide_script() {
  awk -v stop="${2:-}" '
    /^<!-- check: manual-begin -->$/ { manual = 1; next }
    /^<!-- check: manual-end -->$/ { manual = 0; next }
    manual { next }
    /^<!-- check: [a-z-]+ -->$/ {
      name = $3; gsub("-", "_", name); print "check_" name
      if ($3 == stop) exit
      next
    }
    /^```bash$/ { block = 1; next }
    /^```$/ { block = 0 }
    block' "$1"
}

{
  echo 'set -eu'
  # The functions a check marker calls.
  sed -n '/^# --- check functions/,/^# --- end check functions/p' "${BASH_SOURCE[0]}"
  if [[ "$GUIDE_NAME" == nat-agent ]]; then
    # Where the guide starts: the quickstart through its gateway registration.
    guide_script "$QUICKSTART" register-gateway
  fi
  guide_script "$GUIDE"
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
substitute "dev state directory" sed "s#~/.local/state/tenuo-openshell/dev#\"\$DEV_DIR\"#g"
if [[ "$INSTALL" == snap ]]; then
  # The guide's instruction for the snap, whose CLI cannot read ~/.local.
  # shellcheck disable=SC2088 # expanded in the script run from the guide
  snap_policy="~/snap/openshell/common/tenuo-openshell/$POLICY_FILE"
  grep -Fq -- "--policy $snap_policy" "$GUIDE" || {
    echo "the guide no longer gives the snap's sandbox policy path" >&2
    exit 1
  }
  substitute "snap sandbox policy" \
    sed "s#--policy \"\$DEV_DIR\"/$POLICY_FILE#--policy $snap_policy#"
fi
# Nothing answers the approval prompt.
substitute "unattended approval" sed "s#^tenuo-openshell approve --dev #tenuo-openshell approve --yes --dev #"
if [[ -n "${TENUO_QS_CLI:-}" ]]; then
  cli="$(cd "$(dirname "$TENUO_QS_CLI")" && pwd)/$(basename "$TENUO_QS_CLI")"
  [[ -x "$cli" ]] || { echo "TENUO_QS_CLI is not executable: $cli" >&2; exit 1; }
  # Replace the two-line release download with a copy of the local binary.
  # shellcheck disable=SC2016 # $BIN is expanded in the generated script.
  substitute "TENUO_QS_CLI=$cli" awk -v cli="$cli" '
    /releases\/download\/.*\/tenuo-openshell-v/ { print "cp \"" cli "\" \"$BIN/tenuo-openshell\""; skip = 1; next }
    skip && /\| tar -xz/ { skip = 0; next }
    { skip = 0; print }'
  echo "using TENUO_QS_CLI=$cli"
fi
DEMO_IMAGE="$(grep -oE 'ghcr\.io/tenuo-ai/tenuo-openshell-demo:v[0-9][^ ]*' "$QUICKSTART" | head -1)"
MIDDLEWARE_IMAGE="ghcr.io/tenuo-ai/tenuo-openshell:${DEMO_IMAGE##*:}"
if [[ -n "${TENUO_QS_DEMO_IMAGE:-}" ]]; then
  # dev up runs it as the demo MCP server; only the quickstart names it.
  if [[ "$GUIDE_NAME" == quickstart ]]; then
    substitute "TENUO_QS_DEMO_IMAGE=$TENUO_QS_DEMO_IMAGE" \
      sed -E "s#ghcr\.io/tenuo-ai/tenuo-openshell-demo:v[0-9][^ ]*#$TENUO_QS_DEMO_IMAGE#g"
  fi
  DEMO_IMAGE="$TENUO_QS_DEMO_IMAGE"
  echo "using TENUO_QS_DEMO_IMAGE=$DEMO_IMAGE"
fi
if [[ "$GUIDE_NAME" == nat-agent ]]; then
  NAT_IMAGE="$(grep -oE 'ghcr\.io/tenuo-ai/tenuo-openshell-nat-demo:v[0-9][^ ]*' "$GUIDE" | head -1)"
  [[ "${NAT_IMAGE##*:}" == "${DEMO_IMAGE##*:}" || -n "${TENUO_QS_DEMO_IMAGE:-}" ]] || {
    echo "the guides name different releases: $NAT_IMAGE and $DEMO_IMAGE" >&2
    exit 1
  }
  if [[ -n "${TENUO_QS_NAT_IMAGE:-}" ]]; then
    substitute "TENUO_QS_NAT_IMAGE=$TENUO_QS_NAT_IMAGE" \
      sed -E "s#ghcr\.io/tenuo-ai/tenuo-openshell-nat-demo:v[0-9][^ ]*#$TENUO_QS_NAT_IMAGE#g"
    echo "using TENUO_QS_NAT_IMAGE=$TENUO_QS_NAT_IMAGE"
  fi
fi
if [[ -n "${TENUO_QS_MIDDLEWARE_IMAGE:-}" ]]; then
  MIDDLEWARE_IMAGE="$TENUO_QS_MIDDLEWARE_IMAGE"
  echo "using TENUO_QS_MIDDLEWARE_IMAGE=$MIDDLEWARE_IMAGE"
fi
export TENUO_OPENSHELL_IMAGE="$MIDDLEWARE_IMAGE" TENUO_OPENSHELL_DEMO_IMAGE="$DEMO_IMAGE"

# --- OpenShell, as install.sh leaves it --------------------------------------

mkdir -p "$BIN"
if [[ "$MODE" == standin ]]; then
  mkdir -p "$XDG_CONFIG_HOME/openshell"
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
  openshell-gateway --version
fi
openshell --version

if [[ "$MODE" == standin ]]; then
  # What the Homebrew formula's post_install writes. The Linux packages ship
  # none; the gateway then runs on its defaults.
  printf '[openshell]\nversion = 2\n\n[openshell.gateway]\n' >"$GATEWAY_CONFIG"
  cp "$GATEWAY_CONFIG" "$WORK/gateway.toml.installed"
  # The Linux user service's ExecStartPre steps.
  openshell-gateway config preflight
  openshell-gateway generate-certs --output-dir "$OPENSHELL_LOCAL_TLS_DIR" \
    --server-san host.openshell.internal
fi


if [[ "$MODE" == standin ]]; then
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
fi

# --- Run the guide -----------------------------------------------------------

cd "$WORK"
started="$(date +%s)"
# Nothing types into the guide: `openshell sandbox exec` forwards its
# standard input, and waits for it to end.
bash "$SCRIPT" </dev/null 2>&1 | tee "$OUTPUT"
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
if [[ "$INSTALL" == snap ]]; then
  # Only root reads the snap's gateway.toml; `dev up` says it cannot check it.
  expect "again:    to the end of $GATEWAY_CONFIG, with sudo. \`dev up\` cannot read that file," \
    "a second dev up said it cannot read the snap's gateway.toml"
  expect "gateway     cannot read $GATEWAY_CONFIG" "dev status said it cannot read the snap's gateway.toml"
else
  expect "already registers this middleware" "a second dev up found the registration"
  expect "gateway     registered in $GATEWAY_CONFIG" "dev status found the registration"
fi
expect "approval restart_service needs 1 of 1 approver(s)" "the demo preset gates restart_service"
ran() {
  [[ "$(grep -c '^RAN ' "$OUTPUT")" == "$1" ]] || {
    echo "FAIL the MCP server ran other than the $1 allowed calls" >&2
    exit 1
  }
  echo "PASS denied and held calls never reached the MCP server"
}
case "$GUIDE_NAME" in
  quickstart)
    expect "allowed  read_logs(service=payments, environment=staging): payments/staging" "call inside the task ran"
    expect "denied   read_logs(service=identity, environment=production) by the Tenuo agent, before it left the sandbox: constraint-violation" \
      "call outside the task denied in the sandbox"
    expect "held     restart_service(service=payments, environment=staging, replicas=3): waiting for approval" "restart held for approval"
    expect "approved " "approval installed"
    expect "allowed  restart_service(service=payments, environment=staging, replicas=3): restarted payments in staging with 3 replicas" \
      "approved restart ran"
    expect "by the Tenuo middleware in OpenShell: tenuo_missing_warrant" "call that skipped the agent denied by the middleware"
    ran 2
    ;;
  nat-agent)
    expect "allowed  read_logs(service=payments, environment=staging): payments/staging" "the agent's read inside the task ran"
    expect "answer   read_logs ran: payments/staging" "the agent answered with the logs"
    expect "denied   read_logs(service=identity, environment=production): Authorization denied: Constraint not satisfied" \
      "the agent's read outside the task denied by the proxy"
    expect "answer   read_logs did not run: Authorization denied: Constraint not satisfied." "the agent read the denial"
    expect "approved " "approval installed"
    expect "allowed  restart_service(service=payments, environment=staging, replicas=3): restarted payments in staging with 3 replicas" \
      "the agent's approved restart ran"
    # Before the approval, after it was spent, and through the plugin.
    [[ "$(grep -c '^held     restart_service(service=payments, environment=staging, replicas=3): waiting for approval' "$OUTPUT")" == 3 ]] || {
      echo "FAIL the agent's restart was not held three times" >&2
      exit 1
    }
    echo "PASS restart held for approval, again once the approval was spent, and through the plugin"
    expect "<urlopen error [Errno 13] Permission denied>" "the agent's Python could not reach the MCP server"
    expect "denied   read_logs(service=identity, environment=production): Authorization denied (constraint_violation, ref=" \
      "the plugin denied the read outside the task in the agent"
    ran 2
    ;;
esac
expect "restarted the gateway" "the gateway restarted without the middleware"
echo "$GUIDE_NAME passed in ${elapsed}s"
