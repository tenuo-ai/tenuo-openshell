#!/usr/bin/env bash
# Run docs/production-quickstart.md end to end from an empty directory and
# check its outcomes. Every ```bash block in the guide runs, in order, in one
# shell.
# Needs what the guide needs: Docker 28+, curl, jq, and python3.
#
# By default it uses the published artifacts the guide names. To check a
# release candidate before it is published, substitute local builds:
#
#   TENUO_QS_CLI               tenuo-openshell binary for this host, copied
#                              into bin/ instead of the release download
#   TENUO_QS_MIDDLEWARE_IMAGE  local image for ghcr.io/tenuo-ai/tenuo-openshell
#   TENUO_QS_AGENT_IMAGE       local image for ghcr.io/tenuo-ai/tenuo-openshell-agent
#
# The guide itself is not changed; only the script run from it is.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUIDE="$ROOT/docs/production-quickstart.md"
WORK="$(mktemp -d)"
SCRIPT="$WORK/quickstart.sh"
OUTPUT="$WORK/output.log"

# The guide's own cleanup runs last. This one runs only if a step fails first.
cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$status" != 0 ]]; then
    local dir="$WORK/tenuo-quickstart"
    if [[ -d "$dir" ]]; then
      echo "--- gateway.log ---" >&2
      tail -40 "$dir/gateway.log" >&2 2>/dev/null || true
      echo "--- middleware ---" >&2
      docker logs tenuo-quickstart-middleware 2>&1 | tail -40 >&2 || true
      for pid_file in "$dir/gateway.pid" "$dir/mcp.pid"; do
        [[ -f "$pid_file" ]] && kill "$(cat "$pid_file")" 2>/dev/null || true
      done
    fi
    docker ps -aq --filter name=openshell-default--tenuo-quickstart- | xargs docker rm -f >/dev/null 2>&1 || true
    docker rm -f tenuo-quickstart-middleware >/dev/null 2>&1 || true
    docker rmi tenuo-quickstart-sandbox:latest >/dev/null 2>&1 || true
    echo "production quickstart check failed; output in $OUTPUT" >&2
  else
    rm -rf "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT

if docker ps -a --format '{{.Names}}' | grep -qx tenuo-quickstart-middleware; then
  echo "a tenuo-quickstart-middleware container already exists" >&2
  exit 1
fi

{
  echo 'set -eu'
  awk '/^```bash$/ { block = 1; next } /^```$/ { block = 0 } block' "$GUIDE"
} >"$SCRIPT"

# Substitute local artifacts. Each override must match the guide, so a renamed
# artifact fails here instead of silently testing the published one.
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
  echo "using $name"
}
if [[ -n "${TENUO_QS_CLI:-}" ]]; then
  cli="$(cd "$(dirname "$TENUO_QS_CLI")" && pwd)/$(basename "$TENUO_QS_CLI")"
  [[ -x "$cli" ]] || { echo "TENUO_QS_CLI is not executable: $cli" >&2; exit 1; }
  # Replace the two-line release download with a copy of the local binary.
  substitute "TENUO_QS_CLI=$cli" awk -v cli="$cli" '
    /releases\/download\/.*\/tenuo-openshell-v/ { print "cp \"" cli "\" bin/tenuo-openshell"; skip = 1; next }
    skip && /\| tar -xz/ { skip = 0; next }
    { skip = 0; print }'
fi
if [[ -n "${TENUO_QS_MIDDLEWARE_IMAGE:-}" ]]; then
  substitute "TENUO_QS_MIDDLEWARE_IMAGE=$TENUO_QS_MIDDLEWARE_IMAGE" \
    sed -E "s#ghcr\.io/tenuo-ai/tenuo-openshell:v[0-9][^ ]*#$TENUO_QS_MIDDLEWARE_IMAGE#g"
fi
if [[ -n "${TENUO_QS_AGENT_IMAGE:-}" ]]; then
  substitute "TENUO_QS_AGENT_IMAGE=$TENUO_QS_AGENT_IMAGE" \
    sed -E "s#ghcr\.io/tenuo-ai/tenuo-openshell-agent:v[0-9][^ ]*#$TENUO_QS_AGENT_IMAGE#g"
fi

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

[[ "$(grep -c '^wrote tenuo/policy.json.sig$' "$OUTPUT")" == 2 ]] || {
  echo "FAIL each policy version was not signed as it was written" >&2
  exit 1
}
echo "PASS each policy version signed as it was written"
expect '"text": "read_logs ran for payments in staging"' "allowed call ran"
expect '"code":"constraint-violation"' "call outside the warrant denied in the sandbox"
expect '"reason_code":"tenuo_missing_warrant"' "unsigned call denied by the middleware"
expect 'outcome=allow reason=-' "middleware logged the allow"
expect 'outcome=deny reason=tenuo_missing_warrant' "middleware logged the deny"
expect '"text": "restart_service ran for payments in staging"' "widened warrant took effect"
[[ "$(grep -c '^RAN ' "$OUTPUT")" == 1 ]] || {
  echo "FAIL the MCP server ran a denied call" >&2
  exit 1
}
echo "PASS denied calls never reached the MCP server"
echo "production quickstart passed in ${elapsed}s"
