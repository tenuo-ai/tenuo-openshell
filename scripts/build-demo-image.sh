#!/usr/bin/env bash
# Build the demo image (deploy/demo-image) locally, for this machine's
# platform.
#
#   scripts/build-demo-image.sh <tag> [<agent-image>]
#
# The agent binary comes from <agent-image> when given, for example
# ghcr.io/tenuo-ai/tenuo-openshell-agent:v0.1.3. Otherwise it is built from
# this checkout as a static musl binary, as the release builds it.
#
# release.yml stages the attested release binary instead.
set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  echo "usage: $0 <tag> [<agent-image>]" >&2
  exit 2
fi
tag="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arch="$(docker version --format '{{.Server.Arch}}')"

work="$(mktemp -d)"
container=""
built=""
cleanup() {
  [[ -n "$container" ]] && docker rm -f "$container" >/dev/null 2>&1 || true
  [[ -n "$built" ]] && docker rmi "$built" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

agent_image="${2:-}"
if [[ -z "$agent_image" ]]; then
  built="tenuo-openshell-agent-build:$$"
  agent_image="$built"
  docker build -q -t "$built" -f - "$ROOT" >/dev/null <<'EOF'
FROM rust:1.91-alpine
RUN apk add --no-cache musl-dev
WORKDIR /source
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
COPY agent ./agent
COPY fuzz/Cargo.toml ./fuzz/
COPY fuzz/fuzz_targets ./fuzz/fuzz_targets
RUN cargo build --release --locked -p tenuo-openshell-agent --bin tenuo-openshell-agent \
    && cp target/release/tenuo-openshell-agent /usr/local/bin/
EOF
fi

mkdir -p "$work/$arch"
container="$(docker create "$agent_image")"
docker cp -q "$container:/usr/local/bin/tenuo-openshell-agent" "$work/$arch/tenuo-openshell-agent"
cp "$ROOT/LICENSE" "$ROOT/deploy/demo-image/Dockerfile" "$ROOT/deploy/demo-image/tenuo-demo-mcp" "$work/"
docker build -q -t "$tag" "$work" >/dev/null
echo "built $tag"
