#!/usr/bin/env bash
# Build the NeMo Agent Toolkit sandbox image (deploy/nat-demo-image) locally,
# for this machine's platform.
#
#   scripts/build-nat-demo-image.sh <tag> [<agent-image>]
#
# The agent binary comes from <agent-image> when given, for example
# ghcr.io/tenuo-ai/tenuo-openshell-agent:v0.1.6. Otherwise it is built from
# this checkout as a static musl binary, as the release builds it. The
# nemo-agent-toolkit-tenuo plugin is built from this checkout with uv.
#
# release.yml stages the attested release binary instead.
set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  echo "usage: $0 <tag> [<agent-image>]" >&2
  exit 2
fi
tag="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v uv >/dev/null 2>&1 || {
  echo "missing prerequisite: uv" >&2
  exit 2
}
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
  docker build -q -t "$built" -f - "$ROOT" >/dev/null <<'DOCKERFILE'
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
DOCKERFILE
fi

mkdir -p "$work/$arch"
container="$(docker create "$agent_image")"
docker cp -q "$container:/usr/local/bin/tenuo-openshell-agent" "$work/$arch/tenuo-openshell-agent"
uv build --quiet --wheel --project "$ROOT/python/nemo-agent-toolkit-tenuo" --out-dir "$work"
image="$ROOT/deploy/nat-demo-image"
cp "$ROOT/LICENSE" "$image/Dockerfile" "$image/requirements.txt" "$image/tenuo-nat-run" \
  "$image/scripted.yml" "$image/scripted-plugin.yml" "$image/nim.yml" "$ROOT/examples/nemo-agent-toolkit/scripted_llm.py" "$work/"
docker build -q -t "$tag" "$work" >/dev/null
echo "built $tag"
