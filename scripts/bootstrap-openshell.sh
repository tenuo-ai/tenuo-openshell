#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="v0.1.2"
COMMIT="6648bd0c290efbc41ba131ee9831ee45cd431f94"
CHECKOUT="${OPENSHELL_SOURCE:-$ROOT/.cache/openshell/$TAG}"

if [[ ! -d "$CHECKOUT/.git" ]]; then
  mkdir -p "$CHECKOUT"
  git init -q "$CHECKOUT"
  git -C "$CHECKOUT" remote add origin https://github.com/NVIDIA/OpenShell.git
fi

if [[ "$(git -C "$CHECKOUT" rev-parse HEAD 2>/dev/null || true)" != "$COMMIT" ]]; then
  git -C "$CHECKOUT" fetch --depth 1 origin "refs/tags/$TAG"
  actual="$(git -C "$CHECKOUT" rev-parse FETCH_HEAD)"
  if [[ "$actual" != "$COMMIT" ]]; then
    echo "OpenShell $TAG resolved to unexpected commit $actual" >&2
    exit 1
  fi
  git -C "$CHECKOUT" switch --detach "$COMMIT" >/dev/null
fi

printf '%s\n' "$CHECKOUT"
