#!/usr/bin/env bash
# Check out NVIDIA OpenShell and print the checkout directory.
#
# By default this is the pinned release: TAG, verified against COMMIT. With
# OPENSHELL_REF set to a branch, tag, or full commit SHA, it checks out that
# ref instead, in its own cache directory, and records the resolved commit in
# .cache/openshell/upstream.commit. The pin stays the release gate; a ref only
# tracks upstream drift.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="v0.1.2"
COMMIT="6648bd0c290efbc41ba131ee9831ee45cd431f94"
REF="${OPENSHELL_REF:-}"

if [[ -z "$REF" ]]; then
  CHECKOUT="${OPENSHELL_SOURCE:-$ROOT/.cache/openshell/$TAG}"
else
  # One directory for every upstream ref, so successive runs build incrementally.
  CHECKOUT="${OPENSHELL_SOURCE:-$ROOT/.cache/openshell/upstream}"
fi

if [[ ! -d "$CHECKOUT/.git" ]]; then
  mkdir -p "$CHECKOUT"
  git init -q "$CHECKOUT"
  git -C "$CHECKOUT" remote add origin https://github.com/NVIDIA/OpenShell.git
fi

if [[ -z "$REF" ]]; then
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
  exit 0
fi

if [[ "$REF" == -* || "$REF" == *..* ]]; then
  echo "OPENSHELL_REF must be a branch, tag, or commit SHA: $REF" >&2
  exit 2
fi
# A branch or tag can move, so fetch it every time. A commit SHA that is
# already checked out needs no network.
if [[ "$REF" =~ ^[0-9a-f]{40}$ && "$(git -C "$CHECKOUT" rev-parse HEAD 2>/dev/null || true)" == "$REF" ]]; then
  actual="$REF"
else
  git -C "$CHECKOUT" fetch --quiet --depth 1 origin "$REF" >&2
  actual="$(git -C "$CHECKOUT" rev-parse 'FETCH_HEAD^{commit}')"
  if [[ "$REF" =~ ^[0-9a-f]{40}$ && "$actual" != "$REF" ]]; then
    echo "OpenShell $REF resolved to unexpected commit $actual" >&2
    exit 1
  fi
  git -C "$CHECKOUT" switch --quiet --detach "$actual"
fi
mkdir -p "$ROOT/.cache/openshell"
printf '%s %s\n' "$REF" "$actual" >"$ROOT/.cache/openshell/upstream.commit"
echo "OpenShell $REF resolved to $actual" >&2
printf '%s\n' "$CHECKOUT"
