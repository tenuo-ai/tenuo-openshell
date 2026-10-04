#!/usr/bin/env bash
# Build, smoke-test, and package release binaries for one target.
#
#   ci/release-binary.sh <tag> <target> <out-dir> <binary>...
#
# Writes <out-dir>/<binary>-<tag>-<target>.tar.gz with the binary and LICENSE
# at the top level. Fails if a binary's --version does not match the tag, if a
# Linux binary links a shared library, or if the agent smoke test fails.
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: $0 <tag> <target> <out-dir> <binary>..." >&2
  exit 2
fi

tag="$1"
target="$2"
out="$3"
shift 3
version="${tag#v}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

case "$target" in
  *-linux-musl)
    # ring compiles C; use the musl toolchain from musl-tools for it.
    export "CC_${target//-/_}=musl-gcc"
    ;;
esac

# Keep macOS tar from adding AppleDouble files.
export COPYFILE_DISABLE=1

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for bin in "$@"; do
  case "$bin" in
    tenuo-openshell-agent) package=tenuo-openshell-agent ;;
    tenuo-openshell) package=tenuo-openshell-middleware ;;
    *)
      echo "unknown binary: $bin" >&2
      exit 2
      ;;
  esac

  cargo build --release --locked --target "$target" -p "$package" --bin "$bin"
  path="${CARGO_TARGET_DIR:-target}/$target/release/$bin"

  reported="$("$path" --version)"
  if [ "$reported" != "$bin $version" ]; then
    echo "$bin --version printed '$reported', expected '$bin $version'" >&2
    exit 1
  fi
  "$path" --help >/dev/null

  if [[ "$target" == *-linux-* ]] && readelf -d "$path" | grep -F NEEDED; then
    echo "$bin links shared libraries; expected a static binary" >&2
    exit 1
  fi

  if [ "$bin" = tenuo-openshell-agent ]; then
    home="$work/home"
    mkdir -p "$home"
    holder="$(HOME="$home" "$path" keygen)"
    if ! [[ "$holder" =~ ^[0-9a-f]{64}$ ]]; then
      echo "keygen printed '$holder', expected a hex public key" >&2
      exit 1
    fi
    test "$(wc -c <"$home/.tenuo/holder.key" | tr -d ' ')" = 32
    status=0
    HOME="$home" "$path" status >/dev/null 2>"$work/status.err" || status=$?
    if [ "$status" != 1 ] || ! grep -F "no warrant has been installed" "$work/status.err" >/dev/null; then
      echo "status without a warrant exited $status:" >&2
      cat "$work/status.err" >&2
      exit 1
    fi
    rm -rf "$home"
  fi

  stage="$work/$bin-$target"
  mkdir "$stage"
  cp "$path" LICENSE "$stage/"
  tar -C "$stage" -czf "$out/$bin-$tag-$target.tar.gz" "$bin" LICENSE
  echo "packaged $out/$bin-$tag-$target.tar.gz"
done
