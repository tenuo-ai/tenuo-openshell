#!/usr/bin/env bash
# Track NVIDIA OpenShell past the pin. The pinned v0.1.2 run stays the release
# gate; this script only feeds the scheduled upstream drift job.
#
#   openshell-upstream.sh resolve [REF]      newest commit on REF (default main)
#                                            with published supervisor and
#                                            sandbox images
#   openshell-upstream.sh images COMMIT      the images OpenShell published for
#                                            COMMIT, pinned by digest
#   openshell-upstream.sh proto-drift [REF]  compare the vendored protocol files
#                                            with REF (default main)
#
# resolve and images print KEY=value lines: OPENSHELL_COMMIT,
# TENUO_DEMO_SUPERVISOR_IMAGE, and TENUO_DEMO_SANDBOX_RUNTIME_IMAGE.
# proto-drift prints a Markdown report and exits 1 when the files differ.
# GITHUB_TOKEN, when set, raises the GitHub API rate limit.
#
# Backticks in printf formats below are Markdown code spans.
# shellcheck disable=SC2016
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="NVIDIA/OpenShell"
REGISTRY="ghcr.io"
IMAGE_PREFIX="nvidia/openshell"
# OpenShell's main-branch CI tags both images with the full commit SHA as soon
# as they are built, and moves `dev` only after its integration suite passes.
# A just-pushed commit has no images yet, so resolve walks back this far.
RESOLVE_DEPTH="${OPENSHELL_RESOLVE_DEPTH:-30}"
WORK=""
trap 'rm -rf "${WORK:-}"' EXIT

die() {
  echo "$*" >&2
  exit 1
}

github_api() {
  local auth=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    auth=(--header "Authorization: Bearer $GITHUB_TOKEN")
  fi
  curl -fsSL --retry 3 \
    --header "Accept: application/vnd.github+json" \
    ${auth[@]+"${auth[@]}"} \
    "https://api.github.com/repos/$REPO/$1"
}

# Write file PATH at COMMIT to OUT: raw_file COMMIT PATH OUT. Returns 1 when
# the file does not exist there; any other failure is fatal.
raw_file() {
  local status
  status="$(curl -sSL --retry 3 --output "$3" --write-out '%{http_code}' \
    "https://raw.githubusercontent.com/$REPO/$1/$2")" || die "could not fetch $2 at $1"
  case "$status" in
    200) return 0 ;;
    404) return 1 ;;
    *) die "fetching $2 at $1 returned HTTP $status" ;;
  esac
}

# Print the digest of REPOSITORY:TAG on GHCR, or nothing when the tag is absent.
image_digest() {
  local repository="$1" tag="$2" token
  token="$(curl -fsSL --retry 3 "https://$REGISTRY/token?scope=repository:$IMAGE_PREFIX/$repository:pull" | jq -er .token)" \
    || die "could not get an anonymous $REGISTRY token for $IMAGE_PREFIX/$repository"
  curl -fsS --retry 3 --head \
    --header "Authorization: Bearer $token" \
    --header "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
    "https://$REGISTRY/v2/$IMAGE_PREFIX/$repository/manifests/$tag" 2>/dev/null \
    | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2 }'
}

# Print the KEY=value lines for COMMIT, or return 1 when either image is missing.
images_for() {
  local commit="$1" supervisor sandbox
  supervisor="$(image_digest supervisor "$commit")"
  sandbox="$(image_digest sandbox "$commit")"
  [[ -n "$supervisor" && -n "$sandbox" ]] || return 1
  printf 'OPENSHELL_COMMIT=%s\n' "$commit"
  printf 'TENUO_DEMO_SUPERVISOR_IMAGE=%s/%s/supervisor:%s@%s\n' "$REGISTRY" "$IMAGE_PREFIX" "$commit" "$supervisor"
  printf 'TENUO_DEMO_SANDBOX_RUNTIME_IMAGE=%s/%s/sandbox:%s@%s\n' "$REGISTRY" "$IMAGE_PREFIX" "$commit" "$sandbox"
}

cmd_images() {
  local commit="${1:?usage: openshell-upstream.sh images COMMIT}"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "images takes a full 40-character commit SHA"
  images_for "$commit" || die "OpenShell published no supervisor and sandbox images for $commit"
}

cmd_resolve() {
  local ref="${1:-main}" commits commit tip skipped=0
  commits="$(github_api "commits?sha=$ref&per_page=$RESOLVE_DEPTH" | jq -er '.[].sha')" \
    || die "could not list OpenShell commits on $ref"
  tip="$(head -1 <<<"$commits")"
  for commit in $commits; do
    if images_for "$commit"; then
      if [[ "$skipped" -gt 0 ]]; then
        echo "OpenShell $ref tip $tip has no published images yet; using $commit, $skipped commit(s) behind" >&2
      fi
      return 0
    fi
    skipped=$((skipped + 1))
  done
  die "none of the last $RESOLVE_DEPTH commits on OpenShell $ref has published supervisor and sandbox images"
}

# The vendored directory is the only one under proto/openshell/. Its NOTICE
# names the pinned commit and the upstream source paths.
vendored_dir() {
  local dirs=("$ROOT"/proto/openshell/*/)
  [[ "${#dirs[@]}" == 1 && -f "${dirs[0]}NOTICE" ]] \
    || die "expected exactly one vendored directory with a NOTICE under proto/openshell/"
  printf '%s\n' "${dirs[0]%/}"
}

cmd_proto_drift() {
  local ref="${1:-main}" dir pin commit paths path name work drift=0 changed=() watched
  dir="$(vendored_dir)"
  pin="$(sed -n 's/.*(commit \([0-9a-f]\{40\}\)).*/\1/p' "$dir/NOTICE" | head -1)"
  [[ -n "$pin" ]] || die "$dir/NOTICE does not name the pinned commit"
  paths="$(sed -n 's/^- \(proto\/[^ ]*\.proto\)$/\1/p' "$dir/NOTICE")"
  [[ -n "$paths" ]] || die "$dir/NOTICE lists no source paths"
  commit="$(github_api "commits/$ref" | jq -er .sha)" || die "could not resolve OpenShell $ref"
  WORK="$(mktemp -d)"
  work="$WORK"

  printf '## OpenShell protocol drift\n\n'
  printf -- '- Vendored: `%s` (OpenShell `%s`)\n' "${dir#"$ROOT"/}" "$pin"
  printf -- '- Upstream: `%s` at [`%s`](https://github.com/%s/commit/%s)\n\n' "$ref" "$commit" "$REPO" "$commit"
  printf '| Vendored file | Upstream path | Result |\n|---|---|---|\n'
  for path in $paths; do
    name="$(basename "$path")"
    [[ -f "$dir/$name" ]] || die "$dir/$name is listed in NOTICE but missing"
    if ! raw_file "$commit" "$path" "$work/$name"; then
      printf '| `%s` | `%s` | removed upstream |\n' "$name" "$path"
      : >"$work/$name"
      drift=1
      changed+=("$name")
    elif cmp -s "$dir/$name" "$work/$name"; then
      printf '| `%s` | `%s` | identical |\n' "$name" "$path"
    else
      printf '| `%s` | `%s` | **changed** (%s) |\n' "$name" "$path" \
        "$(diff "$dir/$name" "$work/$name" | awk '/^</ { d++ } /^>/ { a++ } END { printf "+%d -%d lines", a, d }')"
      drift=1
      changed+=("$name")
    fi
  done

  # sandbox.proto is not vendored, but it carries the gateway's middleware
  # registration fields. A change there is worth a look, not a failure.
  watched="proto/sandbox.proto"
  if raw_file "$pin" "$watched" "$work/pin-sandbox.proto" && raw_file "$commit" "$watched" "$work/upstream-sandbox.proto"; then
    if cmp -s "$work/pin-sandbox.proto" "$work/upstream-sandbox.proto"; then
      printf '| (not vendored) | `%s` | identical to the pin |\n' "$watched"
    else
      printf '| (not vendored) | `%s` | changed since the pin; review the middleware registration fields |\n' "$watched"
    fi
  fi

  if [[ "$drift" == 0 ]]; then
    printf '\nNo drift: the vendored files match `%s`.\n' "$ref"
    return 0
  fi
  printf '\nThe vendored contract differs from `%s`. Review the diff before moving the pin; see `docs/upstream-verification.md`.\n' "$ref"
  for name in "${changed[@]}"; do
    printf '\n<details><summary><code>%s</code></summary>\n\n```diff\n' "$name"
    diff -u --label "vendored/$name" --label "$ref/$name" "$dir/$name" "$work/$name" | head -400 || true
    printf '```\n\n</details>\n'
  done
  return 1
}

case "${1:-}" in
  resolve) shift; cmd_resolve "$@" ;;
  images) shift; cmd_images "$@" ;;
  proto-drift) shift; cmd_proto_drift "$@" ;;
  *)
    sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
