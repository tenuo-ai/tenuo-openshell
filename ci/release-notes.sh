#!/usr/bin/env bash
# Print the CHANGELOG.md section for a release tag, without its heading.
# Fails when the section is missing or empty.
set -euo pipefail

tag="${1:?usage: ci/release-notes.sh vX.Y.Z}"
version="${tag#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"

notes="$(awk -v version="$version" '
  index($0, "## [" version "]") == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found && /^\[[^]]+\]: / { next }
  found { print }
' "$root/CHANGELOG.md")"

if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "CHANGELOG.md has no notes for $version" >&2
  exit 1
fi
printf '%s\n' "$notes"
