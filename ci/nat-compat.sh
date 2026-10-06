#!/usr/bin/env bash
# Run the Agent Toolkit plugin tests and entry-point discovery against one
# NeMo Agent Toolkit minor release, outside the locked environment.
#
#   ci/nat-compat.sh 1.8 [python]
#   ci/nat-compat.sh 1.10.0rc1 [python]
#
# The locked environment (make check) covers the newest supported release.
# A minor release (1.8) covers the others in the supported range. An exact
# version, pre-releases included, is installed even when it is outside the
# plugin's declared range: the upstream drift workflow uses it to try the
# next Agent Toolkit release before the range moves.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAT_MINOR="${1:?usage: ci/nat-compat.sh <nat minor, e.g. 1.8> [python]}"
PYTHON="${2:-3.12}"
PLUGIN="$ROOT/python/nemo-agent-toolkit-tenuo"
VENV="$(mktemp -d)/venv"
trap 'rm -rf "$(dirname "$VENV")"' EXIT

uv venv --quiet --python "$PYTHON" "$VENV"
if [[ "$NAT_MINOR" =~ ^[0-9]+\.[0-9]+$ ]]; then
  uv pip install --quiet --python "$VENV/bin/python" \
    "$PLUGIN[test]" "nvidia-nat-core==$NAT_MINOR.*" "nvidia-nat-test==$NAT_MINOR.*"
else
  overrides="$(dirname "$VENV")/overrides.txt"
  printf 'nvidia-nat-core==%s\nnvidia-nat-test==%s\n' "$NAT_MINOR" "$NAT_MINOR" >"$overrides"
  uv pip install --quiet --python "$VENV/bin/python" --prerelease allow \
    --override "$overrides" "$PLUGIN[test]"
fi

installed="$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("nvidia-nat-core"))')"
tenuo_installed="$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("tenuo"))')"
case "$installed" in
  "$NAT_MINOR" | "$NAT_MINOR".*) echo "INFO nvidia-nat-core $installed, tenuo $tenuo_installed, Python $PYTHON" ;;
  *) echo "FAIL expected nvidia-nat-core $NAT_MINOR, got $installed" >&2; exit 1 ;;
esac

# Run from the plugin directory so pytest reads its configuration
# (asyncio mode and the src path). The entry-point test needs the installed
# distribution's metadata.
(cd "$PLUGIN" && "$VENV/bin/python" -m pytest tests -q -p no:cacheprovider)
"$VENV/bin/nat" info components | grep -F tenuo >/dev/null
echo "PASS nvidia-nat-core $installed"
