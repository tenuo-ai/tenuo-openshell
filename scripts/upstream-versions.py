#!/usr/bin/env python3
"""Compare what this repository supports with the newest upstream releases.

    uv run --no-project --with packaging scripts/upstream-versions.py

Reads the pins and ranges from the files that set them:

- the OpenShell pin, TAG in scripts/bootstrap-openshell.sh;
- the NeMo Agent Toolkit and Tenuo ranges in the plugin's pyproject.toml;
- the Tenuo crate requirement in Cargo.toml and the locked version in
  Cargo.lock.

It prints a Markdown report and exits 1 when an upstream stable release falls
outside what this repository supports and has verified: a new OpenShell
release that is not the pin, or a NeMo Agent Toolkit or Tenuo release outside
the declared range. A pre-release outside the range is reported, not a
failure; the upstream drift workflow tests it.

With GITHUB_OUTPUT set it also writes openshell_release (the newest OpenShell
release tag), openshell_pin, and nat_newest (the newest nvidia-nat-core,
pre-releases included).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "python" / "nemo-agent-toolkit-tenuo" / "pyproject.toml"
USER_AGENT = "tenuo-openshell-upstream-drift (https://github.com/tenuo-ai/tenuo-openshell)"


def get_json(url: str) -> dict | list:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return json.load(response)


def pypi_versions(name: str) -> list[Version]:
    data = get_json(f"https://pypi.org/pypi/{name}/json")
    versions = []
    for raw, files in data["releases"].items():
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            versions.append(Version(raw))
        except InvalidVersion:
            continue
    return sorted(versions)


def crate_versions(name: str) -> list[Version]:
    data = get_json(f"https://crates.io/api/v1/crates/{name}/versions")
    return sorted(Version(v["num"]) for v in data["versions"] if not v["yanked"])


def openshell_releases() -> list[str]:
    data = get_json("https://api.github.com/repos/NVIDIA/OpenShell/releases?per_page=30")
    return [r["tag_name"] for r in data if not r["draft"] and not r["prerelease"] and re.fullmatch(r"v\d+\.\d+\.\d+", r["tag_name"])]


def requirement(deps: list[str], name: str) -> SpecifierSet:
    for dep in deps:
        match = re.fullmatch(rf"{re.escape(name)}\s*([<>=!~,.\d\s]+)", dep)
        if match:
            return SpecifierSet(match.group(1).replace(" ", ""))
    raise SystemExit(f"{PLUGIN} declares no range for {name}")


def cargo_caret(req: str) -> SpecifierSet:
    """Cargo's default requirement "0.3.2" is ^0.3.2: >=0.3.2, <0.4.0."""
    parts = [int(p) for p in req.split(".")]
    lower = Version(req)
    if parts[0] > 0:
        upper = f"{parts[0] + 1}.0.0"
    elif len(parts) > 1 and parts[1] > 0:
        upper = f"0.{parts[1] + 1}.0"
    else:
        upper = f"0.0.{parts[2] + 1}"
    return SpecifierSet(f">={lower},<{upper}")


def newest(versions: list[Version], *, stable: bool) -> Version | None:
    candidates = [v for v in versions if not (stable and v.is_prerelease)]
    return max(candidates) if candidates else None


def main() -> int:
    pin = re.search(r'^TAG="(v[^"]+)"', (ROOT / "scripts" / "bootstrap-openshell.sh").read_text(), re.M).group(1)
    project = tomllib.loads(PLUGIN.read_text())["project"]
    nat_range = requirement(project["dependencies"], "nvidia-nat-core")
    tenuo_py_range = requirement(project["dependencies"], "tenuo")
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    tenuo_dep = cargo.get("workspace", {}).get("dependencies", {}).get("tenuo") or cargo["dependencies"]["tenuo"]
    tenuo_crate_req = tenuo_dep["version"] if isinstance(tenuo_dep, dict) else tenuo_dep
    tenuo_crate_range = cargo_caret(tenuo_crate_req.lstrip("^"))
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    tenuo_locked = next(p["version"] for p in lock["package"] if p["name"] == "tenuo")

    releases = openshell_releases()
    openshell_latest = max(releases, key=lambda t: Version(t[1:]))
    nat = pypi_versions("nvidia-nat-core")
    nat_stable, nat_any = newest(nat, stable=True), newest(nat, stable=False)
    tenuo_py = pypi_versions("tenuo")
    tenuo_py_stable = newest(tenuo_py, stable=True)
    tenuo_crate = crate_versions("tenuo")
    tenuo_crate_stable = newest(tenuo_crate, stable=True)

    rows: list[tuple[str, str, str, str]] = []
    failed = False

    def row(component: str, supported: str, latest: str, ok: bool, note: str = "") -> None:
        nonlocal failed
        failed |= not ok
        rows.append((component, supported, latest, ("ok" if ok else "**outside**") + (f": {note}" if note else "")))

    row(
        "NVIDIA OpenShell release",
        f"`{pin}` (pinned)",
        f"`{openshell_latest}`",
        openshell_latest == pin,
        "" if openshell_latest == pin else "a new release; move the pin after the E2E passes against it",
    )
    row(
        "nvidia-nat-core",
        f"`{nat_range}`",
        f"`{nat_stable}`",
        nat_stable in nat_range,
        "" if nat_stable in nat_range else "a new release; widen the range after the plugin tests pass on it",
    )
    if nat_any != nat_stable:
        in_range = nat_range.contains(nat_any, prereleases=True)
        rows.append(("nvidia-nat-core pre-release", f"`{nat_range}`", f"`{nat_any}`", "ok" if in_range else "ahead of the range; tested by the `nat-next` job"))
    row("tenuo (PyPI)", f"`{tenuo_py_range}`", f"`{tenuo_py_stable}`", tenuo_py_stable in tenuo_py_range)
    row(
        "tenuo (crates.io)",
        f"`^{tenuo_crate_req}`, locked `{tenuo_locked}`",
        f"`{tenuo_crate_stable}`",
        tenuo_crate_stable in tenuo_crate_range,
        "" if Version(tenuo_locked) == tenuo_crate_stable else "newer than the lock; tested by the `tenuo-latest` job",
    )

    print("## Upstream releases\n")
    print("| Component | Supported | Newest upstream | Result |\n|---|---|---|---|")
    for r in rows:
        print("| " + " | ".join(r) + " |")
    print()
    if failed:
        print("An upstream release is outside what this repository supports. See `docs/compatibility-matrix.md` for how a range moves.")
    else:
        print("Every newest stable release is inside the supported range.")

    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a") as fh:
            fh.write(f"openshell_release={openshell_latest}\nopenshell_pin={pin}\nnat_newest={nat_any}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
