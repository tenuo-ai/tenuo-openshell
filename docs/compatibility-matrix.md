# Compatibility matrix

What Tenuo for OpenShell supports, and the CI job that proves each row. A
version is supported when a job runs against it. A row without a job says so.

[![Upstream drift](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/upstream-drift.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-openshell/actions/workflows/upstream-drift.yml)

## Supported versions

| Component | Supported | Tested in CI | Newest upstream, checked nightly |
| --- | --- | --- | --- |
| NVIDIA OpenShell | v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` | v0.1.2 (release gate) | `main` and the newest release |
| Supervisor middleware protocol | `openshell.middleware.v1`, protocol `1.0` | Vendored files from v0.1.2 | Byte comparison with `main` |
| NVIDIA NeMo Agent Toolkit (`nvidia-nat-core`) | `>=1.8,<1.10` | 1.8.x, 1.9.x | The newest release, pre-releases included |
| Tenuo, Python (`tenuo`) | `>=0.3.2,<0.4` | 0.3.2 | The newest release in range |
| Tenuo, Rust (`tenuo` crate) | `^0.3.2` | 0.3.2 (locked) | The newest release in range |
| Python | 3.11, 3.12, 3.13 | All three | |
| Model (NAT agent guide) | `nvidia/nemotron-3-super-120b-a12b` on NVIDIA's API | Weekly | |

## OpenShell installs

The quickstart and the NAT agent guide run against a gateway OpenShell's
`install.sh` set up.

| Install | Platform | Covered by |
| --- | --- | --- |
| deb package | Ubuntu x86_64, arm64 | `linux-install.yml`, weekly and on pull requests that touch the guides |
| snap | Ubuntu x86_64 | `linux-install.yml` |
| Homebrew | macOS, Apple silicon | Manual run before each release; needs Docker Desktop host networking |
| rpm package | Fedora, RHEL | Not covered: hosted runners are Ubuntu only |
| Gateway built from source | Linux | `openshell-e2e.yml` (pinned), `upstream-drift.yml` (`main`, newest release) |
| Kubernetes, Helm chart | Any | `helm lint` in CI; no cluster run |

## Jobs

| Workflow | When | What it proves | Gates |
| --- | --- | --- | --- |
| `ci.yml` | Every pull request | Rust tests, the plugin on Python 3.11 to 3.13 with NAT 1.9 (locked) and 1.8, the NAT example, demo fixtures, the container build, chart lint | Merge |
| `openshell-e2e.yml` | Weekly, on demand | The full authenticated demo against the pinned OpenShell | Release |
| `linux-install.yml` | Weekly, guide changes, on demand | Both guides on the deb and snap installs | No |
| `nim-e2e.yml` | Weekly, workflow changes, on demand | The NAT agent guide with a real model through an OpenShell provider | No |
| `upstream-drift.yml` | Nightly, on demand | Everything below | No; fails loudly |

`upstream-drift.yml` runs these jobs:

| Job | Fails when |
| --- | --- |
| `versions` | An upstream stable release falls outside what this repository supports: an OpenShell release that is not the pin, or a NeMo Agent Toolkit or Tenuo release outside the declared range. `scripts/upstream-versions.py` reads the pins and ranges from the files that set them. |
| `proto-drift` | A vendored protocol file differs from OpenShell `main` or is gone. |
| `e2e (main)` | The full authenticated demo fails against OpenShell `main`, built from source with the supervisor and sandbox images OpenShell published for that commit. |
| `e2e (vX.Y.Z)` | The same, against OpenShell's newest release. Runs only while that release is newer than the pin. |
| `nat-next` | The plugin tests or `nat info components` discovery fail on the newest `nvidia-nat-core`, pre-releases included, installed past the declared range. |
| `tenuo-latest` | The Rust tests fail after `cargo update --package tenuo`. The `nat-next` job also installs the newest `tenuo` from PyPI in range. |

A failure turns the run red and opens one issue labeled `upstream-drift`, or
comments on the open one. The next passing run comments and closes it. Only the
`report` job can write issues. Pull requests that change the workflow or its
scripts run the checks without touching the issue.

## Moving a range

A range or pin moves in one pull request, after the jobs pass against the new
version:

1. **OpenShell.** Run `upstream-drift.yml` on demand with the release tag as
   `ref`. Then move `TAG`, `COMMIT`, and the pinned images in
   `scripts/bootstrap-openshell.sh` and `scripts/openshell-e2e.sh`, re-vendor
   `proto/openshell/`, and update [Upstream verification](upstream-verification.md).
   Run `openshell-e2e.yml` and `linux-install.yml` before merging.
2. **NeMo Agent Toolkit.** Widen `nvidia-nat-core` and `nvidia-nat-test` in the
   plugin's `pyproject.toml`, move the lock, and add the previous minor
   release to the `agent-toolkit-plugin` matrix in `ci.yml`.
3. **Tenuo.** Move the requirement in `Cargo.toml` and the plugin's
   `pyproject.toml`, then the locks.

Update this page and the README's Compatibility section in the same pull
request.
