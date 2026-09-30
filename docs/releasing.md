# Release and distribution gate

This repository has a manually dispatched, environment-gated release workflow.
Its default `publish=false` mode verifies an existing signed version tag,
builds the Python and Helm artifacts, builds the multi-platform image, and
attaches provenance without publishing to registries. `publish=true` additionally
publishes to PyPI and GHCR, signs the image, and creates the GitHub release.
Protect the `release` environment and enable publishing only after package
ownership, trusted publishing, artifact names, support policy, and rollback
ownership are agreed.

## Pre-release checklist

1. Update `CHANGELOG.md`, Rust and Python versions, compatibility tables, and
   user-facing install instructions together.
2. Verify the pinned OpenShell release and commit, Agent Toolkit range, Tenuo
   range, protocol files, NVIDIA image digests, and base-image digest.
3. Run `make check`, the Redis replay integration test, Helm lint/rendering,
   and `make e2e` from a clean checkout with a supported container runtime.
4. Build the Python wheel/sdist and middleware image from the release commit.
   Install the wheel into a fresh environment and verify `nat info components`.
5. Inspect the source distribution, container configuration, licenses, and
   dependency inventory. Generate SBOMs for the Python and container artifacts.
6. Scan dependencies and images, sign artifacts, attach provenance, and record
   immutable digests.
7. Create and push a signed Git tag, then dispatch `.github/workflows/release.yml`
   for that exact tag. Publish the Python package and container only from that
   workflow; the Rust crate remains `publish = false` unless a supported library
   interface is deliberately introduced. Image tags include the Git tag's `v`
   prefix, matching the Helm value (for example, `v0.1.0`).
8. Repeat the quickstart using only public artifacts, then verify signatures,
   checksums, plugin discovery, secure startup, one allowed call, and negative
   authorization cases.

Do not advertise `pip install`, a container tag, or a support window until the
corresponding artifact and ownership process exist. Release tags must be
immutable; fixes ship as a new version.
