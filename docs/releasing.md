# Release and distribution gate

This repository intentionally has no automatic publication workflow yet. Add
registry credentials and enable publishing only after package ownership,
artifact names, support policy, and rollback ownership are agreed.

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
7. Publish a signed Git tag and GitHub release. Publish the Python package and
   container only from that tag; the Rust crate remains `publish = false` unless
   a supported library interface is deliberately introduced.
8. Repeat the quickstart using only public artifacts, then verify signatures,
   checksums, plugin discovery, secure startup, one allowed call, and negative
   authorization cases.

Do not advertise `pip install`, a container tag, or a support window until the
corresponding artifact and ownership process exist. Release tags must be
immutable; fixes ship as a new version.
