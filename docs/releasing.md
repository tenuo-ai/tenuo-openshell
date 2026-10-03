# Release and distribution gate

This repository has a manually dispatched, environment-gated release workflow.
Its default `publish=false` mode verifies an existing signed version tag,
builds the Python and Helm artifacts, the operator and sandbox binaries, and
the multi-platform image, and attaches provenance without publishing to
registries; the results stay in the workflow run's artifacts. `publish=true`
additionally publishes to PyPI and GHCR, signs the image and the binary
archives, and creates the GitHub release with the binaries attached.
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
   from `main` for that exact tag
   (`gh workflow run release.yml --ref main -f tag=v0.1.0 -f publish=false`).
   Signatures name the workflow and the ref it ran from; the verification
   commands below expect `main`. Publish the Python package, container, and
   binaries only from that workflow; the Rust crate remains `publish = false`
   unless a supported library interface is deliberately introduced. Image tags
   include the Git tag's `v` prefix, matching the Helm value (for example,
   `v0.1.0`).
8. Repeat the quickstart using only public artifacts, then verify signatures,
   checksums, plugin discovery, secure startup, one allowed call, and negative
   authorization cases.

## Release binaries

The `binaries` job builds each binary on a native runner with
`cargo build --release --locked`:

| Binary | Target | Runner |
| --- | --- | --- |
| `tenuo-openshell-agent` | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| `tenuo-openshell-agent` | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| `tenuo-openshell` | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| `tenuo-openshell` | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| `tenuo-openshell` | `aarch64-apple-darwin` | `macos-15` |

Linux binaries are statically linked against musl, so they run in any Linux
sandbox image regardless of its libc. TLS uses rustls; there is no OpenSSL
dependency. The macOS binary targets macOS 11 or later and is not notarized.

[`ci/release-binary.sh`](../ci/release-binary.sh) builds, checks, and packages
one target. It fails unless each `--version` prints the tag's version and each
Linux binary has no shared-library dependencies. For the agent it also runs
`keygen` into a temporary `HOME` and checks that `status` exits 1 with
`no warrant has been installed`. Run it locally for the host target:

```bash
ci/release-binary.sh v0.1.0 aarch64-apple-darwin /tmp/release tenuo-openshell
```

Each archive is named `<binary>-<tag>-<target>.tar.gz` and holds the binary
and `LICENSE`. The `verify-and-build` job adds the archives to `SHA256SUMS`
and to the build provenance attestation, which also covers each extracted
binary. With `publish=true` it signs each archive and `SHA256SUMS` with
keyless `cosign sign-blob`, writes `<file>.sigstore.json` bundles, and
attaches the archives, `SHA256SUMS`, and bundles to the GitHub release.

## Verifying a release binary

Download the archive, `SHA256SUMS`, and the archive's `.sigstore.json` bundle
from the GitHub release into one directory, then check the checksum, the
signature, and the provenance:

```bash
tag=v0.1.0
archive="tenuo-openshell-agent-$tag-x86_64-unknown-linux-musl.tar.gz"

sha256sum --ignore-missing -c SHA256SUMS

cosign verify-blob "$archive" \
  --bundle "$archive.sigstore.json" \
  --certificate-identity "https://github.com/tenuo-ai/tenuo-openshell/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify "$archive" \
  --repo tenuo-ai/tenuo-openshell \
  --signer-workflow tenuo-ai/tenuo-openshell/.github/workflows/release.yml \
  --source-ref "refs/heads/main"
```

The certificate and attestation record the ref the workflow was dispatched
from, not the release tag; the tag is checked by the workflow and appears in
the archive name and `--version`. On macOS, use
`shasum -a 256 --ignore-missing -c SHA256SUMS`. The same
`gh attestation verify` command accepts an extracted binary, such as one
already copied into a sandbox image.

Do not advertise `pip install`, a container tag, or a support window until the
corresponding artifact and ownership process exist. Release tags must be
immutable; fixes ship as a new version.
