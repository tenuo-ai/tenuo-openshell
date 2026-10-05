# Releasing

Releases are cut by `.github/workflows/release.yml`, a manually dispatched
workflow that runs in the protected `release` environment. It checks out an
existing version tag and requires the tag to match the Rust versions and to
have notes in `CHANGELOG.md`. It then runs `make check` and builds:

- the Python wheel and sdist;
- the Helm chart;
- the operator and sandbox binaries;
- the multi-platform middleware image; and
- the agent image, from the same sandbox binaries.

It attests the build provenance of all of them.

- `publish=false` is a dry run. The artifacts stay in the workflow run.
- `publish=true` also pushes and signs the middleware image, the agent image,
  and the Helm chart (as `oci://ghcr.io/tenuo-ai/charts/tenuo-openshell`) on
  GHCR, signs the binary archives, publishes the Python package to PyPI, and creates the GitHub
  release from the `CHANGELOG.md` section.

## One-time setup

Before the first `publish=true` run:

1. **PyPI trusted publisher.** Add a pending publisher for
   `nemo-agent-toolkit-tenuo` with these values:
   - owner `tenuo-ai`
   - repository `tenuo-openshell`
   - workflow `release.yml`
   - environment `release`

   The workflow uses no PyPI token.
2. **`release` environment.** It requires a reviewer, so every publish waits
   for approval.
3. **Tag signing.** Configure a key for signed tags, for example an SSH
   signing key registered with GitHub:
   `git config gpg.format ssh`, `git config user.signingkey <key>`.
4. **GHCR packages.** After the first push of each package
   (`tenuo-openshell`, `tenuo-openshell-agent`, `charts/tenuo-openshell`),
   open its package settings:
   - link the package to this repository;
   - set it to public when the repository is public.

   New packages start private.

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
   (`gh workflow run release.yml --ref main -f tag=v0.1.1 -f publish=false`).
   Signatures name the workflow and the ref it ran from; the verification
   commands below expect `main`. Publish the Python package, container, and
   binaries only from that workflow; the Rust crate remains `publish = false`
   unless a supported library interface is deliberately introduced. Image tags
   include the Git tag's `v` prefix, matching the Helm value (for example,
   `v0.1.0`).
8. Download the dry run's `release-artifacts`, and check the wheel, chart, and
   archives. Then dispatch again with `-f publish=true` and approve the
   `release` environment.
9. Repeat the quickstart using only public artifacts, then verify signatures,
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
signature, and the provenance. The bundles use the Sigstore bundle format
that cosign 3 writes. cosign 2 cannot read them.

```bash
tag=v0.1.1
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

## Verifying the image, chart, and package

```bash
tag=v0.1.1

identity=(--certificate-identity "https://github.com/tenuo-ai/tenuo-openshell/.github/workflows/release.yml@refs/heads/main"
  --certificate-oidc-issuer https://token.actions.githubusercontent.com)

cosign verify "ghcr.io/tenuo-ai/tenuo-openshell:$tag" "${identity[@]}"
cosign verify "ghcr.io/tenuo-ai/tenuo-openshell-agent:$tag" "${identity[@]}"
cosign verify "ghcr.io/tenuo-ai/charts/tenuo-openshell:${tag#v}" "${identity[@]}"

helm install tenuo-openshell oci://ghcr.io/tenuo-ai/charts/tenuo-openshell \
  --version "${tag#v}" -f my-values.yaml

python -m pip install "nemo-agent-toolkit-tenuo==${tag#v}"
nat info components
```

The chart's default image is the release image for the chart's version, so
`helm install` needs no image override. Pin by digest in production;
`cosign verify` prints it.

## After a release

- Run `make demo` and the README quickstart against the public artifacts
  only.
- Release tags are immutable. Fixes ship as a new version, with a new
  `CHANGELOG.md` section.
