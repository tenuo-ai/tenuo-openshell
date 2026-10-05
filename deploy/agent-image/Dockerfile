# tenuo-openshell-agent release image. It holds only the static binary, so a
# sandbox image can take it with one line:
#
#   COPY --from=ghcr.io/tenuo-ai/tenuo-openshell-agent:<tag> \
#     /usr/local/bin/tenuo-openshell-agent /usr/local/bin/
#
# release.yml builds it from the attested release binaries, staged as
# <arch>/tenuo-openshell-agent next to this file. Nothing is compiled here, so
# both platforms build on one runner without emulation.
FROM scratch
ARG TARGETARCH
ARG VERSION=unknown
ARG REVISION=unknown
LABEL org.opencontainers.image.title="tenuo-openshell-agent" \
      org.opencontainers.image.description="In-sandbox key holder and signing MCP proxy for Tenuo on NVIDIA OpenShell" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.source="https://github.com/tenuo-ai/tenuo-openshell" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY LICENSE /usr/share/doc/tenuo-openshell-agent/LICENSE
COPY ${TARGETARCH}/tenuo-openshell-agent /usr/local/bin/tenuo-openshell-agent
USER 10001
ENTRYPOINT ["/usr/local/bin/tenuo-openshell-agent"]
