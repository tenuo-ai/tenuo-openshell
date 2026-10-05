# tenuo-openshell-demo: the sandbox image and demo MCP server for the
# quickstart (docs/quickstart.md).
#
# One image serves two roles:
#
# - the OpenShell sandbox, which runs `tenuo-openshell-agent proxy`; and
# - the demo MCP server, which `tenuo-openshell dev up` runs next to the
#   middleware as `tenuo-demo-mcp`.
#
# curl is here so the quickstart can show a call that skips the agent.
#
# release.yml builds it on a native runner per platform, from the attested
# release binary staged as <arch>/tenuo-openshell-agent next to this file.
FROM ubuntu:24.04
ARG TARGETARCH
ARG VERSION=unknown
ARG REVISION=unknown
LABEL org.opencontainers.image.title="tenuo-openshell-demo" \
      org.opencontainers.image.description="Quickstart sandbox image and demo MCP server for Tenuo on NVIDIA OpenShell" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.source="https://github.com/tenuo-ai/tenuo-openshell" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY LICENSE /usr/share/doc/tenuo-openshell-demo/LICENSE
COPY ${TARGETARCH}/tenuo-openshell-agent /usr/local/bin/tenuo-openshell-agent
COPY tenuo-demo-mcp /usr/local/bin/tenuo-demo-mcp
