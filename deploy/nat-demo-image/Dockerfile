# tenuo-openshell-nat-demo: the OpenShell sandbox image for the NeMo Agent
# Toolkit guide (docs/nat-agent.md).
#
# - NeMo Agent Toolkit 1.9 with the MCP client and the LangChain ReAct agent,
#   pinned with hashes in requirements.txt, and the nemo-agent-toolkit-tenuo
#   plugin from this repository;
# - tenuo-openshell-agent, which runs the MCP signing proxy; and
# - the workflows in /etc/tenuo-nat, the scripted model, and tenuo-nat-run.
#
# Python lives under /usr/local, which the sandbox's filesystem policy can
# read; its real path, /usr/local/bin/python3.12, is the binary a provider
# profile names. Bytecode is compiled at build time because the sandbox
# cannot write it.
#
# release.yml builds it on a native runner per platform, from the attested
# release binary staged as <arch>/tenuo-openshell-agent next to this file,
# with the plugin wheel built from python/nemo-agent-toolkit-tenuo and the
# scripted model from examples/nemo-agent-toolkit/scripted_llm.py.
# scripts/build-nat-demo-image.sh stages the same.
FROM python:3.12-slim
ARG TARGETARCH
ARG VERSION=unknown
ARG REVISION=unknown
LABEL org.opencontainers.image.title="tenuo-openshell-nat-demo" \
      org.opencontainers.image.description="NeMo Agent Toolkit sandbox image for Tenuo on NVIDIA OpenShell" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.source="https://github.com/tenuo-ai/tenuo-openshell" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY requirements.txt /tmp/requirements.txt
COPY nemo_agent_toolkit_tenuo-*.whl /tmp/
RUN python3 -m pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
        --require-hashes --only-binary :all: -r /tmp/requirements.txt \
    && python3 -m pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
        --no-deps /tmp/nemo_agent_toolkit_tenuo-*.whl \
    && python3 -m compileall -q -j0 /usr/local/lib/python3.12/site-packages >/dev/null \
    && rm -f /tmp/requirements.txt /tmp/nemo_agent_toolkit_tenuo-*.whl \
    && useradd --system --uid 10001 --create-home --home-dir /home/tenuo tenuo
COPY LICENSE /usr/share/doc/tenuo-openshell-nat-demo/LICENSE
COPY ${TARGETARCH}/tenuo-openshell-agent /usr/local/bin/tenuo-openshell-agent
COPY tenuo-nat-run /usr/local/bin/tenuo-nat-run
COPY scripted_llm.py /usr/local/share/tenuo-nat/scripted_llm.py
COPY scripted.yml scripted-plugin.yml nim.yml /etc/tenuo-nat/
ENV HOME=/home/tenuo
USER 10001
