FROM rust:1.91-bookworm AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
COPY agent ./agent
# fuzz/ is a workspace member, so cargo needs its manifest and targets to load
# the workspace. Nothing from it is built here.
COPY fuzz/Cargo.toml ./fuzz/
COPY fuzz/fuzz_targets ./fuzz/fuzz_targets
RUN cargo build --release --locked --bin tenuo-openshell-middleware

FROM debian:bookworm-slim
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Tenuo for NVIDIA OpenShell" \
      org.opencontainers.image.description="Task-scoped authorization middleware for NVIDIA OpenShell" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.source="https://github.com/tenuo-ai/tenuo-openshell" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN useradd --system --uid 10001 --no-create-home tenuo
COPY --from=build /source/target/release/tenuo-openshell-middleware /usr/local/bin/tenuo-openshell-middleware
USER 10001
EXPOSE 50051 9090
ENTRYPOINT ["/usr/local/bin/tenuo-openshell-middleware"]
