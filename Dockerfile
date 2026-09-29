FROM rust:1.91-bookworm AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
RUN cargo build --release --locked --bin tenuo-openshell-middleware

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home tenuo
COPY --from=build /source/target/release/tenuo-openshell-middleware /usr/local/bin/tenuo-openshell-middleware
USER 10001
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/tenuo-openshell-middleware"]
