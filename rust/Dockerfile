ARG BASE_IMAGE=sovereign-stack/base-container:local
FROM rust:1.99.0-slim-trixie@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273 AS build
ENV SOURCE_DATE_EPOCH=1791360000
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY evidence.sh /usr/local/bin/evidence
RUN cargo test --locked && cargo build --release --locked \
    && /usr/local/bin/evidence

FROM ${BASE_IMAGE}
COPY --from=build /src/target/release/sovereign-stack-rust /usr/local/bin/hello-rust
COPY --from=build /evidence/ /usr/share/sovereign-stack/rust/
USER 65532:65532
EXPOSE 8080
CMD ["/usr/local/bin/hello-rust"]
