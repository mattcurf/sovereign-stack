ARG BASE_IMAGE=sovereign-stack/base-container:local
FROM rust:1.98.1-slim-trixie@sha256:bce1476d4be4d78b83705bc5f428b86d640eeeea33e9dadafbc037b5703a53bf AS build
ENV SOURCE_DATE_EPOCH=1789027200
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
