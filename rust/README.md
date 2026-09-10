# Tokio hello-world HTTP server

Rust **1.98.1** is supplied by a digest-pinned official Debian trixie builder.
Tokio **1.53.1** and every transitive dependency/checksum are in `Cargo.lock`.
The builder runs `cargo test --locked` then `cargo build --release --locked`;
lockfile drift is an error. No native libraries are downloaded ad hoc.

The stripped release binary uses a current-thread Tokio runtime with networking,
I/O and timers enabled, and listens on **0.0.0.0:8080**. It returns
`Hello, world! From Rust.` to an HTTP request and closes the connection. Headers
are bounded to 8192 bytes and connection handling to five seconds. Tests exercise
the response Content-Length and oversized-header rejection.

This intentionally small demonstration is **not a complete HTTP implementation**:
it recognizes the header terminator, not full HTTP grammar/method semantics;
it has no TLS, routing, request-body processing or keepalive. Do not use it as an
internet-facing general server without a maintained HTTP stack and protocol
tests. Container memory limits and connection timeouts bound resource use but
are not comprehensive denial-of-service protection.

The final stage derives from `ARG BASE_IMAGE`, default
`sovereign-stack/base-container:local`. It retains only the application binary
and attribution evidence, not Cargo/rustc. It runs as **65532:65532** and needs
no writable rootfs. The binary links to the base's glibc; linux/amd64 is the only
tested target. A musl cross-toolchain/static alternate is intentionally omitted.

`/usr/share/sovereign-stack/rust/` preserves `Cargo.lock`, `Cargo.toml`, full
`cargo-metadata.json`, compiler/tool versions, Rust's `COPYRIGHT.html` and
`dependencies/<crate-version>/` manifests plus LICENSE/COPYING/NOTICE files.
Cargo metadata may include non-Linux target dependencies; this is a conservative
dependency inventory, not proof every listed crate is linked into the binary.
The full build stage is tagged `sovereign-stack/rust-builder:local` so scanners
can inspect its compiler, Debian package database, registry sources and crate
metadata independently. No assertion of complete license compliance or zero
known vulnerabilities follows from retaining these files.

On updates, choose the new builder digest and exact Tokio version, regenerate
the lock with that pinned Cargo, review changes, rebuild and rerun strict scans.
Do not switch the build to unlocked Cargo or delete lock metadata to hide CVEs.
See [base repeatability limitations](../base-container/README.md).

References:

* [Cargo --locked and --frozen semantics](https://doc.rust-lang.org/cargo/commands/cargo-build.html)
* [Cargo metadata schema](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)
* [Cargo vendor and corresponding source retention](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)
* [Tokio runtime builder](https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html)
