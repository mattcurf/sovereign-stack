#!/bin/sh
set -eu
mkdir -p /evidence/dependencies
cp Cargo.toml Cargo.lock /evidence/
cargo metadata --locked --format-version=1 > /evidence/cargo-metadata.json
rustc --version > /evidence/rustc-version.txt
cargo --version > /evidence/cargo-version.txt
for crate in /usr/local/cargo/registry/src/*/*; do
    destination="/evidence/dependencies/$(basename "$crate")"
    mkdir -p "$destination"
    cp "$crate/Cargo.toml" "$destination/"
    find "$crate" -maxdepth 1 -type f \( -iname '*license*' -o -iname '*copying*' -o -iname '*notice*' \) \
        -exec cp {} "$destination/" \;
done
cp "$(rustc --print sysroot)/share/doc/rust/COPYRIGHT.html" /evidence/RUST-COPYRIGHT.html
