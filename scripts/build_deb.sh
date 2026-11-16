#!/usr/bin/env bash
# Build the Debian package of the CLI, with the gpu and ebpf features.
#
# It is built inside Ubuntu 22.04, not on the host: the binary then links
# glibc 2.35 and installs on Ubuntu 22.04+ and Debian 12+. Built on a newer
# host it would depend on that host's glibc and install almost nowhere.
#
# Usage: ./scripts/build_deb.sh        (needs docker; writes target/debian/*.deb)
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/src/target/deb-build \
    -e OWNER="$(id -u):$(id -g)" ubuntu:22.04 bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # clang compiles the BPF programs; the libbpf headers are vendored
    apt-get install -y -qq curl ca-certificates build-essential clang llvm >/dev/null
    curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal
    . "$HOME/.cargo/env"
    cargo install -q --locked cargo-deb
    mkdir -p target/debian
    cargo deb --locked --output target/debian/
    chown -R "$OWNER" target/deb-build target/debian
'
ls -l target/debian/*.deb
