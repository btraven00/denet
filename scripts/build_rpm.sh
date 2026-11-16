#!/usr/bin/env bash
# Build the RPM of the CLI, with the gpu and ebpf features.
#
# It is built inside AlmaLinux 8, not on the host: the binary then links
# glibc 2.28 and installs on RHEL/Rocky/Alma 8+ and Fedora. Built on a newer
# host it would need that host's glibc, which no RHEL 8 or 9 system has.
#
# Usage: ./scripts/build_rpm.sh        (needs docker; writes target/rpm/*.rpm)
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/src/target/rpm-build \
    -e OWNER="$(id -u):$(id -g)" almalinux:8 bash -euc '
    # clang compiles the BPF programs (the libbpf headers are vendored);
    # rpm-build provides the dependency scanner cargo-generate-rpm calls
    dnf install -y -q gcc clang llvm rpm-build >/dev/null
    curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal
    . "$HOME/.cargo/env"
    cargo install -q --locked cargo-generate-rpm
    cargo build --release --locked --features gpu,ebpf --bin denet
    # cargo-generate-rpm reads target/release, so point it at this build
    mkdir -p target/rpm
    cargo generate-rpm --target-dir "$CARGO_TARGET_DIR" --auto-req auto -o target/rpm/
    chown -R "$OWNER" target/rpm-build target/rpm
'
ls -l target/rpm/*.rpm
