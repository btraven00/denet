#!/usr/bin/env bash
set -euxo pipefail

cargo build --release --bin denet

install -Dm755 target/release/denet "${PREFIX}/bin/denet"
