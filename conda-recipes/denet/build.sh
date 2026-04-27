#!/usr/bin/env bash
set -euxo pipefail

cargo install --path . --bin denet --root "${PREFIX}" --no-track
