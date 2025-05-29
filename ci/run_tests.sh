#!/bin/bash
set -e

# Script for running tests in CI environment
# This avoids environment issues that can occur when running directly with pixi

# Display the commands being run
set -x

# Make sure we're in the project root
cd "$(dirname "$0")/.."

# Run Rust tests first (without Python dependencies)
cargo test --no-default-features

# Build the extension and install it
./scripts/build_and_install.sh

# Extension has already been installed by build_and_install.sh
# No need to run pip install again

# Run the Python tests
python -m pytest tests/

echo "All tests passed!"