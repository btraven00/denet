#!/bin/bash
# Build and install script for denet using maturin develop

set -e  # Exit on error

# Go to the project root
cd "$(dirname "$0")/.."

echo "🔨 Building and installing denet with maturin develop..."

# Use maturin develop to build and install in editable mode.
# Forward extra args (e.g. --features python,ebpf) to maturin; they add to the
# features configured in pyproject.toml's [tool.maturin].
maturin develop --release "$@"

# Verify the installation
echo "Verifying installation..."
python -c "import denet; print('✅ denet successfully installed!')"
