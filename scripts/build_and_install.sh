#!/bin/bash
# Direct build and install script for denet
# This script builds the Rust extension and installs it directly with pip
# without relying on maturin's develop command

set -e  # Exit on error

# Go to the project root
cd "$(dirname "$0")/.."

# Display what we're doing
echo "🔨 Building and installing denet..."

# Get Python executable path
PYTHON_EXE=$(which python)
echo "Using Python at: $PYTHON_EXE"

# Build the wheel using maturin
echo "Building wheel..."
maturin build

# Find the most recently built wheel
WHEEL_PATH=$(ls -t target/wheels/*.whl | head -1)

if [ -z "$WHEEL_PATH" ]; then
    echo "❌ Error: No wheel file found after build."
    exit 1
fi

echo "Built wheel: $WHEEL_PATH"

# Install the wheel with pip or alternative methods
echo "Installing wheel..."
if $PYTHON_EXE -c "import pip" 2>/dev/null; then
    # If pip is available, use it
    $PYTHON_EXE -m pip install --force-reinstall "$WHEEL_PATH"
else
    # Alternative for pixi/conda environments without pip
    echo "No pip module found, copying wheel directly..."
    SITE_PACKAGES=$($PYTHON_EXE -c "import site; print(site.getsitepackages()[0])")
    echo "Site packages directory: $SITE_PACKAGES"
    
    # Extract wheel (it's just a zip file)
    TEMP_DIR=$(mktemp -d)
    unzip -q "$WHEEL_PATH" -d "$TEMP_DIR"
    
    # Find and copy the .so file
    SO_FILE=$(find "$TEMP_DIR" -name "*.so" | head -1)
    if [ -n "$SO_FILE" ]; then
        cp "$SO_FILE" "$SITE_PACKAGES/"
        echo "Copied $SO_FILE to $SITE_PACKAGES/"
    else
        echo "Error: No .so file found in the wheel"
        exit 1
    fi
    
    # Clean up
    rm -rf "$TEMP_DIR"
fi

# Verify the installation
# Verify that the module can be imported
echo "Verifying installation..."
if $PYTHON_EXE -c "import denet; print('✅ denet successfully installed!')"; then
    echo "✅ Build and installation complete!"
else
    echo "❌ Installation verification failed."
    
    # Print Python path for debugging
    echo "Python path:"
    $PYTHON_EXE -c "import sys; print(sys.path)"
    
    echo "Attempting to find denet module..."
    find $($PYTHON_EXE -c "import site; print(' '.join(site.getsitepackages()))") -name "*denet*" || echo "No denet module found"
    
    exit 1
fi