#!/bin/bash
# Script to update version numbers in multiple files
# Usage: ./scripts/update_version.sh 0.1.2

set -e  # Exit on error

# Check if version argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 VERSION"
    echo "Example: $0 0.1.2"
    exit 1
fi

NEW_VERSION=$1

# Check if version format is valid (x.y.z)
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format x.y.z (e.g., 0.1.2)"
    exit 1
fi

# Get directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Updating version to $NEW_VERSION"

# Update version in pyproject.toml
echo "Updating pyproject.toml..."
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$REPO_ROOT/pyproject.toml"
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$REPO_ROOT/Cargo.toml"

# Update version in flake.nix
echo "Updating flake.nix..."
sed -i "s/version = \".*\";/version = \"$NEW_VERSION\";/" "$REPO_ROOT/flake.nix"

# If you have a version specified in __init__.py, update it
if [ -f "$REPO_ROOT/python/denet/__init__.py" ]; then
    echo "Updating python/denet/__init__.py..."
    # Different patterns depending on how version is defined
    sed -i "s/__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" "$REPO_ROOT/python/denet/__init__.py"
    # Also try the single quotes format
    sed -i "s/__version__ = '.*'/__version__ = '$NEW_VERSION'/" "$REPO_ROOT/python/denet/__init__.py"
fi

# If version isn't defined in __init__.py, add it
if ! grep -q "__version__" "$REPO_ROOT/python/denet/__init__.py"; then
    echo "Adding __version__ to python/denet/__init__.py..."
    # Add version after the first line that contains "import"
    sed -i "0,/import/s/import.*/&\n\n__version__ = \"$NEW_VERSION\"/" "$REPO_ROOT/python/denet/__init__.py"
fi

# Update version in CITATION.cff if it exists
if [ -f "$REPO_ROOT/CITATION.cff" ]; then
    echo "Updating CITATION.cff..."
    # Check if version is quoted
    if grep -q "^version: \"" "$REPO_ROOT/CITATION.cff"; then
        # Update quoted version
        sed -i "s/^version: \".*\"$/version: \"$NEW_VERSION\"/" "$REPO_ROOT/CITATION.cff"
    else
        # Update unquoted version
        sed -i "s/^version: .*$/version: $NEW_VERSION/" "$REPO_ROOT/CITATION.cff"
    fi
fi

echo "Version updated to $NEW_VERSION"
echo "Don't forget to commit these changes and create a tag:"
echo "git commit -am \"Bump version to $NEW_VERSION\""
echo "git tag -a v$NEW_VERSION -m \"Version $NEW_VERSION\""
echo "git push && git push --tags"
