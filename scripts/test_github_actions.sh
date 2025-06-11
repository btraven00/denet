#!/bin/bash
# Test GitHub Actions workflows locally using act
# https://github.com/nektos/act

set -e  # Exit on error

echo "🔍 Testing GitHub Actions workflows locally using act"

# Check if act is installed
if ! command -v act &> /dev/null; then
    echo "❌ Error: act is not installed. Please install it first:"
    echo "  • GitHub: https://github.com/nektos/act"
    echo "  • Install: brew install act (macOS) or follow GitHub instructions"
    exit 1
fi

# Get directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Go to repository root
cd "$REPO_ROOT"

# Check if .github/workflows directory exists
if [ ! -d ".github/workflows" ]; then
    echo "❌ Error: .github/workflows directory not found in $REPO_ROOT"
    exit 1
fi

# Parse command line arguments
WORKFLOW=""
PLATFORM="ubuntu-latest"
EVENT="push"

print_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -w, --workflow WORKFLOW  Specific workflow file to test (e.g., test.yml)"
    echo "  -p, --platform PLATFORM  Platform to run on (default: ubuntu-latest)"
    echo "  -e, --event EVENT        Event to trigger (default: push)"
    echo "  -h, --help               Show this help message"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -w|--workflow)
            WORKFLOW="$2"
            shift 2
            ;;
        -p|--platform)
            PLATFORM="$2"
            shift 2
            ;;
        -e|--event)
            EVENT="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Prepare command
CMD="act $EVENT"

if [ -n "$WORKFLOW" ]; then
    # Check if workflow file exists
    if [ ! -f ".github/workflows/$WORKFLOW" ]; then
        echo "❌ Error: Workflow file .github/workflows/$WORKFLOW not found"
        exit 1
    fi
    
    CMD="$CMD -W .github/workflows/$WORKFLOW"
    echo "🚀 Testing specific workflow: $WORKFLOW"
else
    echo "🚀 Testing all workflows in .github/workflows/"
fi

# Add platform
CMD="$CMD -P $PLATFORM=ghcr.io/catthehacker/ubuntu:act-latest"

echo "📋 Running command: $CMD"
echo "⚙️ Platform: $PLATFORM"
echo "🔔 Event: $EVENT"
echo "-------------------------------------------"

# Run act
eval "$CMD"

echo "-------------------------------------------"
echo "✅ GitHub Actions workflow test completed"