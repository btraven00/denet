#!/bin/bash
# Setup permissions for denet binary
# This script sets the necessary capabilities for stack trace capture

set -e
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

echo -e "${BOLD}DeNet Permission Setup${RESET}"
echo "============================"

# Check for debug or release builds
BINARY_PATHS=(
    "./target/debug/denet"
    "./target/release/denet"
)

BINARY_PATH=""
for path in "${BINARY_PATHS[@]}"; do
    if [ -f "$path" ]; then
        BINARY_PATH="$path"
        break
    fi
done

if [ -z "$BINARY_PATH" ]; then
    echo -e "${RED}Error: denet binary not found. Please build first:${RESET}"
    echo "cargo build --features ebpf"
    exit 1
fi

echo -e "\n${BOLD}Using binary: ${BLUE}${BINARY_PATH}${RESET}"

# Check capabilities
echo -e "\n${BOLD}Checking capabilities...${RESET}"
CAPS=$(getcap "$BINARY_PATH" 2>/dev/null || echo "No capabilities set")
echo "Current capabilities: $CAPS"

if [[ ! "$CAPS" == *"cap_bpf"* || ! "$CAPS" == *"cap_perfmon"* ]]; then
    echo -e "${YELLOW}Warning: denet doesn't have required capabilities${RESET}"
    echo -e "Running: sudo setcap cap_bpf,cap_perfmon=ep $BINARY_PATH"
    sudo setcap cap_bpf,cap_perfmon=ep "$BINARY_PATH"

    # Verify capabilities were set
    NEW_CAPS=$(getcap "$BINARY_PATH" 2>/dev/null || echo "Failed to set capabilities")
    if [[ "$NEW_CAPS" == *"cap_bpf"* && "$NEW_CAPS" == *"cap_perfmon"* ]]; then
        echo -e "${GREEN}✓ Successfully set capabilities: $NEW_CAPS${RESET}"
    else
        echo -e "${RED}✗ Failed to set capabilities properly: $NEW_CAPS${RESET}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ Capabilities already set correctly${RESET}"
fi

# Check for other binaries that might need capabilities
OTHER_BINARIES=(
    "./target/debug/offcpu_test"
    "./target/release/offcpu_test"
)

echo -e "\n${BOLD}Checking for other binaries...${RESET}"
for bin in "${OTHER_BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        BIN_CAPS=$(getcap "$bin" 2>/dev/null || echo "No capabilities set")
        echo "$bin: $BIN_CAPS"

        if [[ ! "$BIN_CAPS" == *"cap_bpf"* || ! "$BIN_CAPS" == *"cap_perfmon"* ]]; then
            echo -e "${YELLOW}Setting capabilities for $bin${RESET}"
            sudo setcap cap_bpf,cap_perfmon=ep "$bin"
            echo -e "${GREEN}✓ Set capabilities for $bin${RESET}"
        fi
    fi
done

# Check kernel parameters
echo -e "\n${BOLD}Checking kernel parameters...${RESET}"
echo "kernel.unprivileged_bpf_disabled = $(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo "N/A")"
echo "kernel.perf_event_paranoid = $(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo "N/A")"
echo "kernel.kptr_restrict = $(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "N/A")"

# Suggest optimal kernel parameters
echo -e "\n${BOLD}Recommended kernel parameters:${RESET}"
echo "kernel.unprivileged_bpf_disabled = 1    (prevents unprivileged BPF use)"
echo "kernel.perf_event_paranoid = 2          (restricts perf events to privileged users)"
echo "kernel.kptr_restrict = 1                (hides kernel addresses except to privileged users)"

echo -e "\n${GREEN}${BOLD}Setup complete!${RESET}"
echo -e "You can now run denet with eBPF stack tracing functionality."
echo -e "Example: ${BLUE}$BINARY_PATH --stack-trace-pid 1234${RESET}"
