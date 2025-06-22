#!/bin/bash
# Test script for denet stack trace profiling
# This script tests the fixed stack trace implementation in the main denet build

set -e
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

echo -e "${BOLD}DeNet Stack Trace Fixes Test${RESET}"
echo "============================="

# Check if denet is built with ebpf feature
if ! [ -f "./target/debug/denet" ]; then
    echo -e "${RED}Error: denet binary not found. Please build first:${RESET}"
    echo "cargo build --features ebpf"
    exit 1
fi

# Compile test_func.c with debug symbols if needed
if ! [ -f "./test_func" ] || [ "$(stat -c %Y test_func.c)" -gt "$(stat -c %Y test_func)" ]; then
    echo -e "\n${BOLD}Compiling test program with debug symbols...${RESET}"
    gcc -g -O0 -o test_func test_func.c
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to compile test_func.c${RESET}"
        exit 1
    fi
    echo -e "${GREEN}✓ Compiled test_func with debug symbols${RESET}"
else
    echo -e "\n${BOLD}Using existing test program${RESET}"
fi

# Ensure capabilities are set
echo -e "\n${BOLD}Checking capabilities...${RESET}"
if [ -f "./setup_permissions.sh" ]; then
    echo "Running setup_permissions.sh to ensure proper capabilities"
    ./setup_permissions.sh
else
    CAPS=$(getcap ./target/debug/denet)
    echo "Current capabilities: $CAPS"

    if [[ ! "$CAPS" == *"cap_bpf"* || ! "$CAPS" == *"cap_perfmon"* ]]; then
        echo -e "${YELLOW}Warning: denet doesn't have required capabilities${RESET}"
        echo -e "Running: sudo setcap cap_bpf,cap_perfmon=ep ./target/debug/denet"
        sudo setcap cap_bpf,cap_perfmon=ep ./target/debug/denet
        echo -e "${GREEN}✓ Set capabilities${RESET}"
    fi
fi

# Run the test program
echo -e "\n${BOLD}Running test program...${RESET}"
./test_func 5 &
TEST_PID=$!
echo "Test program running with PID: $TEST_PID"

# Wait a moment for the program to start
sleep 1

# Create output file
OUTPUT_FILE="denet_stack_trace_results.json"

# Run denet with stack trace profiling
echo -e "\n${BOLD}Running denet with stack trace profiling...${RESET}"
RUST_LOG=debug ./target/debug/denet -o $OUTPUT_FILE -d 10 --enable-ebpf --debug attach $TEST_PID

# Check if test program is still running
if kill -0 $TEST_PID 2>/dev/null; then
    echo -e "\n${BOLD}Stopping test program...${RESET}"
    kill $TEST_PID
else
    echo -e "\n${BOLD}Test program already completed${RESET}"
fi

# Analyze results
echo -e "\n${BOLD}Analyzing results...${RESET}"
if [ -f "$OUTPUT_FILE" ]; then
    echo "Results saved to $OUTPUT_FILE"

    # Check for stack traces
    STACK_TRACE_COUNT=$(grep -c "stack_traces" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    EMPTY_STACKS=$(grep -c '"user_stack": \[\]' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    USER_STACK_ERRORS=$(grep -c '"user_stack_error":' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    KERNEL_STACK_ERRORS=$(grep -c '"kernel_stack_error":' "$OUTPUT_FILE" 2>/dev/null || echo "0")

    # Check for successful symbolication
    SYMBOLICATED_FRAMES=$(grep -c '"symbol":' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    FUNCTION_FRAMES=$(grep -c "level[1-3]_function" "$OUTPUT_FILE" 2>/dev/null || echo "0")

    echo "Stack trace events: $STACK_TRACE_COUNT"
    echo "Empty user stacks: $EMPTY_STACKS"
    echo "User stack errors: $USER_STACK_ERRORS"
    echo "Kernel stack errors: $KERNEL_STACK_ERRORS"
    echo "Symbolicated frames: $SYMBOLICATED_FRAMES"
    echo "Identified functions from test program: $FUNCTION_FRAMES"

    if [ "$SYMBOLICATED_FRAMES" -gt 0 ]; then
        echo -e "${GREEN}✓ Successfully captured and symbolicated stack traces!${RESET}"

        # Show example stack traces
        echo -e "\n${BOLD}Example symbolicated frames:${RESET}"
        grep -A 3 '"symbol":' "$OUTPUT_FILE" | head -n 10

        # Check if test functions were found
        if [ "$FUNCTION_FRAMES" -gt 0 ]; then
            echo -e "\n${BOLD}Found test program functions in stack traces:${RESET}"
            grep -A 2 "level[1-3]_function" "$OUTPUT_FILE" | head -n 10
            echo -e "\n${GREEN}${BOLD}Stack trace symbolication is working correctly!${RESET}"
        else
            echo -e "\n${YELLOW}⚠ Symbolication worked but test functions not found.${RESET}"
            echo "This might indicate a problem with the debug symbols or address mapping."
        fi
    elif [ "$USER_STACK_ERRORS" -gt 0 ] || [ "$KERNEL_STACK_ERRORS" -gt 0 ]; then
        echo -e "${YELLOW}⚠ Stack trace errors detected.${RESET}"
        echo -e "\n${BOLD}User stack errors:${RESET}"
        grep -A 1 '"user_stack_error":' "$OUTPUT_FILE" | head -n 10
    else
        echo -e "${RED}❌ No symbolicated stack frames found.${RESET}"
    fi
else
    echo -e "${RED}No results file found${RESET}"
fi

# Clean up
echo -e "\n${BOLD}Test completed.${RESET}"
