#!/bin/bash

# Create LCOV coverage data if it doesn't exist
if [ ! -f lcov.info ]; then
    echo "Generating coverage data..."
    cargo llvm-cov --lcov --output-path lcov.info
fi

# Extract file coverage information
echo "Coverage by file:"
echo "-----------------"

# Process each source file in the lcov.info
grep -a "SF:" lcov.info | while read -r line; do
    # Extract the source file path
    file=${line#SF:}

    # Get line coverage for this file
    total_lines=$(grep -a -A1 "SF:$file" lcov.info | grep -a "LF:" | cut -d: -f2)
    covered_lines=$(grep -a -A2 "SF:$file" lcov.info | grep -a "LH:" | cut -d: -f2)

    # Calculate percentage
    if [[ -n "$total_lines" && -n "$covered_lines" && "$total_lines" -gt 0 ]]; then
        percentage=$(echo "scale=2; $covered_lines * 100 / $total_lines" | bc)
    else
        percentage="N/A"
    fi

    # Print the results
    printf "%-50s %6d / %-6d %6s%%\n" "$file" "$covered_lines" "$total_lines" "$percentage"
done

# Calculate overall coverage
total_lines=$(grep -a "LF:" lcov.info | awk -F: '{sum += $2} END {print sum}')
covered_lines=$(grep -a "LH:" lcov.info | awk -F: '{sum += $2} END {print sum}')
percentage=$(echo "scale=2; $covered_lines * 100 / $total_lines" | bc)

echo "-----------------"
printf "%-50s %6d / %-6d %6s%%\n" "TOTAL" "$covered_lines" "$total_lines" "$percentage"
