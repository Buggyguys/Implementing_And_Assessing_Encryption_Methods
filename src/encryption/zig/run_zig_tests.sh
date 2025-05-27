#!/bin/bash
# CryptoBench Pro - Zig Tests Runner
# This script runs the Zig encryption benchmarks

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." &> /dev/null && pwd )"

# If configuration file is provided as argument, use it
if [ "$#" -eq 1 ]; then
    CONFIG_FILE="$1"
else
    # Look for latest session config
    LATEST_SESSION=$(find "$PROJECT_ROOT/sessions" -type d -name "Session-*" | sort -r | head -n 1)
    CONFIG_FILE="$LATEST_SESSION/test_config.json"
fi

echo "Using configuration file: $CONFIG_FILE"

# Run the Zig core script
python3 "$SCRIPT_DIR/zig_core.py" "$CONFIG_FILE"

# Check result
if [ $? -eq 0 ]; then
    echo "Zig encryption tests completed successfully"
    exit 0
else
    echo "Zig encryption tests failed"
    exit 1
fi 