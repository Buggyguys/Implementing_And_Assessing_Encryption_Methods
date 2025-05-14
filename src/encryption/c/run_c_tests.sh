#!/bin/bash

# Exit on error
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"

# Change to the project root directory
cd "$PROJECT_ROOT"

# Create a clear visual separation for C tests
echo ""
echo "=================================================================="
echo "               C ENCRYPTION BENCHMARKS STARTING                   "
echo "=================================================================="
echo ""

# Check for clean build flag
CLEAN_BUILD=""
if [ "$1" = "clean" ]; then
    CLEAN_BUILD="clean"
    shift
fi

# Check if a configuration file was provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 [clean] <config_file>"
    exit 1
fi

CONFIG_FILE="$1"

# Silently extract configuration parameters without printing detailed paths
if [ -f "$CONFIG_FILE" ]; then
    # Extract AES key size and mode from the encryption_methods.aes section
    AES_KEY_SIZE=$(grep -A10 '"aes": {' "$CONFIG_FILE" | grep -o '"key_size": *"[^"]*"' | grep -o '[0-9]\+' | head -1)
    AES_MODE=$(grep -A10 '"aes": {' "$CONFIG_FILE" | grep -o '"mode": *"[^"]*"' | grep -o '[^"]*"' | sed 's/"$//' | head -1)
    
    # Extract use_stdlib and use_custom settings
    USE_STDLIB=$(grep -o '"use_stdlib": *\(true\|false\)' "$CONFIG_FILE" | grep -o '\(true\|false\)' | head -1)
    USE_CUSTOM=$(grep -o '"use_custom": *\(true\|false\)' "$CONFIG_FILE" | grep -o '\(true\|false\)' | head -1)
    
    if [ "$USE_STDLIB" = "true" ]; then
        USE_STDLIB=1
    else
        USE_STDLIB=0
    fi
    
    if [ "$USE_CUSTOM" = "true" ]; then
        USE_CUSTOM=1
    else
        USE_CUSTOM=0
    fi
    
    export TEST_CONFIG_PATH="$CONFIG_FILE"
    export AES_KEY_SIZE=$AES_KEY_SIZE
    export AES_MODE=$AES_MODE
    export USE_STDLIB=$USE_STDLIB
    export USE_CUSTOM=$USE_CUSTOM
else
    echo "Warning: Could not find configuration file: $CONFIG_FILE"
fi

# Create build directory if it doesn't exist
BUILD_DIR="$PROJECT_ROOT/build/c_encryption"
mkdir -p "$BUILD_DIR"

# First, ensure the code is built with the latest changes
echo ""
echo "------------------------------------------------------------------"
echo "                       BUILDING C CODE                            "
echo "------------------------------------------------------------------"
# Run build script silently with only important messages captured
bash "$SCRIPT_DIR/build_c.sh" $CLEAN_BUILD
if [ $? -ne 0 ]; then
    echo "Build failed! Aborting tests."
    exit 1
fi
echo "------------------------------------------------------------------"
echo "Build successful."
echo ""

# Define possible executable paths
LOCAL_EXECUTABLE="$SCRIPT_DIR/c_core"
BUILD_EXECUTABLE="$BUILD_DIR/c_encryption_benchmark"

# Run the built C program with the specified configuration
echo ""
echo "------------------------------------------------------------------"
echo "                   RUNNING C BENCHMARKS                           "
echo "------------------------------------------------------------------"
echo ""
if [ -x "$LOCAL_EXECUTABLE" ]; then
    "$LOCAL_EXECUTABLE" "$CONFIG_FILE"
elif [ -x "$BUILD_EXECUTABLE" ]; then
    "$BUILD_EXECUTABLE" "$CONFIG_FILE"
else
    echo "Error: Could not find executable at either $LOCAL_EXECUTABLE or $BUILD_EXECUTABLE"
    exit 1
fi

# Clean up placeholder implementations after tests are done
echo ""
echo "------------------------------------------------------------------"
echo "                     CLEANUP PHASE                                "
echo "------------------------------------------------------------------"
echo "Cleaning up placeholder implementations..."
bash "$SCRIPT_DIR/clean_placeholders.sh"
echo ""

echo "=================================================================="
echo "          C ENCRYPTION BENCHMARKS COMPLETED SUCCESSFULLY          "
echo "=================================================================="
echo ""

# Don't print an additional "C tests completed successfully" message
exit 0 