#!/bin/bash
# Clean script for C encryption implementations

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"

echo "Cleaning C implementation build artifacts..."

# Change to the script directory
cd "$SCRIPT_DIR"

# Clean local build directory
if [ -d "build" ]; then
    echo "Removing local build directory contents..."
    rm -rf build/*
fi

# Clean executables
echo "Removing executables..."
rm -f c_core

# Clean project build directory
BUILD_DIR="${PROJECT_ROOT}/build/c_encryption"
if [ -d "$BUILD_DIR" ]; then
    echo "Removing project build directory contents..."
    rm -rf "$BUILD_DIR"/*
fi

# Remove placeholder implementations
echo "Checking for placeholder implementations..."
for impl_dir in camellia chacha rsa ecc; do
    if [ -f "${impl_dir}/implementation.c" ] && grep -q "// Placeholder implementation" "${impl_dir}/implementation.c"; then
        echo "Removing placeholder ${impl_dir} implementation..."
        rm -f "${impl_dir}/implementation.c"
    fi
done

echo "Cleaning complete!" 