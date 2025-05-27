#!/bin/bash
# Build script for Zig encryption implementations

# Exit on error
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$SCRIPT_DIR"

# Check for clean build flag
CLEAN_BUILD=0
if [ "$1" = "clean" ]; then
    CLEAN_BUILD=1
    echo "Performing clean build..."
fi

echo "Building Zig encryption implementations..."

# Create build directories
mkdir -p build
BUILD_DIR="${PROJECT_ROOT}/build/zig_encryption"
mkdir -p "$BUILD_DIR"

# Clean up if requested
if [ $CLEAN_BUILD -eq 1 ]; then
    echo "Cleaning build directory..."
    rm -rf build/*
    rm -f zig_core
    rm -f "${BUILD_DIR}/zig_encryption_benchmark"
    
    # Remove placeholder implementations only (leave actual implementations)
    for impl_dir in camellia chacha rsa ecc; do
        if [ -f "${impl_dir}/implementation.zig" ] && grep -q "// Placeholder implementation" "${impl_dir}/implementation.zig"; then
            echo "Removing placeholder ${impl_dir} implementation..."
            rm -f "${impl_dir}/implementation.zig"
        fi
    done
fi

# Check if Zig is installed
if ! command -v zig &> /dev/null; then
    echo "Error: Zig compiler not found. Please install Zig from https://ziglang.org/"
    exit 1
fi

# Get Zig version
ZIG_VERSION=$(zig version)
echo "Using Zig version: $ZIG_VERSION"

# Check for minimum Zig version (0.11.0 or higher)
REQUIRED_VERSION="0.11.0"
if ! printf '%s\n%s\n' "$REQUIRED_VERSION" "$ZIG_VERSION" | sort -V -C; then
    echo "Warning: Zig version $ZIG_VERSION may not be compatible. Recommended: $REQUIRED_VERSION or higher"
fi

# Build with Zig
echo "Compiling Zig implementation..."
zig build -Doptimize=ReleaseFast

# Check if the executable was built successfully
if [ ! -f "zig-out/bin/zig_core" ]; then
    echo "Error: Zig core executable not found at zig-out/bin/zig_core. Build may have failed."
    exit 1
fi

# Copy the executable to our build directory
cp zig-out/bin/zig_core build/zig_core

# Create a symlink in the current directory for backward compatibility
ln -sf build/zig_core zig_core

# Also copy to project build directory
cp build/zig_core "${BUILD_DIR}/zig_encryption_benchmark"

echo "Zig encryption implementation build complete!"
echo "Executable available at:"
echo "  - Local: build/zig_core"
echo "  - Project: ${BUILD_DIR}/zig_encryption_benchmark" 