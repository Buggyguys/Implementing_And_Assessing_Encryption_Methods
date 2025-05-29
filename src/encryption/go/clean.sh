#!/bin/bash

# Exit on any error
set -e

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Remove build directory
BUILD_DIR="$SCRIPT_DIR/build"
if [ -d "$BUILD_DIR" ]; then
    echo "Cleaning Go build directory..."
    rm -rf "$BUILD_DIR"
    echo "Clean completed successfully"
else
    echo "Build directory not found, nothing to clean"
fi 