#!/bin/bash
# Build script for C encryption implementations

# Exit on error
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building C encryption implementations..."

# Check if cJSON is available
if [ ! -f "cJSON.c" ]; then
    echo "Downloading cJSON library..."
    curl -L https://github.com/DaveGamble/cJSON/raw/master/cJSON.c -o cJSON.c
    curl -L https://github.com/DaveGamble/cJSON/raw/master/cJSON.h -o cJSON.h
fi

# Compile the core
echo "Compiling C core..."
gcc -Wall -O2 -o c_core c_core.c cJSON.c -lm

# Set permissions
chmod +x c_core

echo "C implementation built successfully" 