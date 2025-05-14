#!/bin/bash
# Build script for C encryption implementations

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

echo "Building C encryption implementations..."

# Create build directories
mkdir -p build
BUILD_DIR="${PROJECT_ROOT}/build/c_encryption"
mkdir -p "$BUILD_DIR"

# Clean up if requested
if [ $CLEAN_BUILD -eq 1 ]; then
    echo "Cleaning build directory..."
    rm -rf build/*
    rm -f c_core
    rm -f "${BUILD_DIR}/c_encryption_benchmark"
    
    # Remove placeholder implementations only (leave actual implementations)
    for impl_dir in camellia chacha rsa ecc; do
        if [ -f "${impl_dir}/implementation.c" ] && grep -q "// Placeholder implementation" "${impl_dir}/implementation.c"; then
            echo "Removing placeholder ${impl_dir} implementation..."
            rm -f "${impl_dir}/implementation.c"
        fi
    done
fi

# Determine the platform and set library paths
if [ "$(uname)" == "Darwin" ]; then
    # macOS with Homebrew
    if [ -d "/opt/homebrew" ]; then
        # Apple Silicon Mac
        BREW_PREFIX="/opt/homebrew"
    elif [ -d "/usr/local" ]; then
        # Intel Mac
        BREW_PREFIX="/usr/local"
    fi
    
    JSON_C_INCLUDE="${BREW_PREFIX}/include"
    JSON_C_LIB="${BREW_PREFIX}/lib"
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    JSON_C_INCLUDE="/usr/include"
    JSON_C_LIB="/usr/lib"
fi

echo "Using JSON-C include path: ${JSON_C_INCLUDE}"
echo "Using JSON-C library path: ${JSON_C_LIB}"

# Helper function to check if a file exists and contains actual implementation
# rather than just being a placeholder
check_implementation() {
    local file=$1
    if [ ! -f "$file" ]; then
        return 1  # File doesn't exist
    elif grep -q "// Placeholder implementation" "$file"; then
        return 1  # File is just a placeholder
    else
        return 0  # Real implementation exists
    fi
}

# Compile the implementation files
echo "Compiling implementation files..."

# AES implementation
echo "Compiling AES..."
# Compile individual AES mode files
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/aes_gcm.o aes/aes_gcm.c
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/aes_cbc.o aes/aes_cbc.c
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/aes_ctr.o aes/aes_ctr.c
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/aes_ecb.o aes/aes_ecb.c
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/aes_key.o aes/aes_key.c
# Compile main AES implementation
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/aes_implementation.o aes/implementation.c

# Camellia implementation
echo "Compiling Camellia..."
if ! check_implementation "camellia/implementation.c"; then
    echo "Creating placeholder for Camellia implementation"
    mkdir -p camellia
    echo "// Placeholder implementation" > camellia/implementation.c
    echo "#include \"implementation.h\"" >> camellia/implementation.c
    echo "void register_camellia_implementations(implementation_registry_t* registry) {}" >> camellia/implementation.c
fi
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/camellia_implementation.o camellia/implementation.c

# ChaCha20 implementation
echo "Compiling ChaCha20..."
if ! check_implementation "chacha/implementation.c"; then
    echo "Creating placeholder for ChaCha20 implementation"
    mkdir -p chacha
    echo "// Placeholder implementation" > chacha/implementation.c
    echo "#include \"implementation.h\"" >> chacha/implementation.c
    echo "void register_chacha_implementations(implementation_registry_t* registry) {}" >> chacha/implementation.c
fi
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/chacha_implementation.o chacha/implementation.c

# RSA implementation
echo "Compiling RSA..."
if ! check_implementation "rsa/implementation.c"; then
    echo "Creating placeholder for RSA implementation"
    mkdir -p rsa
    echo "// Placeholder implementation" > rsa/implementation.c
    echo "#include \"implementation.h\"" >> rsa/implementation.c
    echo "void register_rsa_implementations(implementation_registry_t* registry) {}" >> rsa/implementation.c
fi
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/rsa_implementation.o rsa/implementation.c

# ECC implementation
echo "Compiling ECC..."
if ! check_implementation "ecc/implementation.c"; then
    echo "Creating placeholder for ECC implementation"
    mkdir -p ecc
    echo "// Placeholder implementation" > ecc/implementation.c
    echo "#include \"implementation.h\"" >> ecc/implementation.c
    echo "void register_ecc_implementations(implementation_registry_t* registry) {}" >> ecc/implementation.c
fi
gcc -Wall -O2 -I"${JSON_C_INCLUDE}" -I"${SCRIPT_DIR}" -c -o build/ecc_implementation.o ecc/implementation.c

# Compile the core with all implementations
echo "Compiling C core..."
gcc -Wall -O2 \
    -I"${JSON_C_INCLUDE}" \
    -I"${SCRIPT_DIR}" \
    -L"${JSON_C_LIB}" \
    -o c_core \
    c_core.c \
    build/aes_implementation.o \
    build/aes_gcm.o \
    build/aes_cbc.o \
    build/aes_ctr.o \
    build/aes_ecb.o \
    build/aes_key.o \
    build/camellia_implementation.o \
    build/chacha_implementation.o \
    build/rsa_implementation.o \
    build/ecc_implementation.o \
    -ljson-c -lm

# Also copy the executable to the project build directory for use by the orchestrator
echo "Copying executable to ${BUILD_DIR}/c_encryption_benchmark"
cp c_core "${BUILD_DIR}/c_encryption_benchmark"

# Set permissions
chmod +x c_core
chmod +x "${BUILD_DIR}/c_encryption_benchmark"

echo "C implementation built successfully" 