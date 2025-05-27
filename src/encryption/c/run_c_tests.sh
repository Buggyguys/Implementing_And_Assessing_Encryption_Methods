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
    
    # Extract if encryption methods are enabled
    AES_ENABLED=$(grep -A10 '"aes": {' "$CONFIG_FILE" | grep -o '"enabled": *\(true\|false\)' | grep -o '\(true\|false\)' | head -1)
    CHACHA20_ENABLED=$(grep -A10 '"chacha20": {' "$CONFIG_FILE" | grep -o '"enabled": *\(true\|false\)' | grep -o '\(true\|false\)' | head -1)
    RSA_ENABLED=$(grep -A10 '"rsa": {' "$CONFIG_FILE" | grep -o '"enabled": *\(true\|false\)' | grep -o '\(true\|false\)' | head -1)
    ECC_ENABLED=$(grep -A10 '"ecc": {' "$CONFIG_FILE" | grep -o '"enabled": *\(true\|false\)' | grep -o '\(true\|false\)' | head -1)
    CAMELLIA_ENABLED=$(grep -A10 '"camellia": {' "$CONFIG_FILE" | grep -o '"enabled": *\(true\|false\)' | grep -o '\(true\|false\)' | head -1)
    
    # Convert to 1/0 for C code
    if [ "$AES_ENABLED" = "true" ]; then
        AES_ENABLED=1
    else
        AES_ENABLED=0
    fi
    
    if [ "$CHACHA20_ENABLED" = "true" ]; then
        CHACHA20_ENABLED=1
    else
        CHACHA20_ENABLED=0
    fi
    
    if [ "$RSA_ENABLED" = "true" ]; then
        RSA_ENABLED=1
    else
        RSA_ENABLED=0
    fi
    
    if [ "$ECC_ENABLED" = "true" ]; then
        ECC_ENABLED=1
    else
        ECC_ENABLED=0
    fi
    
    if [ "$CAMELLIA_ENABLED" = "true" ]; then
        CAMELLIA_ENABLED=1
    else
        CAMELLIA_ENABLED=0
    fi
    
    # Extract RSA key size, padding, and key reuse settings
    RSA_KEY_SIZE=$(grep -A10 '"rsa": {' "$CONFIG_FILE" | grep -o '"key_size": *"[^"]*"' | grep -o '[0-9]\+' | head -1)
    RSA_PADDING=$(grep -A10 '"rsa": {' "$CONFIG_FILE" | grep -o '"padding": *"[^"]*"' | awk -F'"' '{print $4}' | head -1)
    RSA_KEY_REUSE=$(grep -A10 '"rsa": {' "$CONFIG_FILE" | grep -o '"reuse_keys": *\(true\|false\)' | grep -o '\(true\|false\)' | head -1)
    RSA_KEY_COUNT=$(grep -A10 '"rsa": {' "$CONFIG_FILE" | grep -o '"key_sets": *[0-9]\+' | grep -o '[0-9]\+' | head -1)
    
    # Convert RSA_PADDING to lowercase format expected by implementation
    if [ "$RSA_PADDING" = "PKCS#1 v1.5" ] || [ "$RSA_PADDING" = "PKCS1" ]; then
        RSA_PADDING="pkcs1"
    elif [ "$RSA_PADDING" = "OAEP" ]; then
        RSA_PADDING="oaep"
    fi
    
    # Convert boolean true/false to 1/0 for key reuse
    if [ "$RSA_KEY_REUSE" = "true" ]; then
        RSA_KEY_REUSE=1
    else
        RSA_KEY_REUSE=0
    fi
    
    # Extract use_stdlib and use_custom settings
    USE_STDLIB=$(grep -o '"use_stdlib": *\(true\|false\)' "$CONFIG_FILE" | grep -o '\(true\|false\)' | head -1)
    USE_CUSTOM=$(grep -o '"use_custom": *\(true\|false\)' "$CONFIG_FILE" | grep -o '\(true\|false\)' | head -1)
    
    # Extract ECC curve setting
    ECC_CURVE=$(grep -A10 '"ecc": {' "$CONFIG_FILE" | grep -o '"curve": *"[^"]*"' | awk -F'"' '{print $4}' | head -1)
    
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
    
    # Export RSA configuration
    export RSA_KEY_SIZE=$RSA_KEY_SIZE
    export RSA_PADDING=$RSA_PADDING
    export RSA_KEY_REUSE=$RSA_KEY_REUSE
    export RSA_KEY_COUNT=$RSA_KEY_COUNT
    
    # Export ECC configuration
    export ECC_CURVE=$ECC_CURVE
    
    # Export enabled flags for each algorithm
    export AES_ENABLED=$AES_ENABLED
    export CHACHA20_ENABLED=$CHACHA20_ENABLED
    export RSA_ENABLED=$RSA_ENABLED
    export ECC_ENABLED=$ECC_ENABLED
    export CAMELLIA_ENABLED=$CAMELLIA_ENABLED
    
    # Log the configuration that will be used
    echo "RSA Configuration: Key Size=$RSA_KEY_SIZE, Padding=$RSA_PADDING, Key Reuse=$RSA_KEY_REUSE, Key Count=$RSA_KEY_COUNT"
    echo "ECC Configuration: Curve=\"$ECC_CURVE\" (value set in environment variable)"
    echo "Enabled Algorithms: AES=$AES_ENABLED, ChaCha20=$CHACHA20_ENABLED, RSA=$RSA_ENABLED, ECC=$ECC_ENABLED, Camellia=$CAMELLIA_ENABLED"
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
LOCAL_EXECUTABLE="$SCRIPT_DIR/build/c_core"
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
bash "$SCRIPT_DIR/clean.sh"
echo ""

echo "=================================================================="
echo "          C ENCRYPTION BENCHMARKS COMPLETED SUCCESSFULLY          "
echo "=================================================================="
echo ""

# Don't print an additional "C tests completed successfully" message
exit 0 