#!/bin/bash
# Test runner script for Zig encryption implementations

# Exit on error
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$SCRIPT_DIR"

echo "Running Zig encryption implementation tests..."

# Check if Zig is installed
if ! command -v zig &> /dev/null; then
    echo "Error: Zig compiler not found. Please install Zig from https://ziglang.org/"
    exit 1
fi

# Get Zig version
ZIG_VERSION=$(zig version)
echo "Using Zig version: $ZIG_VERSION"

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    if [ -f "./clean.sh" ]; then
        chmod +x clean.sh
        ./clean.sh
    fi
}

# Set trap to cleanup on exit (success or failure)
trap cleanup EXIT

# Build the implementation first (automatic compile)
echo "Building Zig implementation..."
chmod +x build_zig.sh
./build_zig.sh

# Check if the executable was built successfully
if [ ! -f "build/zig_core" ]; then
    echo "Error: Zig core executable not found. Build may have failed."
    exit 1
fi

echo "Build successful. Executable found at: build/zig_core"

# Run unit tests if available
echo "Running unit tests..."
if [ -f "build.zig" ]; then
    zig build test
else
    echo "No build.zig found, skipping unit tests"
fi

# If a config file is provided as argument, run with that config
if [ $# -ge 1 ]; then
    CONFIG_FILE="$1"
    echo "Running with provided config file: $CONFIG_FILE"
    
    # Check if config file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Error: Config file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Run the executable with the provided config
    echo "Running Zig core with configuration..."
    ./build/zig_core "$CONFIG_FILE"
    
    echo "Zig tests completed successfully!"
    exit 0
fi

# If no config provided, run with dummy config for testing
echo "No config file provided, running with test configuration..."

# Create a temporary test config
TEST_CONFIG_FILE="/tmp/zig_test_config.json"
cat > "$TEST_CONFIG_FILE" << 'EOF'
{
    "test_parameters": {
        "iterations": 1,
        "dataset_path": "/tmp/test_data.bin",
        "use_stdlib": true,
        "use_custom": false,
        "processing_strategy": "Memory",
        "chunk_size": "1K"
    },
    "dataset_info": {
        "file_size_kb": 1
    },
    "session_info": {
        "session_dir": "/tmp/zig_test_session",
        "session_id": "test_session_001",
        "human_timestamp": "2024-01-01 12:00:00"
    },
    "encryption_methods": {
        "aes": {
            "enabled": true,
            "key_size": "256",
            "mode": "GCM"
        }
    }
}
EOF

# Create test data
echo "Creating test data..."
mkdir -p /tmp/zig_test_session/results
dd if=/dev/urandom of=/tmp/test_data.bin bs=1024 count=1 2>/dev/null

# Run the executable
echo "Running Zig core with test configuration..."
./build/zig_core "$TEST_CONFIG_FILE"

# Check if results were generated
if [ -f "/tmp/zig_test_session/results/zig_results.json" ]; then
    echo "Test successful! Results generated:"
    cat "/tmp/zig_test_session/results/zig_results.json"
else
    echo "Warning: No results file generated"
fi

# Cleanup test files
echo "Cleaning up test files..."
rm -f "$TEST_CONFIG_FILE"
rm -f /tmp/test_data.bin
rm -rf /tmp/zig_test_session

echo "Zig tests completed successfully!" 