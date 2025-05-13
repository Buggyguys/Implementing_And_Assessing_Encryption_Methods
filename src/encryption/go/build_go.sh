#!/bin/bash
# Build script for Go encryption implementations

# Exit on error
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building Go encryption implementations..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Go not found. Please install Go to build this implementation."
    exit 1
fi

# Initialize Go module if not already initialized
if [ ! -f "go.mod" ]; then
    echo "Initializing Go module..."
    go mod init cryptobench
    
    # Add required dependencies
    go get golang.org/x/crypto/aes
    go get golang.org/x/crypto/chacha20poly1305
    go get golang.org/x/crypto/rsa
    go get golang.org/x/crypto/ecdh
fi

# Build the Go implementation
echo "Building Go core..."
go build -o go_core go_core.go

# Set permissions
chmod +x go_core

echo "Go implementation built successfully" 