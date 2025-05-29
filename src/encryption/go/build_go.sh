#!/bin/bash
# Build script for Go encryption implementations

# Exit on any error
set -e

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Initialize Go module if it doesn't exist
if [ ! -f "$SCRIPT_DIR/go.mod" ]; then
    cd "$SCRIPT_DIR"
    go mod init encryption
fi

# Build the Go program
echo "Building Go implementation..."
cd "$SCRIPT_DIR"

# Remove empty custom implementation files if they exist
find "$SCRIPT_DIR/aes" -type f -name "custom_*.go" -size 0 -delete

# Build the program
go build -o "$SCRIPT_DIR/go_core" go_core.go

# Make the binary executable
chmod +x "$SCRIPT_DIR/go_core"

echo "Go build completed successfully" 