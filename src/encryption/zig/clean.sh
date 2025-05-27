#!/bin/bash
# Clean script for Zig encryption implementations

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$SCRIPT_DIR"

echo "Cleaning Zig encryption implementations..."

# Remove build artifacts
echo "Removing build artifacts..."
rm -rf build/
rm -rf zig-out/
rm -f zig_core

# Remove build directory in project root
BUILD_DIR="${PROJECT_ROOT}/build/zig_encryption"
if [ -d "$BUILD_DIR" ]; then
    echo "Removing project build directory: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

# Helper function to check if a file is a placeholder
is_placeholder() {
    local file=$1
    if [ -f "$file" ] && grep -q "// Placeholder implementation" "$file"; then
        return 0  # Is a placeholder
    else
        return 1  # Not a placeholder or doesn't exist
    fi
}

# Remove placeholder implementations only (leave actual implementations)
echo "Removing placeholder implementations..."

for impl_dir in aes camellia chacha rsa ecc; do
    if is_placeholder "${impl_dir}/implementation.zig"; then
        echo "Removing placeholder ${impl_dir} implementation..."
        rm -f "${impl_dir}/implementation.zig"
        
        # Remove directory if it's empty
        if [ -d "$impl_dir" ] && [ -z "$(ls -A "$impl_dir")" ]; then
            rmdir "$impl_dir"
            echo "Removed empty directory: $impl_dir"
        fi
    fi
done

# Clean any temporary files
echo "Removing temporary files..."
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.bak" -delete 2>/dev/null || true
find . -name "*~" -delete 2>/dev/null || true

echo "Zig cleanup completed successfully!" 