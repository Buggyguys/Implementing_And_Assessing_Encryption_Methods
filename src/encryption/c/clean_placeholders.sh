#!/bin/bash
# Script to clean placeholder implementations

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the script directory
cd "$SCRIPT_DIR"

# Remove placeholder implementations only
echo "Checking for placeholder implementations..."
for impl_dir in camellia chacha rsa ecc; do
    if [ -f "${impl_dir}/implementation.c" ] && grep -q "// Placeholder implementation" "${impl_dir}/implementation.c"; then
        echo "Removing placeholder ${impl_dir} implementation..."
        rm -f "${impl_dir}/implementation.c"
        
        # For Camellia, also remove the component files if they were created as placeholders
        if [ "$impl_dir" = "camellia" ]; then
            for component in camellia_common camellia_key camellia_gcm camellia_cbc camellia_ctr camellia_ecb; do
                if [ -f "${impl_dir}/${component}.c" ] && grep -q "// Placeholder implementation" "${impl_dir}/${component}.c"; then
                    echo "Removing placeholder ${impl_dir}/${component}.c..."
                    rm -f "${impl_dir}/${component}.c"
                fi
            done
        fi
    fi
done

echo "Placeholder cleanup complete!" 