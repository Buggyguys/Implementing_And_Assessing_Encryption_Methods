#!/bin/bash

# Exit on error
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"

# Change to the project root directory
cd "$PROJECT_ROOT"

echo "Running Python encryption tests..."

# Check if a configuration file was provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <config_file>"
    exit 1
fi

CONFIG_FILE="$1"
echo "Using configuration file: $CONFIG_FILE"
echo "Script directory: $SCRIPT_DIR"
echo "Project root: $PROJECT_ROOT"

# Add the project root to PYTHONPATH
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# Instead of creating a separate file, directly check registered implementations
python3 -c "from src.encryption.python.aes import AESImplementation; from src.encryption.python.python_core import ENCRYPTION_IMPLEMENTATIONS; print(f\"Registered implementations in preload: {list(ENCRYPTION_IMPLEMENTATIONS.keys())}\")"

# Run the Python core directly using the Python interpreter
python3 -m src.encryption.python.python_core "$CONFIG_FILE"

echo "Python encryption tests completed"
exit 0 