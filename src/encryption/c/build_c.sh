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
            
            # For Camellia, also remove the component files if they were created as placeholders
            if [ "$impl_dir" = "camellia" ]; then
                for component in camellia_common camellia_key camellia_cbc camellia_cfb camellia_ofb; do
                    if [ -f "${impl_dir}/${component}.c" ] && grep -q "// Placeholder implementation" "${impl_dir}/${component}.c"; then
                        echo "Removing placeholder ${impl_dir}/${component}.c..."
                        rm -f "${impl_dir}/${component}.c"
                    fi
                done
            fi
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
    
    # Check for OpenSSL in Homebrew
    if [ -d "${BREW_PREFIX}/opt/openssl@3" ]; then
        OPENSSL_PREFIX="${BREW_PREFIX}/opt/openssl@3"
    elif [ -d "${BREW_PREFIX}/opt/openssl@1.1" ]; then
        OPENSSL_PREFIX="${BREW_PREFIX}/opt/openssl@1.1"
    elif [ -d "${BREW_PREFIX}/opt/openssl" ]; then
        OPENSSL_PREFIX="${BREW_PREFIX}/opt/openssl"
    else
        echo "Error: OpenSSL not found in Homebrew"
        exit 1
    fi
    
    OPENSSL_INCLUDE="${OPENSSL_PREFIX}/include"
    OPENSSL_LIB="${OPENSSL_PREFIX}/lib"
    
    # Verify OpenSSL headers exist
    if [ ! -f "${OPENSSL_INCLUDE}/openssl/rsa.h" ]; then
        echo "Error: OpenSSL headers not found at ${OPENSSL_INCLUDE}/openssl"
        echo "Please install OpenSSL with Homebrew: brew install openssl"
        exit 1
    fi
    
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    JSON_C_INCLUDE="/usr/include"
    JSON_C_LIB="/usr/lib"
    OPENSSL_INCLUDE="/usr/include"
    OPENSSL_LIB="/usr/lib"
    
    # Check if OpenSSL headers exist
    if [ ! -f "${OPENSSL_INCLUDE}/openssl/rsa.h" ]; then
        echo "Error: OpenSSL headers not found at ${OPENSSL_INCLUDE}/openssl"
        echo "Please install OpenSSL development headers:"
        echo "  Debian/Ubuntu: apt-get install libssl-dev"
        echo "  RHEL/CentOS: yum install openssl-devel"
        exit 1
    fi
fi

echo "Using JSON-C include path: ${JSON_C_INCLUDE}"
echo "Using JSON-C library path: ${JSON_C_LIB}"
echo "Using OpenSSL include path: ${OPENSSL_INCLUDE}"
echo "Using OpenSSL library path: ${OPENSSL_LIB}"

# Define our include paths - use direct paths without quotes
INCLUDE_FLAGS="-I${SCRIPT_DIR}/include -I${JSON_C_INCLUDE} -I${OPENSSL_INCLUDE} -I${SCRIPT_DIR}"

# Common compilation flags
CFLAGS="-Wall -O2 ${INCLUDE_FLAGS} -DOPENSSL_API_COMPAT=0x10100000L -Wno-deprecated-declarations -DUSE_OPENSSL"

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

# First, compile cJSON as it's used by all implementations
echo "Compiling cJSON..."
gcc ${CFLAGS} -c -o build/cJSON.o include/cJSON.c

# Compile crypto utilities
echo "Compiling crypto utilities..."
gcc ${CFLAGS} -c -o build/crypto_utils.o include/crypto_utils.c

# AES implementation
echo "Compiling AES..."
# Compile individual AES mode files - Updated modes: CBC, GCM, CFB, OFB
gcc ${CFLAGS} -c -o build/aes_core.o aes/aes_core.c
gcc ${CFLAGS} -c -o build/aes_gcm.o aes/aes_gcm.c
gcc ${CFLAGS} -c -o build/aes_cbc.o aes/aes_cbc.c
gcc ${CFLAGS} -c -o build/aes_cfb.o aes/aes_cfb.c
gcc ${CFLAGS} -c -o build/aes_ofb.o aes/aes_ofb.c
gcc ${CFLAGS} -c -o build/aes_key.o aes/aes_key.c
# Compile main AES implementation
gcc ${CFLAGS} -c -o build/aes_implementation.o aes/implementation.c

# Camellia implementation
echo "Compiling Camellia..."
echo "Creating placeholder for Camellia implementation"
mkdir -p camellia
echo "// Placeholder implementation" > camellia/implementation.c
echo "#include \"implementation.h\"" >> camellia/implementation.c
echo "void register_camellia_implementations(implementation_registry_t* registry) {}" >> camellia/implementation.c
gcc ${CFLAGS} -c -o build/camellia_implementation.o camellia/implementation.c

# ChaCha20 implementation
echo "Compiling ChaCha20..."
if ! check_implementation "chacha/implementation.c"; then
    echo "Creating placeholder for ChaCha20 implementation"
    mkdir -p chacha
    echo "// Placeholder implementation" > chacha/implementation.c
    echo "#include \"implementation.h\"" >> chacha/implementation.c
    echo "void register_chacha_implementations(implementation_registry_t* registry) {}" >> chacha/implementation.c
fi
gcc ${CFLAGS} -c -o build/chacha_implementation.o chacha/implementation.c

# RSA implementation
echo "Compiling RSA..."
if ! check_implementation "rsa/implementation.c"; then
    echo "Creating placeholder for RSA implementation"
    mkdir -p rsa
    echo "// Placeholder implementation" > rsa/implementation.c
    echo "#include \"implementation.h\"" >> rsa/implementation.c
    echo "void register_rsa_implementations(implementation_registry_t* registry) {}" >> rsa/implementation.c
fi
gcc ${CFLAGS} -c -o build/rsa_implementation.o rsa/implementation.c

# Check for and compile RSA helper files if they exist
if [ -f "rsa/rsa_key.c" ]; then
    echo "Compiling RSA key management..."
    gcc ${CFLAGS} -c -o build/rsa_key.o rsa/rsa_key.c
fi

if [ -f "rsa/rsa_common.c" ]; then
    echo "Compiling RSA common functions..."
    gcc ${CFLAGS} -c -o build/rsa_common.o rsa/rsa_common.c
fi

# ECC implementation
echo "Compiling ECC..."
if ! check_implementation "ecc/implementation.c"; then
    echo "Creating placeholder for ECC implementation"
    mkdir -p ecc
    echo "// Placeholder implementation" > ecc/implementation.c
    echo "#include \"implementation.h\"" >> ecc/implementation.c
    echo "void register_ecc_implementations(implementation_registry_t* registry) {}" >> ecc/implementation.c
fi
gcc ${CFLAGS} -c -o build/ecc_implementation.o ecc/implementation.c

# Check for and compile ECC helper files if they exist
if [ -f "ecc/ecc_common.c" ]; then
    echo "Compiling ECC common functions..."
    gcc ${CFLAGS} -c -o build/ecc_common.o ecc/ecc_common.c
fi

if [ -f "ecc/ecc_key.c" ]; then
    echo "Compiling ECC key management..."
    gcc ${CFLAGS} -c -o build/ecc_key.o ecc/ecc_key.c
fi

if [ -f "ecc/encryption_ecc.c" ]; then
    echo "Compiling ECC encryption functions..."
    gcc ${CFLAGS} -c -o build/encryption_ecc.o ecc/encryption_ecc.c
fi

if [ -f "ecc/decryption_ecc.c" ]; then
    echo "Compiling ECC decryption functions..."
    gcc ${CFLAGS} -c -o build/decryption_ecc.o ecc/decryption_ecc.c
fi

# Compile the core with all implementations
echo "Compiling C core..."
gcc -Wall -O2 \
    ${INCLUDE_FLAGS} \
    -DOPENSSL_API_COMPAT=0x10100000L \
    -Wno-deprecated-declarations \
    -L"${JSON_C_LIB}" \
    -L"${OPENSSL_LIB}" \
    -o build/c_core \
    c_core.c \
    build/cJSON.o \
    build/crypto_utils.o \
    build/aes_implementation.o \
    build/aes_core.o \
    build/aes_gcm.o \
    build/aes_cbc.o \
    build/aes_cfb.o \
    build/aes_ofb.o \
    build/aes_key.o \
    build/camellia_implementation.o \
    $([ -f build/camellia_common.o ] && echo "build/camellia_common.o") \
    $([ -f build/camellia_key.o ] && echo "build/camellia_key.o") \
    $([ -f build/camellia_cbc.o ] && echo "build/camellia_cbc.o") \
    $([ -f build/camellia_cfb.o ] && echo "build/camellia_cfb.o") \
    $([ -f build/camellia_ofb.o ] && echo "build/camellia_ofb.o") \
    $([ -f build/camellia_ecb.o ] && echo "build/camellia_ecb.o") \
    build/chacha_implementation.o \
    build/rsa_implementation.o \
    $([ -f build/rsa_key.o ] && echo "build/rsa_key.o") \
    $([ -f build/rsa_common.o ] && echo "build/rsa_common.o") \
    build/ecc_implementation.o \
    $([ -f build/ecc_common.o ] && echo "build/ecc_common.o") \
    $([ -f build/ecc_key.o ] && echo "build/ecc_key.o") \
    $([ -f build/encryption_ecc.o ] && echo "build/encryption_ecc.o") \
    $([ -f build/decryption_ecc.o ] && echo "build/decryption_ecc.o") \
    -lcrypto -lssl -ldl -lpthread

# Create a symlink in the current directory for backward compatibility
ln -sf build/c_core c_core

# Also copy to project build directory
cp build/c_core "${BUILD_DIR}/c_encryption_benchmark"

echo "C encryption implementation build complete!" 