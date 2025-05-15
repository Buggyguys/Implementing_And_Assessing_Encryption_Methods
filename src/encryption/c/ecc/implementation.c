#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#include "implementation.h"
#include "../include/utils.h"
#include "ecc_common.h"
#include "ecc_key.h"

// Register ECC implementations based on configuration
void register_ecc_implementations(implementation_registry_t* registry) {
    int index = registry->count;
    
    // Get the configuration from environment variables
    char* use_stdlib_str = getenv("USE_STDLIB");
    char* use_custom_str = getenv("USE_CUSTOM");
    char* curve_str = getenv("ECC_CURVE");
    char* ecc_enabled_str = getenv("ECC_ENABLED");
    
    // Default values if environment variables are not set
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;  // Default to true
    int use_custom = use_custom_str ? atoi(use_custom_str) : 1;  // Default to true
    ecc_curve_type_t curve = CURVE_P256;  // Default to P-256
    int ecc_enabled = ecc_enabled_str ? atoi(ecc_enabled_str) : 1;  // Default to enabled
    
    // Normalize and parse curve parameter
    if (curve_str) {
        // Remove any spaces and convert to uppercase for comparison
        char normalized_curve[32] = {0};
        int j = 0;
        for (int i = 0; curve_str[i] && j < sizeof(normalized_curve)-1; i++) {
            if (curve_str[i] != ' ' && curve_str[i] != '-') {
                normalized_curve[j++] = toupper(curve_str[i]);
            }
        }
        
        // Compare with normalized curve names
        if (strcmp(normalized_curve, "P256") == 0 || strcmp(normalized_curve, "SECP256R1") == 0) {
            curve = CURVE_P256;
        } else if (strcmp(normalized_curve, "P384") == 0 || strcmp(normalized_curve, "SECP384R1") == 0) {
            curve = CURVE_P384;
        } else if (strcmp(normalized_curve, "P521") == 0 || strcmp(normalized_curve, "SECP521R1") == 0) {
            curve = CURVE_P521;
        } else {
            fprintf(stderr, "Warning: Unrecognized ECC curve '%s', defaulting to P-256\n", curve_str);
        }
    }
    
    // Check if ECC is enabled in the configuration
    if (!ecc_enabled) {
        printf("ECC implementations disabled in configuration\n");
        return;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Determine key size based on curve
    int key_size;
    const char* curve_name;
    
    switch(curve) {
        case CURVE_P384:
            key_size = 384;
            curve_name = "P-384";
            break;
        case CURVE_P521:
            key_size = 521;
            curve_name = "P-521";
            break;
        case CURVE_P256:
        default:
            key_size = 256;
            curve_name = "P-256";
            break;
    }
    
    // Register standard ECC implementation if enabled
    if (use_stdlib) {
        char impl_name[64];
        snprintf(impl_name, sizeof(impl_name), "ecc_%s", curve_name);
        
        strcpy(registry->implementations[index].name, impl_name);
        registry->implementations[index].algo_type = ALGO_ECC;
        registry->implementations[index].is_custom = 0;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, curve_name);
        registry->implementations[index].init = ecc_init;
        registry->implementations[index].cleanup = ecc_cleanup;
        registry->implementations[index].generate_key = ecc_generate_key;
        registry->implementations[index].encrypt = ecc_encrypt;
        registry->implementations[index].decrypt = ecc_decrypt;
        registry->implementations[index].encrypt_stream = ecc_encrypt_stream;
        registry->implementations[index].decrypt_stream = ecc_decrypt_stream;
        registry->count++;
    }
    
    // Register custom ECC implementation if enabled
    if (use_custom) {
        index = registry->count;
        char impl_name[64];
        snprintf(impl_name, sizeof(impl_name), "ecc_%s_custom", curve_name);
        
        strcpy(registry->implementations[index].name, impl_name);
        registry->implementations[index].algo_type = ALGO_ECC;
        registry->implementations[index].is_custom = 1;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, curve_name);
        registry->implementations[index].init = ecc_custom_init;
        registry->implementations[index].cleanup = ecc_custom_cleanup;
        registry->implementations[index].generate_key = ecc_custom_generate_key;
        registry->implementations[index].encrypt = ecc_custom_encrypt;
        registry->implementations[index].decrypt = ecc_custom_decrypt;
        registry->implementations[index].encrypt_stream = ecc_custom_encrypt_stream;
        registry->implementations[index].decrypt_stream = ecc_custom_decrypt_stream;
        registry->count++;
    }
}

// Standard library implementation functions
void* ecc_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 0;
    context->curve = CURVE_P256;  // Default to P-256
    context->ec_key = NULL;
    context->private_key = NULL;
    context->private_key_length = 0;
    context->public_key = NULL;
    context->public_key_length = 0;
    context->shared_secret = NULL;
    context->shared_secret_length = 0;
    
    // Get curve from environment variable
    char* curve_str = getenv("ECC_CURVE");
    if (curve_str) {
        // Normalize curve name using the same approach as in register_ecc_implementations
        char normalized_curve[32] = {0};
        int j = 0;
        for (int i = 0; curve_str[i] && j < sizeof(normalized_curve)-1; i++) {
            if (curve_str[i] != ' ' && curve_str[i] != '-') {
                normalized_curve[j++] = toupper(curve_str[i]);
            }
        }
        
        // Compare with normalized curve names
        if (strcmp(normalized_curve, "P256") == 0 || strcmp(normalized_curve, "SECP256R1") == 0) {
            context->curve = CURVE_P256;
        } else if (strcmp(normalized_curve, "P384") == 0 || strcmp(normalized_curve, "SECP384R1") == 0) {
            context->curve = CURVE_P384;
        } else if (strcmp(normalized_curve, "P521") == 0 || strcmp(normalized_curve, "SECP521R1") == 0) {
            context->curve = CURVE_P521;
        } else {
            fprintf(stderr, "Warning in ecc_init: Unrecognized curve '%s', defaulting to P-256\n", curve_str);
        }
    }
    
    return context;
}

void ecc_cleanup(void* context) {
    if (!context) return;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Free EC key
    if (ecc_context->ec_key) {
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
    }
    
    // Free private key
    if (ecc_context->private_key) {
        free(ecc_context->private_key);
        ecc_context->private_key = NULL;
    }
    
    // Free public key
    if (ecc_context->public_key) {
        free(ecc_context->public_key);
        ecc_context->public_key = NULL;
    }
    
    // Free shared secret
    if (ecc_context->shared_secret) {
        free(ecc_context->shared_secret);
        ecc_context->shared_secret = NULL;
    }
    
    free(ecc_context);
}

// Custom implementation functions (for benchmarking purposes)
void* ecc_custom_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC context for custom implementation\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 1;
    context->curve = CURVE_P256;  // Default to P-256
    context->ec_key = NULL;
    context->private_key = NULL;
    context->private_key_length = 0;
    context->public_key = NULL;
    context->public_key_length = 0;
    context->shared_secret = NULL;
    context->shared_secret_length = 0;
    
    // Get curve from environment variable
    char* curve_str = getenv("ECC_CURVE");
    if (curve_str) {
        // Normalize curve name using the same approach as in register_ecc_implementations
        char normalized_curve[32] = {0};
        int j = 0;
        for (int i = 0; curve_str[i] && j < sizeof(normalized_curve)-1; i++) {
            if (curve_str[i] != ' ' && curve_str[i] != '-') {
                normalized_curve[j++] = toupper(curve_str[i]);
            }
        }
        
        // Compare with normalized curve names
        if (strcmp(normalized_curve, "P256") == 0 || strcmp(normalized_curve, "SECP256R1") == 0) {
            context->curve = CURVE_P256;
        } else if (strcmp(normalized_curve, "P384") == 0 || strcmp(normalized_curve, "SECP384R1") == 0) {
            context->curve = CURVE_P384;
        } else if (strcmp(normalized_curve, "P521") == 0 || strcmp(normalized_curve, "SECP521R1") == 0) {
            context->curve = CURVE_P521;
        } else {
            fprintf(stderr, "Warning in ecc_custom_init: Unrecognized curve '%s', defaulting to P-256\n", curve_str);
        }
    }
    
    return context;
}

void ecc_custom_cleanup(void* context) {
    ecc_cleanup(context); // Same cleanup for both implementations
} 