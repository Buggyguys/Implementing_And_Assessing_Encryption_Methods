#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>


#include "ecc_common.h"
#include "ecc_key.h"

// Key generation wrapper for the implementation interface
unsigned char* ecc_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Clean up any existing keys
    if (ecc_context->ec_key) {
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
    }
    
    if (ecc_context->private_key) {
        free(ecc_context->private_key);
        ecc_context->private_key = NULL;
        ecc_context->private_key_length = 0;
    }
    
    if (ecc_context->public_key) {
        free(ecc_context->public_key);
        ecc_context->public_key = NULL;
        ecc_context->public_key_length = 0;
    }
    
    // Generate a new key pair
    ecc_context->ec_key = ecc_generate_key_pair(ecc_context->curve);
    if (!ecc_context->ec_key) {
        fprintf(stderr, "Error: Failed to generate EC key pair\n");
        return NULL;
    }
    
    // Export the private key (for return value)
    unsigned char* private_key = ecc_export_private_key(ecc_context->ec_key, &ecc_context->private_key_length);
    if (!private_key) {
        fprintf(stderr, "Error: Failed to export private key\n");
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
        return NULL;
    }
    
    // Store in context
    ecc_context->private_key = (unsigned char*)malloc(ecc_context->private_key_length);
    if (!ecc_context->private_key) {
        fprintf(stderr, "Error: Memory allocation failed for private key\n");
        free(private_key);
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
        return NULL;
    }
    
    memcpy(ecc_context->private_key, private_key, ecc_context->private_key_length);
    
    // Export the public key (for context)
    ecc_context->public_key = ecc_export_public_key(ecc_context->ec_key, &ecc_context->public_key_length);
    if (!ecc_context->public_key) {
        fprintf(stderr, "Error: Failed to export public key\n");
        free(private_key);
        free(ecc_context->private_key);
        ecc_context->private_key = NULL;
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
        return NULL;
    }
    
    // Set the output key length
    *key_length = ecc_context->private_key_length;
    
    return private_key;
}

// Custom implementation key generation (wrapper around standard implementation)
unsigned char* ecc_custom_generate_key(void* context, int* key_length) {
    return ecc_generate_key(context, key_length);
} 