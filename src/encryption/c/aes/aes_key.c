#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "aes_key.h"

unsigned char* aes_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Free old key if it exists
    if (aes_context->key) {
        free(aes_context->key);
        aes_context->key = NULL;
    }
    
    // Calculate key length in bytes
    aes_context->key_length = aes_context->key_size / 8;
    
    // Allocate memory for key
    aes_context->key = (unsigned char*)malloc(aes_context->key_length);
    if (!aes_context->key) {
        fprintf(stderr, "Error: Could not allocate memory for AES key\n");
        return NULL;
    }
    
    // Generate random key (temporary implementation)
    generate_random_bytes(aes_context->key, aes_context->key_length);
    
    // Generate IV for modes that require it
    if (strcmp(aes_context->mode, "GCM") == 0) {
        aes_context->iv_length = 12; // 96 bits for GCM
    } else if (strcmp(aes_context->mode, "CBC") == 0 || 
               strcmp(aes_context->mode, "CTR") == 0) {
        aes_context->iv_length = 16; // 128 bits
    } else {
        aes_context->iv_length = 0; // ECB doesn't need IV
    }
    
    if (aes_context->iv_length > 0) {
        if (aes_context->iv) {
            free(aes_context->iv);
        }
        
        aes_context->iv = (unsigned char*)malloc(aes_context->iv_length);
        if (!aes_context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for AES IV\n");
            free(aes_context->key);
            aes_context->key = NULL;
            return NULL;
        }
        
        // Generate random IV (temporary implementation)
        generate_random_bytes(aes_context->iv, aes_context->iv_length);
    }
    
    if (key_length) {
        *key_length = aes_context->key_length;
    }
    
    // Return a copy of the key
    unsigned char* key_copy = (unsigned char*)malloc(aes_context->key_length);
    if (!key_copy) {
        fprintf(stderr, "Error: Could not allocate memory for AES key copy\n");
        return NULL;
    }
    
    memcpy(key_copy, aes_context->key, aes_context->key_length);
    return key_copy;
}

unsigned char* aes_custom_generate_key(void* context, int* key_length) {
    // For now, the custom key generator does the same as the standard one
    // In a real-world implementation, you might want to use different algorithms
    return aes_generate_key(context, key_length);
}

// Standard AES key generation functions for specific key sizes
unsigned char* aes_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 128 bits
    aes_context->key_size = 128;
    
    // Call the general key generation function
    return aes_generate_key(context, key_length);
}

unsigned char* aes_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 192 bits
    aes_context->key_size = 192;
    
    // Call the general key generation function
    return aes_generate_key(context, key_length);
}

unsigned char* aes_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 256 bits
    aes_context->key_size = 256;
    
    // Call the general key generation function
    return aes_generate_key(context, key_length);
}

// Custom AES key generation functions for specific key sizes
unsigned char* aes_custom_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 128 bits
    aes_context->key_size = 128;
    
    // Call the custom key generation function
    return aes_custom_generate_key(context, key_length);
}

unsigned char* aes_custom_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 192 bits
    aes_context->key_size = 192;
    
    // Call the custom key generation function
    return aes_custom_generate_key(context, key_length);
}

unsigned char* aes_custom_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 256 bits
    aes_context->key_size = 256;
    
    // Call the custom key generation function
    return aes_custom_generate_key(context, key_length);
}

#ifdef USE_OPENSSL
#include <openssl/rand.h>

// OpenSSL key generation functions for specific key sizes
unsigned char* aes_openssl_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 128 bits
    aes_context->key_size = 128;
    
    // Call the OpenSSL key generation function
    return aes_openssl_generate_key(context, key_length);
}

unsigned char* aes_openssl_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 192 bits
    aes_context->key_size = 192;
    
    // Call the OpenSSL key generation function
    return aes_openssl_generate_key(context, key_length);
}

unsigned char* aes_openssl_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Set the key size to 256 bits
    aes_context->key_size = 256;
    
    // Call the OpenSSL key generation function
    return aes_openssl_generate_key(context, key_length);
}

// Main OpenSSL key generation function
unsigned char* aes_openssl_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // Free old key if it exists
    if (aes_context->key) {
        free(aes_context->key);
        aes_context->key = NULL;
    }
    
    // Calculate key length in bytes
    aes_context->key_length = aes_context->key_size / 8;
    
    // Allocate memory for key
    aes_context->key = (unsigned char*)malloc(aes_context->key_length);
    if (!aes_context->key) {
        fprintf(stderr, "Error: Could not allocate memory for AES key\n");
        return NULL;
    }
    
    // Generate random key using OpenSSL
    if (RAND_bytes(aes_context->key, aes_context->key_length) != 1) {
        fprintf(stderr, "Error: OpenSSL RAND_bytes failed\n");
        free(aes_context->key);
        aes_context->key = NULL;
        return NULL;
    }
    
    // Generate IV for modes that require it
    if (strcmp(aes_context->mode, "GCM") == 0) {
        aes_context->iv_length = 12; // 96 bits for GCM
    } else if (strcmp(aes_context->mode, "CBC") == 0 || 
               strcmp(aes_context->mode, "CTR") == 0) {
        aes_context->iv_length = 16; // 128 bits
    } else {
        aes_context->iv_length = 0; // ECB doesn't need IV
    }
    
    if (aes_context->iv_length > 0) {
        if (aes_context->iv) {
            free(aes_context->iv);
        }
        
        aes_context->iv = (unsigned char*)malloc(aes_context->iv_length);
        if (!aes_context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for AES IV\n");
            free(aes_context->key);
            aes_context->key = NULL;
            return NULL;
        }
        
        // Generate random IV using OpenSSL
        if (RAND_bytes(aes_context->iv, aes_context->iv_length) != 1) {
            fprintf(stderr, "Error: OpenSSL RAND_bytes failed for IV\n");
            free(aes_context->key);
            aes_context->key = NULL;
            free(aes_context->iv);
            aes_context->iv = NULL;
            return NULL;
        }
    }
    
    if (key_length) {
        *key_length = aes_context->key_length;
    }
    
    // Return a copy of the key
    unsigned char* key_copy = (unsigned char*)malloc(aes_context->key_length);
    if (!key_copy) {
        fprintf(stderr, "Error: Could not allocate memory for AES key copy\n");
        return NULL;
    }
    
    memcpy(key_copy, aes_context->key, aes_context->key_length);
    return key_copy;
}
#endif 