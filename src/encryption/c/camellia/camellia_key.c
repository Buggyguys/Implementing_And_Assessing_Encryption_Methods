#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "camellia_key.h"

unsigned char* camellia_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Free old key if it exists
    if (camellia_context->key) {
        free(camellia_context->key);
        camellia_context->key = NULL;
    }
    
    // Calculate key length in bytes
    camellia_context->key_length = camellia_context->key_size / 8;
    
    // Allocate memory for key
    camellia_context->key = (unsigned char*)malloc(camellia_context->key_length);
    if (!camellia_context->key) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia key\n");
        return NULL;
    }
    
    // Generate random key (temporary implementation)
    generate_random_bytes(camellia_context->key, camellia_context->key_length);
    
    // Generate IV for modes that require it
    if (strcmp(camellia_context->mode, "GCM") == 0) {
        camellia_context->iv_length = 12; // 96 bits for GCM
    } else if (strcmp(camellia_context->mode, "CBC") == 0 || 
               strcmp(camellia_context->mode, "CTR") == 0) {
        camellia_context->iv_length = 16; // 128 bits
    } else {
        camellia_context->iv_length = 0; // ECB doesn't need IV
    }
    
    if (camellia_context->iv_length > 0) {
        if (camellia_context->iv) {
            free(camellia_context->iv);
        }
        
        camellia_context->iv = (unsigned char*)malloc(camellia_context->iv_length);
        if (!camellia_context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for Camellia IV\n");
            free(camellia_context->key);
            camellia_context->key = NULL;
            return NULL;
        }
        
        // Generate random IV (temporary implementation)
        generate_random_bytes(camellia_context->iv, camellia_context->iv_length);
    }
    
    if (key_length) {
        *key_length = camellia_context->key_length;
    }
    
    // Return a copy of the key
    unsigned char* key_copy = (unsigned char*)malloc(camellia_context->key_length);
    if (!key_copy) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia key copy\n");
        return NULL;
    }
    
    memcpy(key_copy, camellia_context->key, camellia_context->key_length);
    return key_copy;
}

unsigned char* camellia_custom_generate_key(void* context, int* key_length) {
    // For now, the custom key generator does the same as the standard one
    // In a real-world implementation, you might want to use different algorithms
    return camellia_generate_key(context, key_length);
}

// Standard Camellia key generation functions for specific key sizes
unsigned char* camellia_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 128 bits
    camellia_context->key_size = 128;
    
    // Call the general key generation function
    return camellia_generate_key(context, key_length);
}

unsigned char* camellia_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 192 bits
    camellia_context->key_size = 192;
    
    // Call the general key generation function
    return camellia_generate_key(context, key_length);
}

unsigned char* camellia_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 256 bits
    camellia_context->key_size = 256;
    
    // Call the general key generation function
    return camellia_generate_key(context, key_length);
}

// Custom Camellia key generation functions for specific key sizes
unsigned char* camellia_custom_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 128 bits
    camellia_context->key_size = 128;
    
    // Call the custom key generation function
    return camellia_custom_generate_key(context, key_length);
}

unsigned char* camellia_custom_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 192 bits
    camellia_context->key_size = 192;
    
    // Call the custom key generation function
    return camellia_custom_generate_key(context, key_length);
}

unsigned char* camellia_custom_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 256 bits
    camellia_context->key_size = 256;
    
    // Call the custom key generation function
    return camellia_custom_generate_key(context, key_length);
}

#ifdef USE_OPENSSL
#include <openssl/rand.h>

// OpenSSL key generation functions for specific key sizes
unsigned char* camellia_openssl_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 128 bits
    camellia_context->key_size = 128;
    
    // Call the OpenSSL key generation function
    return camellia_openssl_generate_key(context, key_length);
}

unsigned char* camellia_openssl_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 192 bits
    camellia_context->key_size = 192;
    
    // Call the OpenSSL key generation function
    return camellia_openssl_generate_key(context, key_length);
}

unsigned char* camellia_openssl_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Set the key size to 256 bits
    camellia_context->key_size = 256;
    
    // Call the OpenSSL key generation function
    return camellia_openssl_generate_key(context, key_length);
}

// Main OpenSSL key generation function
unsigned char* camellia_openssl_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // Free old key if it exists
    if (camellia_context->key) {
        free(camellia_context->key);
        camellia_context->key = NULL;
    }
    
    // Calculate key length in bytes
    camellia_context->key_length = camellia_context->key_size / 8;
    
    // Allocate memory for key
    camellia_context->key = (unsigned char*)malloc(camellia_context->key_length);
    if (!camellia_context->key) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia key\n");
        return NULL;
    }
    
    // Generate random key using OpenSSL
    if (RAND_bytes(camellia_context->key, camellia_context->key_length) != 1) {
        fprintf(stderr, "Error: OpenSSL RAND_bytes failed\n");
        free(camellia_context->key);
        camellia_context->key = NULL;
        return NULL;
    }
    
    // Generate IV for modes that require it
    if (strcmp(camellia_context->mode, "GCM") == 0) {
        camellia_context->iv_length = 12; // 96 bits for GCM
    } else if (strcmp(camellia_context->mode, "CBC") == 0 || 
               strcmp(camellia_context->mode, "CTR") == 0) {
        camellia_context->iv_length = 16; // 128 bits
    } else {
        camellia_context->iv_length = 0; // ECB doesn't need IV
    }
    
    if (camellia_context->iv_length > 0) {
        if (camellia_context->iv) {
            free(camellia_context->iv);
        }
        
        camellia_context->iv = (unsigned char*)malloc(camellia_context->iv_length);
        if (!camellia_context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for Camellia IV\n");
            free(camellia_context->key);
            camellia_context->key = NULL;
            return NULL;
        }
        
        // Generate random IV using OpenSSL
        if (RAND_bytes(camellia_context->iv, camellia_context->iv_length) != 1) {
            fprintf(stderr, "Error: OpenSSL RAND_bytes failed for IV\n");
            free(camellia_context->key);
            free(camellia_context->iv);
            camellia_context->key = NULL;
            camellia_context->iv = NULL;
            return NULL;
        }
    }
    
    if (key_length) {
        *key_length = camellia_context->key_length;
    }
    
    // Return a copy of the key
    unsigned char* key_copy = (unsigned char*)malloc(camellia_context->key_length);
    if (!key_copy) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia key copy\n");
        return NULL;
    }
    
    memcpy(key_copy, camellia_context->key, camellia_context->key_length);
    return key_copy;
}
#endif 