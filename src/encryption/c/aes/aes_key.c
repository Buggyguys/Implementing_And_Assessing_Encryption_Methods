#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_key.h"

unsigned char* aes_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // free old key if it exists
    if (aes_context->key) {
        crypto_secure_free(aes_context->key, aes_context->key_length);
        aes_context->key = NULL;
    }
    
    // calculate key length in bytes
    aes_context->key_length = aes_context->key_size / 8;
    
    // allocate memory for key using secure allocation
    aes_context->key = (unsigned char*)crypto_secure_alloc(aes_context->key_length);
    if (!aes_context->key) {
        fprintf(stderr, "Error: Could not allocate memory for AES key\n");
        return NULL;
    }
    
    // generate random key using cryptographically secure function
    if (!crypto_generate_key(aes_context->key, aes_context->key_length)) {
        fprintf(stderr, "Error: Failed to generate AES key\n");
        crypto_secure_free(aes_context->key, aes_context->key_length);
        aes_context->key = NULL;
        return NULL;
    }
    
    // generate IV for modes that require it using standard sizes
    if (aes_context->mode[0] != '\0') {
        aes_context->iv_length = crypto_get_standard_iv_size("AES", aes_context->mode);
    } else {
        // default to GCM
        aes_context->iv_length = 12;
    }
    
    if (aes_context->iv_length > 0) {
        if (aes_context->iv) {
            crypto_secure_free(aes_context->iv, aes_context->iv_length);
        }
        
        aes_context->iv = (unsigned char*)crypto_secure_alloc(aes_context->iv_length);
        if (!aes_context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for AES IV\n");
            crypto_secure_free(aes_context->key, aes_context->key_length);
            aes_context->key = NULL;
            return NULL;
        }
        
        // Generate random IV using cryptographically secure function
        if (!crypto_generate_iv(aes_context->iv, aes_context->iv_length)) {
            fprintf(stderr, "Error: Failed to generate AES IV\n");
            crypto_secure_free(aes_context->iv, aes_context->iv_length);
            crypto_secure_free(aes_context->key, aes_context->key_length);
            aes_context->key = NULL;
            aes_context->iv = NULL;
            return NULL;
        }
    }
    
    if (key_length) {
        *key_length = aes_context->key_length;
    }
    
    // return a copy of the key using secure allocation
    unsigned char* key_copy = (unsigned char*)crypto_secure_alloc(aes_context->key_length);
    if (!key_copy) {
        fprintf(stderr, "Error: Could not allocate memory for AES key copy\n");
        return NULL;
    }
    
    memcpy(key_copy, aes_context->key, aes_context->key_length);
    return key_copy;
}

unsigned char* aes_custom_generate_key(void* context, int* key_length) {
    return aes_generate_key(context, key_length);
}

// standard AES key generation functions for specific key sizes
unsigned char* aes_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 128 bits
    aes_context->key_size = 128;
    return aes_generate_key(context, key_length);
}

unsigned char* aes_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 192 bits
    aes_context->key_size = 192;
    return aes_generate_key(context, key_length);
}

unsigned char* aes_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 256 bits
    aes_context->key_size = 256;
    return aes_generate_key(context, key_length);
}

// custom AES key generation functions for specific key sizes
unsigned char* aes_custom_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 128 bits
    aes_context->key_size = 128;
    return aes_custom_generate_key(context, key_length);
}

unsigned char* aes_custom_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 192 bits
    aes_context->key_size = 192;
    return aes_custom_generate_key(context, key_length);
}

unsigned char* aes_custom_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 256 bits
    aes_context->key_size = 256;
    return aes_custom_generate_key(context, key_length);
}

#ifdef USE_OPENSSL
#include <openssl/rand.h>

// forward declaration
unsigned char* aes_openssl_generate_key(void* context, int* key_length);

// openssl key generation functions for specific key sizes
unsigned char* aes_openssl_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 128 bits
    aes_context->key_size = 128;
    return aes_openssl_generate_key(context, key_length);
}

unsigned char* aes_openssl_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 192 bits
    aes_context->key_size = 192;
    return aes_openssl_generate_key(context, key_length);
}

unsigned char* aes_openssl_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // set the key size to 256 bits
    aes_context->key_size = 256;
    return aes_openssl_generate_key(context, key_length);
}

// main OpenSSL key generation function
unsigned char* aes_openssl_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // free old key if it exists
    if (aes_context->key) {
        free(aes_context->key);
        aes_context->key = NULL;
    }
    
    // calculate key length in bytes
    aes_context->key_length = aes_context->key_size / 8;
    
    // allocate memory for key
    aes_context->key = (unsigned char*)malloc(aes_context->key_length);
    if (!aes_context->key) {
        fprintf(stderr, "Error: Could not allocate memory for AES key\n");
        return NULL;
    }
    
    // generate random key using OpenSSL
    if (RAND_bytes(aes_context->key, aes_context->key_length) != 1) {
        fprintf(stderr, "Error: OpenSSL RAND_bytes failed\n");
        free(aes_context->key);
        aes_context->key = NULL;
        return NULL;
    }
    
    // generate IV for modes that require it
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
        
        // generate random IV using OpenSSL
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
    
    // return a copy of the key
    unsigned char* key_copy = (unsigned char*)malloc(aes_context->key_length);
    if (!key_copy) {
        fprintf(stderr, "Error: Could not allocate memory for AES key copy\n");
        return NULL;
    }
    
    memcpy(key_copy, aes_context->key, aes_context->key_length);
    return key_copy;
}
#endif 