#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/utils.h"
#include "camellia_key.h"

// s-box for custom key derivation
static const uint8_t camellia_sbox1[256] = {
    0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
    0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
    0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
    0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
    0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
    0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
    0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
    0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
    0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
    0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
    0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
};

// custom key derivation for enhanced security (currently unused but kept for future use)
void camellia_custom_key_derivation(const uint8_t* original_key, size_t key_len, uint8_t* derived_key) {
    // apply multiple rounds of transformation
    memcpy(derived_key, original_key, key_len);
    
    for (int round = 0; round < 5; round++) {
        for (size_t i = 0; i < key_len; i++) {
            derived_key[i] = camellia_sbox1[derived_key[i]] ^ (round * 0x5A + i);
            derived_key[i] = ((derived_key[i] << 3) | (derived_key[i] >> 5)) & 0xFF;
        }
    }
}

#ifdef USE_OPENSSL
#include <openssl/rand.h>

// openssl key generation functions for specific key sizes
unsigned char* camellia_openssl_generate_key_128(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // set key size to 128 bits
    camellia_context->key_size = 128;
    
    // call openssl key generation function
    return camellia_openssl_generate_key(context, key_length);
}

unsigned char* camellia_openssl_generate_key_192(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // set key size to 192 bits
    camellia_context->key_size = 192;
    
    // call openssl key generation function
    return camellia_openssl_generate_key(context, key_length);
}

unsigned char* camellia_openssl_generate_key_256(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // set key size to 256 bits
    camellia_context->key_size = 256;
    
    // call openssl key generation function
    return camellia_openssl_generate_key(context, key_length);
}

// main openssl key generation function
unsigned char* camellia_openssl_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // free old key if it exists
    if (camellia_context->key) {
        free(camellia_context->key);
        camellia_context->key = NULL;
    }
    
    // calculate key length in bytes
    camellia_context->key_length = camellia_context->key_size / 8;
    
    // allocate memory for key
    camellia_context->key = (unsigned char*)malloc(camellia_context->key_length);
    if (!camellia_context->key) {
        fprintf(stderr, "Error: Could not allocate memory for key\n");
        return NULL;
    }
    
    // generate random key using openssl
    if (RAND_bytes(camellia_context->key, camellia_context->key_length) != 1) {
        fprintf(stderr, "Error: OpenSSL RAND_bytes failed\n");
        free(camellia_context->key);
        camellia_context->key = NULL;
        return NULL;
    }
    
    // generate iv for modes that require it
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
            fprintf(stderr, "Error: Could not allocate memory for IV\n");
            free(camellia_context->key);
            camellia_context->key = NULL;
            return NULL;
        }
        
        // generate random iv using openssl
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
    
    // return a copy of the key
    unsigned char* key_copy = (unsigned char*)malloc(camellia_context->key_length);
    if (!key_copy) {
        fprintf(stderr, "Error: Could not allocate memory for key copy\n");
        return NULL;
    }
    
    memcpy(key_copy, camellia_context->key, camellia_context->key_length);
    return key_copy;
}
#endif 