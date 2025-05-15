#ifndef CAMELLIA_IMPLEMENTATION_H
#define CAMELLIA_IMPLEMENTATION_H

#include "../c_core.h"

// Camellia context structure for standard library implementation
typedef struct {
    int key_size;          // Key size in bits (128, 192, or 256)
    char mode[16];         // Mode of operation (CBC, CTR, GCM, ECB)
    int is_custom;         // Whether this is a custom implementation
    unsigned char* key;    // Encryption key
    int key_length;        // Key length in bytes
    unsigned char* iv;     // Initialization vector
    int iv_length;         // IV length in bytes
    
    // For OpenSSL implementation (optional)
    void* openssl_ctx;     // OpenSSL context if using library
} camellia_context_t;

// Function to register all Camellia implementations
void register_camellia_implementations(implementation_registry_t* registry);

// Standard library implementation functions
void* camellia_init(void);
void camellia_cleanup(void* context);
unsigned char* camellia_generate_key(void* context, int* key_length);
unsigned char* camellia_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* camellia_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);

// Stream processing functions
unsigned char* camellia_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* camellia_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Custom implementation functions
void* camellia_custom_init(void);
void camellia_custom_cleanup(void* context);
unsigned char* camellia_custom_generate_key(void* context, int* key_length);
unsigned char* camellia_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* camellia_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);

// Mode-specific implementations
// Camellia-CBC
unsigned char* camellia_cbc_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_cbc_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Camellia-CTR
unsigned char* camellia_ctr_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ctr_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Camellia-GCM
unsigned char* camellia_gcm_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_gcm_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Camellia-ECB
unsigned char* camellia_ecb_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ecb_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif /* CAMELLIA_IMPLEMENTATION_H */ 