#ifndef AES_IMPLEMENTATION_H
#define AES_IMPLEMENTATION_H

#include "../c_core.h"

// AES context structure for standard library implementation
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
} aes_context_t;

// Function to register all AES implementations
void register_aes_implementations(implementation_registry_t* registry);

// Include all other AES headers - this is done in implementation.c, not here
// to avoid circular dependencies. Other files should include the specific headers
// they need.

// Standard library implementation functions
void* aes_init(void);
void aes_cleanup(void* context);
unsigned char* aes_generate_key(void* context, int* key_length);
unsigned char* aes_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* aes_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// Stream processing functions
unsigned char* aes_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* aes_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Custom implementation functions
void* aes_custom_init(void);
void aes_custom_cleanup(void* context);
unsigned char* aes_custom_generate_key(void* context, int* key_length);
unsigned char* aes_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* aes_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// Mode-specific implementations
// AES-CBC
unsigned char* aes_cbc_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_cbc_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// AES-CTR
unsigned char* aes_ctr_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_ctr_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// AES-GCM
unsigned char* aes_gcm_encrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* aes_gcm_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// AES-ECB
unsigned char* aes_ecb_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_ecb_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

#endif /* AES_IMPLEMENTATION_H */ 