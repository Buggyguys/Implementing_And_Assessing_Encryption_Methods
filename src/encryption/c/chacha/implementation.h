#ifndef CHACHA_IMPLEMENTATION_H
#define CHACHA_IMPLEMENTATION_H

#include "../c_core.h"

// ChaCha20 context structure
typedef struct {
    int is_custom;         // Whether this is a custom implementation
    unsigned char* key;    // 32-byte key (256 bits)
    int key_length;        // Key length in bytes (typically 32)
    unsigned char* nonce;  // 12-byte nonce (96 bits)
    int nonce_length;      // Nonce length in bytes (typically 12)
    unsigned int counter;  // Counter for ChaCha20
    
    // For OpenSSL implementation (optional)
    void* openssl_ctx;     // OpenSSL context if using library
} chacha_context_t;

// function to register all ChaCha20 implementations
void register_chacha_implementations(implementation_registry_t* registry);

// function prototypes for ChaCha20 implementations
void* chacha_init(void);
void chacha_cleanup(void* context);
unsigned char* chacha_generate_key(void* context, int* key_length);
unsigned char* chacha_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* chacha_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// stream processing functions
unsigned char* chacha_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* chacha_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// custom implementation functions
void* chacha_custom_init(void);
void chacha_custom_cleanup(void* context);
unsigned char* chacha_custom_generate_key(void* context, int* key_length);
unsigned char* chacha_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* chacha_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// custom stream processing functions
unsigned char* chacha_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* chacha_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

#endif 