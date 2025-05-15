#ifndef RSA_IMPLEMENTATION_H
#define RSA_IMPLEMENTATION_H

#include "../c_core.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Padding types
typedef enum {
    PADDING_PKCS1,     // PKCS#1 v1.5 padding
    PADDING_OAEP       // Optimal Asymmetric Encryption Padding
} rsa_padding_type_t;

// RSA key structure
typedef struct {
    RSA* rsa;             // OpenSSL RSA key
    unsigned char* n;     // Modulus (public)
    unsigned char* e;     // Public exponent
    unsigned char* d;     // Private exponent
    int bits;             // Key size in bits
    int size;             // Key size in bytes
} rsa_key_t;

// RSA context structure
typedef struct {
    int key_size;          // Key size in bits (1024, 2048, 2072, 4096)
    int is_custom;         // Whether this is a custom implementation
    rsa_padding_type_t padding_type; // Padding type (PKCS#1 v1.5 or OAEP)
    int key_reuse;         // Whether to reuse keys
    int key_count;         // Number of keys to use for key reuse
    
    rsa_key_t** keys;      // Array of RSA keys for key reuse
    int current_key_index; // Current key index for key reuse
    
    // For OpenSSL implementation
    RSA* rsa;              // Current RSA key being used
    unsigned char* private_key; // Private key in DER format
    int private_key_length;     // Private key length
    unsigned char* public_key;  // Public key in DER format
    int public_key_length;      // Public key length
} rsa_context_t;

// Function to register all RSA implementations
void register_rsa_implementations(implementation_registry_t* registry);

// Standard library implementation functions
void* rsa_init(void);
void rsa_cleanup(void* context);
unsigned char* rsa_generate_key(void* context, int* key_length);
unsigned char* rsa_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* rsa_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);

// Stream processing functions
unsigned char* rsa_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* rsa_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Custom implementation functions
void* rsa_custom_init(void);
void rsa_custom_cleanup(void* context);
unsigned char* rsa_custom_generate_key(void* context, int* key_length);
unsigned char* rsa_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* rsa_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* rsa_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* rsa_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Key management functions
int rsa_set_key_size(rsa_context_t* context, int key_size);
int rsa_set_padding(rsa_context_t* context, rsa_padding_type_t padding_type);
int rsa_set_key_reuse(rsa_context_t* context, int key_reuse, int key_count);
RSA* rsa_generate_new_key(int key_size);
void rsa_free_key(rsa_key_t* key);
rsa_key_t* rsa_create_key_from_rsa(RSA* rsa_key);
RSA* rsa_get_current_key(rsa_context_t* context);
rsa_key_t* rsa_get_current_key_struct(rsa_context_t* context);
int rsa_move_to_next_key(rsa_context_t* context);

// Helper functions for RSA operations
int rsa_get_max_data_size(rsa_context_t* context);
int rsa_calculate_output_size(rsa_context_t* context, int data_length);

#endif /* RSA_IMPLEMENTATION_H */ 