#ifndef RSA_IMPLEMENTATION_H
#define RSA_IMPLEMENTATION_H

#include "../c_core.h"
#include <stdint.h>
#include <stddef.h>

#ifdef USE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#endif

// padding types
typedef enum {
    PADDING_PKCS1,     // PKCS#1 v1.5 padding
    PADDING_OAEP       // Optimal Asymmetric Encryption Padding
} rsa_padding_type_t;

// rsa header structure for chunked data
typedef struct {
    uint32_t magic;           // magic number for validation
    uint16_t key_size;        // key size in bits
    uint8_t padding_type;     // padding type
    uint8_t reserved;         // reserved for alignment
    uint32_t num_chunks;      // number of encrypted chunks
    uint32_t total_size;      // total original data size
} rsa_header_t;

// rsa context structure
typedef struct {
    int key_size;                    // key size in bits (1024, 2048, 3072, 4096)
    int is_custom;                   // whether this is a custom implementation
    rsa_padding_type_t padding_type; // padding type
    int max_chunk_size;              // maximum input chunk size
    int encrypted_chunk_size;        // size of each encrypted chunk
    
    // for openssl implementation
#ifdef USE_OPENSSL
    RSA* rsa_keypair;               // rsa key pair
#endif
    
    // for custom implementation
    struct {
        uint64_t n;                 // modulus (legacy, for compatibility)
        uint64_t e;                 // public exponent (legacy)
        uint64_t d;                 // private exponent (legacy)
        uint64_t p;                 // prime p (legacy)
        uint64_t q;                 // prime q (legacy)
        int key_length;             // key length in bytes
        
        // actual key components as byte arrays for production use
        unsigned char* n_bytes;     // modulus as bytes
        unsigned char* e_bytes;     // public exponent as bytes
        unsigned char* d_bytes;     // private exponent as bytes
        unsigned char* p_bytes;     // prime p as bytes
        unsigned char* q_bytes;     // prime q as bytes
    } custom_key;
    
    // key storage for return to caller
    unsigned char* key_data;
    int key_data_length;
} rsa_context_t;

// magic number for rsa header validation
#define RSA_MAGIC 0x52534120  // "RSA "

// function prototypes for rsa implementations
void* rsa_init(void);
void rsa_cleanup(void* context);
unsigned char* rsa_generate_key(void* context, int* key_length);
unsigned char* rsa_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* rsa_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// stream processing functions
unsigned char* rsa_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* rsa_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// custom implementation functions
void* rsa_custom_init(void);
void rsa_custom_cleanup(void* context);
unsigned char* rsa_custom_generate_key(void* context, int* key_length);
unsigned char* rsa_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* rsa_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// helper functions
int rsa_calculate_max_chunk_size(int key_size, rsa_padding_type_t padding);
int rsa_calculate_encrypted_chunk_size(int key_size);
int rsa_calculate_total_chunks(size_t data_length, int max_chunk_size);

// internal rsa functions for custom implementation
int rsa_custom_generate_keypair(rsa_context_t* context);
int rsa_custom_encrypt_chunk(rsa_context_t* context, const unsigned char* input, int input_len, unsigned char* output);
int rsa_custom_decrypt_chunk(rsa_context_t* context, const unsigned char* input, int input_len, unsigned char* output);

// demo implementation for educational purposes
int rsa_custom_generate_keypair_demo(rsa_context_t* context);

// modular arithmetic functions for custom implementation
void rsa_mod_exp(const uint8_t* base, const uint8_t* exp, const uint8_t* mod, uint8_t* result, int key_length);
int rsa_generate_prime(uint8_t* prime, int bits);
void rsa_gcd_extended(const uint8_t* a, const uint8_t* b, uint8_t* gcd, uint8_t* x, uint8_t* y, int length);

// registration function
void register_rsa_implementations(implementation_registry_t* registry);

#endif /* RSA_IMPLEMENTATION_H */ 