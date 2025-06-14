#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include "implementation.h"
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "chacha_common.h"
#include "chacha_key.h"

// quarter round function
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (			\
	a += b,  d ^= a,  d = ROTL(d,16),	\
	c += d,  b ^= c,  b = ROTL(b,12),	\
	a += b,  d ^= a,  d = ROTL(d, 8),	\
	c += d,  b ^= c,  b = ROTL(b, 7))

// block function (custom implementation)
static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    int i;
    uint32_t x[16];

    for (i = 0; i < 16; ++i) x[i] = in[i];
    // 20 rounds
    for (i = 0; i < 10; ++i) {
        // column rounds
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

// convert bytes to little-endian uint32_t
static uint32_t load32_le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// convert little-endian uint32_t to bytes
static void store32_le(unsigned char *p, uint32_t x) {
    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

// implementation registered
void register_chacha_implementations(implementation_registry_t* registry) {
    int index = registry->count;
    int implementations_before = registry->count;
    
    // get configuration from environment variables
    char* use_stdlib_str = getenv("USE_STDLIB");
    char* use_custom_str = getenv("USE_CUSTOM");
    char* chacha20_enabled_str = getenv("CHACHA20_ENABLED");
    
    // default values if environment variables are not set
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;  // default to true
    int use_custom = use_custom_str ? atoi(use_custom_str) : 1;  // default to true
    int chacha20_enabled = chacha20_enabled_str ? atoi(chacha20_enabled_str) : 1;  // default to enabled
    
    // check if enabled in configuration
    if (!chacha20_enabled) {
        printf("ChaCha20 implementations disabled in configuration\n");
        return;
    }
    
    // register standard implementation if enabled
    if (use_stdlib) {
        strcpy(registry->implementations[index].name, "chacha20");
        registry->implementations[index].algo_type = ALGO_CHACHA20;
        registry->implementations[index].is_custom = 0;
        registry->implementations[index].key_size = 256; // uses 256-bit keys
        strcpy(registry->implementations[index].mode, "");
        registry->implementations[index].init = chacha_init;
        registry->implementations[index].cleanup = chacha_cleanup;
        registry->implementations[index].generate_key = chacha_generate_key;
        registry->implementations[index].encrypt = chacha_encrypt;
        registry->implementations[index].decrypt = chacha_decrypt;
        registry->implementations[index].encrypt_stream = chacha_encrypt_stream;
        registry->implementations[index].decrypt_stream = chacha_decrypt_stream;
        registry->count++;
    }
    
    // register custom implementation if enabled
    if (use_custom) {
        index = registry->count;
        strcpy(registry->implementations[index].name, "chacha20_custom");
        registry->implementations[index].algo_type = ALGO_CHACHA20;
        registry->implementations[index].is_custom = 1;
        registry->implementations[index].key_size = 256; // uses 256-bit keys
        strcpy(registry->implementations[index].mode, "");
        registry->implementations[index].init = chacha_custom_init;
        registry->implementations[index].cleanup = chacha_custom_cleanup;
        registry->implementations[index].generate_key = chacha_custom_generate_key;
        registry->implementations[index].encrypt = chacha_custom_encrypt;
        registry->implementations[index].decrypt = chacha_custom_decrypt;
        registry->implementations[index].encrypt_stream = chacha_custom_encrypt_stream;
        registry->implementations[index].decrypt_stream = chacha_custom_decrypt_stream;
        registry->count++;
    }
    
    printf("Registered %d ChaCha20 implementations\n", registry->count - implementations_before);
}

// standard library implementation functions (using OpenSSL)
void* chacha_init(void) {
    chacha_context_t* context = (chacha_context_t*)malloc(sizeof(chacha_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(chacha_context_t));
    context->is_custom = 0;
    context->key = NULL;
    context->key_length = 0;
    context->nonce = NULL;
    context->nonce_length = 0;
    context->counter = 0;
    context->openssl_ctx = NULL;
    
    return context;
}

void chacha_cleanup(void* context) {
    if (!context) return;
    
    chacha_context_t* chacha_context = (chacha_context_t*)context;
    
    if (chacha_context->key) {
        crypto_secure_free(chacha_context->key, chacha_context->key_length);
        chacha_context->key = NULL;
    }
    
    if (chacha_context->nonce) {
        crypto_secure_free(chacha_context->nonce, chacha_context->nonce_length);
        chacha_context->nonce = NULL;
    }
    
    if (chacha_context->openssl_ctx) {
        #ifdef USE_OPENSSL
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)chacha_context->openssl_ctx);
        #endif
        chacha_context->openssl_ctx = NULL;
    }
    
    free(chacha_context);
}

unsigned char* chacha_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    chacha_context_t* chacha_context = (chacha_context_t*)context;
    
    // uses 32-byte (256-bit) keys
    *key_length = 32;
    
    // allocate key memory using secure allocation
    unsigned char* key = (unsigned char*)crypto_secure_alloc(*key_length);
    if (!key) {
        fprintf(stderr, "Error: Could not allocate memory for key\n");
        return NULL;
    }
    
    // generate random key using cryptographically secure function
    if (!crypto_generate_key(key, *key_length)) {
        fprintf(stderr, "Error: Failed to generate key\n");
        crypto_secure_free(key, *key_length);
        return NULL;
    }
    
    // store key in context
    if (chacha_context->key) {
        crypto_secure_free(chacha_context->key, chacha_context->key_length);
    }
    
    chacha_context->key = (unsigned char*)crypto_secure_alloc(*key_length);
    if (chacha_context->key) {
        memcpy(chacha_context->key, key, *key_length);
        chacha_context->key_length = *key_length;
    }
    
    // generate 12-byte (96-bit) nonce using standard size
    chacha_context->nonce_length = crypto_get_standard_iv_size("ChaCha20", "");
    if (chacha_context->nonce) {
        crypto_secure_free(chacha_context->nonce, chacha_context->nonce_length);
    }
    
    chacha_context->nonce = (unsigned char*)crypto_secure_alloc(chacha_context->nonce_length);
    if (chacha_context->nonce) {
        if (!crypto_generate_nonce(chacha_context->nonce, chacha_context->nonce_length)) {
            fprintf(stderr, "Error: Failed to generate nonce\n");
            crypto_secure_free(chacha_context->key, chacha_context->key_length);
            crypto_secure_free(key, *key_length);
            chacha_context->key = NULL;
            return NULL;
        }
    }
    
    return key;
}

// standard encryption using OpenSSL
unsigned char* chacha_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    chacha_context_t* chacha_context = (chacha_context_t*)context;
    
    // if key is provided, use it instead of the context key
    if (key) {
        if (chacha_context->key) {
            crypto_secure_free(chacha_context->key, chacha_context->key_length);
        }
        
        // key is always 32 bytes
        chacha_context->key_length = 32;
        chacha_context->key = (unsigned char*)crypto_secure_alloc(chacha_context->key_length);
        if (!chacha_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for key\n");
            return NULL;
        }
        
        memcpy(chacha_context->key, key, chacha_context->key_length);
    }
    
    // check if key exists
    if (!chacha_context->key) {
        fprintf(stderr, "Error: key not set\n");
        return NULL;
    }
    
    // generate nonce if not present
    if (!chacha_context->nonce) {
        chacha_context->nonce_length = 12; // uses 12-byte nonce
        chacha_context->nonce = (unsigned char*)crypto_secure_alloc(chacha_context->nonce_length);
        if (!chacha_context->nonce) {
            fprintf(stderr, "Error: Could not allocate memory for nonce\n");
            return NULL;
        }
        
        // generate random nonce
        if (!crypto_generate_iv(chacha_context->nonce, chacha_context->nonce_length)) {
            fprintf(stderr, "Error: Could not generate nonce\n");
            return NULL;
        }
    }

#ifdef USE_OPENSSL
    // use OpenSSL implementation
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        return NULL;
    }
    
    // initialize cipher
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_context->key, chacha_context->nonce) != 1) {
        fprintf(stderr, "Error: Could not initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // calculate output size (nonce + ciphertext)
    size_t output_size = chacha_context->nonce_length + data_length;
    
    // allocate memory for output
    unsigned char* output = (unsigned char*)malloc(output_size);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for output\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // copy nonce to the beginning of output
    memcpy(output, chacha_context->nonce, chacha_context->nonce_length);
    
    // encrypt data
    int len;
    if (EVP_EncryptUpdate(ctx, output + chacha_context->nonce_length, &len, data, (int)data_length) != 1) {
        fprintf(stderr, "Error: Could not encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    int ciphertext_len = len;
    
    // finalize encryption
    if (EVP_EncryptFinal_ex(ctx, output + chacha_context->nonce_length + len, &len) != 1) {
        fprintf(stderr, "Error: Could not finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    ciphertext_len += len;
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // set the output length
    if (output_length) {
        *output_length = chacha_context->nonce_length + ciphertext_len;
    }
    
    return output;
#else
    // fallback to custom implementation if OpenSSL not available
    return chacha_custom_encrypt(context, data, data_length, key, output_length);
#endif
}

unsigned char* chacha_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 12) {
        fprintf(stderr, "Error: Invalid data for decryption\n");
        return NULL;
    }
    
    chacha_context_t* chacha_context = (chacha_context_t*)context;
    
    // extract nonce from the first 12 bytes of data
    if (chacha_context->nonce) {
        crypto_secure_free(chacha_context->nonce, chacha_context->nonce_length);
    }
    
    chacha_context->nonce_length = 12;
    chacha_context->nonce = (unsigned char*)crypto_secure_alloc(chacha_context->nonce_length);
    if (!chacha_context->nonce) {
        fprintf(stderr, "Error: Could not allocate memory for nonce\n");
        return NULL;
    }
    
    memcpy(chacha_context->nonce, data, chacha_context->nonce_length);
    
    // make sure we have a key
    unsigned char* active_key = NULL;
    if (key) {
        active_key = (unsigned char*)key;
    } else if (chacha_context->key) {
        active_key = chacha_context->key;
    } else {
        fprintf(stderr, "Error: No key available\n");
        return NULL;
    }

#ifdef USE_OPENSSL
    // use OpenSSL implementation
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        return NULL;
    }
    
    // initialize cipher
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, active_key, chacha_context->nonce) != 1) {
        fprintf(stderr, "Error: Could not initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // set output length (data without nonce)
    *output_length = data_length - chacha_context->nonce_length;
    unsigned char* output = (unsigned char*)malloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for output\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // decrypt data
    int len;
    if (EVP_DecryptUpdate(ctx, output, &len, data + chacha_context->nonce_length, (int)(*output_length)) != 1) {
        fprintf(stderr, "Error: Could not decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    int plaintext_len = len;
    
    // finalize decryption
    if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) {
        fprintf(stderr, "Error: Could not finalize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    plaintext_len += len;
    *output_length = plaintext_len;
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    return output;
#else
    // fallback to custom implementation if OpenSSL not available
    return chacha_custom_decrypt(context, data, data_length, key, output_length);
#endif
}

// stream processing functions (fixed variable types)
unsigned char* chacha_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // convert to size_t for internal processing
    size_t data_len = (size_t)data_length;
    size_t out_len = 0;
    unsigned char* result = chacha_encrypt(context, data, data_len, key, &out_len);
    if (output_length) *output_length = (int)out_len;
    return result;
}

unsigned char* chacha_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // convert to size_t for internal processing
    size_t data_len = (size_t)data_length;
    size_t out_len = 0;
    unsigned char* result = chacha_decrypt(context, data, data_len, key, &out_len);
    if (output_length) *output_length = (int)out_len;
    return result;
}

// custom implementation (pure from scratch)
void* chacha_custom_init(void) {
    chacha_context_t* context = (chacha_context_t*)malloc(sizeof(chacha_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(chacha_context_t));
    context->is_custom = 1;
    context->key = NULL;
    context->key_length = 0;
    context->nonce = NULL;
    context->nonce_length = 0;
    context->counter = 0;
    context->openssl_ctx = NULL;
    
    return context;
}

void chacha_custom_cleanup(void* context) {
    chacha_cleanup(context); // reuse standard cleanup
}

unsigned char* chacha_custom_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    chacha_context_t* chacha_context = (chacha_context_t*)context;
    
    // uses 32-byte (256-bit) keys
    *key_length = 32;
    
    // allocate key memory using secure allocation
    unsigned char* key = (unsigned char*)crypto_secure_alloc(*key_length);
    if (!key) {
        fprintf(stderr, "Error: Could not allocate memory for custom key\n");
        return NULL;
    }
    
    // generate base random key using cryptographically secure function
    if (!crypto_generate_key(key, *key_length)) {
        fprintf(stderr, "Error: Failed to generate base key\n");
        crypto_secure_free(key, *key_length);
        return NULL;
    }
    
    // custom key strengthening: apply key derivation with multiple rounds
    unsigned char strengthened_key[32];
    memcpy(strengthened_key, key, 32);
    
    // apply custom key strengthening (multiple rounds of transformation)
    for (int round = 0; round < 3; round++) {
        for (int i = 0; i < 32; i++) {
            // rotate and XOR with position-dependent values
            unsigned char rotated = (strengthened_key[i] << (round + 1)) | (strengthened_key[i] >> (7 - round));
            strengthened_key[i] = rotated ^ (unsigned char)(i * (round + 1) * 37);
        }
        
        // mix with previous bytes
        for (int i = 1; i < 32; i++) {
            strengthened_key[i] ^= strengthened_key[i - 1];
        }
    }
    
    // copy strengthened key back
    memcpy(key, strengthened_key, 32);
    
    // store key in context
    if (chacha_context->key) {
        crypto_secure_free(chacha_context->key, chacha_context->key_length);
    }
    
    chacha_context->key = (unsigned char*)crypto_secure_alloc(*key_length);
    if (chacha_context->key) {
        memcpy(chacha_context->key, key, *key_length);
        chacha_context->key_length = *key_length;
    }
    
    // generate custom nonce with different pattern
    chacha_context->nonce_length = crypto_get_standard_iv_size("ChaCha20", "");
    if (chacha_context->nonce) {
        crypto_secure_free(chacha_context->nonce, chacha_context->nonce_length);
    }
    
    chacha_context->nonce = (unsigned char*)crypto_secure_alloc(chacha_context->nonce_length);
    if (chacha_context->nonce) {
        // generate base nonce
        if (!crypto_generate_nonce(chacha_context->nonce, chacha_context->nonce_length)) {
            fprintf(stderr, "Error: Failed to generate custom nonce\n");
            crypto_secure_free(chacha_context->key, chacha_context->key_length);
            crypto_secure_free(key, *key_length);
            chacha_context->key = NULL;
            return NULL;
        }
        
        // apply custom nonce transformation
        for (int i = 0; i < chacha_context->nonce_length; i++) {
            chacha_context->nonce[i] ^= strengthened_key[i % 32];
        }
    }
    
    return key;
}

// custom encryption using our own implementation
unsigned char* chacha_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    chacha_context_t* chacha_context = (chacha_context_t*)context;
    
    // if key is provided, use it instead of the context key
    if (key) {
        if (chacha_context->key) {
            crypto_secure_free(chacha_context->key, chacha_context->key_length);
        }
        
        // key is always 32 bytes
        chacha_context->key_length = 32;
        chacha_context->key = (unsigned char*)crypto_secure_alloc(chacha_context->key_length);
        if (!chacha_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for key\n");
            return NULL;
        }
        
        memcpy(chacha_context->key, key, chacha_context->key_length);
    }
    
    // check if key exists
    if (!chacha_context->key) {
        fprintf(stderr, "Error: key not set\n");
        return NULL;
    }
    
    // generate nonce if not present
    if (!chacha_context->nonce) {
        chacha_context->nonce_length = 12; // uses 12-byte nonce
        chacha_context->nonce = (unsigned char*)crypto_secure_alloc(chacha_context->nonce_length);
        if (!chacha_context->nonce) {
            fprintf(stderr, "Error: Could not allocate memory for nonce\n");
            return NULL;
        }
        
        // generate random nonce
        if (!crypto_generate_iv(chacha_context->nonce, chacha_context->nonce_length)) {
            fprintf(stderr, "Error: Could not generate nonce\n");
            return NULL;
        }
    }
    
    // calculate output size (nonce + ciphertext)
    size_t output_size = chacha_context->nonce_length + data_length;
    
    // allocate memory for output
    unsigned char* output = (unsigned char*)malloc(output_size);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for output\n");
        return NULL;
    }
    
    // copy nonce to the beginning of output
    memcpy(output, chacha_context->nonce, chacha_context->nonce_length);
    
    // custom encryption with enhanced security features
    uint32_t state[16];
    
    // custom constants (modified for custom implementation)
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // apply custom key derivation before loading into state
    unsigned char derived_key[32];
    for (int i = 0; i < 32; i++) {
        // custom key derivation: XOR with nonce and apply rotation
        unsigned char nonce_byte = chacha_context->nonce[i % chacha_context->nonce_length];
        derived_key[i] = chacha_context->key[i] ^ nonce_byte;
        derived_key[i] = (derived_key[i] << (i % 8)) | (derived_key[i] >> (8 - (i % 8)));
    }
    
    // key (32 bytes = 8 uint32_t) using derived key
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32_le(derived_key + i * 4);
    }
    
    // counter (starts at 0x1000 for custom implementation - different from standard)
    state[12] = 0x1000;
    
    // nonce (12 bytes = 3 uint32_t) with custom modification
    for (int i = 0; i < 3; i++) {
        uint32_t nonce_word = load32_le(chacha_context->nonce + i * 4);
        // apply custom nonce transformation
        nonce_word ^= (uint32_t)(i * 0x12345678);
        state[13 + i] = nonce_word;
    }
    
    // encrypt data in 64-byte blocks
    size_t offset = 0;
    while (offset < data_length) {
        uint32_t keystream[16];
        chacha20_block(keystream, state);
        
        // convert keystream to bytes and XOR with plaintext
        unsigned char keystream_bytes[64];
        for (int i = 0; i < 16; i++) {
            store32_le(keystream_bytes + i * 4, keystream[i]);
        }
        
        size_t block_size = (data_length - offset) < 64 ? (data_length - offset) : 64;
        for (size_t i = 0; i < block_size; i++) {
            output[chacha_context->nonce_length + offset + i] = data[offset + i] ^ keystream_bytes[i];
        }
        
        offset += block_size;
        state[12]++; // increment counter
    }
    
    // set the output length
    if (output_length) {
        *output_length = output_size;
    }
    
    return output;
}

unsigned char* chacha_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 12) {
        fprintf(stderr, "Error: Invalid data for decryption\n");
        return NULL;
    }
    
    chacha_context_t* chacha_context = (chacha_context_t*)context;
    
    // extract nonce from the first 12 bytes of data
    if (chacha_context->nonce) {
        crypto_secure_free(chacha_context->nonce, chacha_context->nonce_length);
    }
    
    chacha_context->nonce_length = 12;
    chacha_context->nonce = (unsigned char*)crypto_secure_alloc(chacha_context->nonce_length);
    if (!chacha_context->nonce) {
        fprintf(stderr, "Error: Could not allocate memory for nonce\n");
        return NULL;
    }
    
    memcpy(chacha_context->nonce, data, chacha_context->nonce_length);
    
    // make sure we have a key
    unsigned char* active_key = NULL;
    if (key) {
        active_key = (unsigned char*)key;
    } else if (chacha_context->key) {
        active_key = chacha_context->key;
    } else {
        fprintf(stderr, "Error: No key available\n");
        return NULL;
    }
    
    // set output length (data without nonce)
    *output_length = data_length - chacha_context->nonce_length;
    unsigned char* output = (unsigned char*)malloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for output\n");
        return NULL;
    }
    
    // custom decryption with enhanced security features (same as encryption in stream cipher)
    uint32_t state[16];
    
    // custom constants (modified for custom implementation)
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // apply custom key derivation before loading into state
    unsigned char derived_key[32];
    for (int i = 0; i < 32; i++) {
        // custom key derivation: XOR with nonce and apply rotation
        unsigned char nonce_byte = chacha_context->nonce[i % chacha_context->nonce_length];
        derived_key[i] = active_key[i] ^ nonce_byte;
        derived_key[i] = (derived_key[i] << (i % 8)) | (derived_key[i] >> (8 - (i % 8)));
    }
    
    // key (32 bytes = 8 uint32_t) using derived key
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32_le(derived_key + i * 4);
    }
    
    // counter (starts at 0x1000 for custom implementation - different from standard)
    state[12] = 0x1000;
    
    // nonce (12 bytes = 3 uint32_t) with custom modification
    for (int i = 0; i < 3; i++) {
        uint32_t nonce_word = load32_le(chacha_context->nonce + i * 4);
        // apply custom nonce transformation
        nonce_word ^= (uint32_t)(i * 0x12345678);
        state[13 + i] = nonce_word;
    }
    
    // decrypt data in 64-byte blocks
    size_t offset = 0;
    const unsigned char* ciphertext = data + chacha_context->nonce_length;
    
    while (offset < *output_length) {
        uint32_t keystream[16];
        chacha20_block(keystream, state);
        
        // convert keystream to bytes and XOR with ciphertext
        unsigned char keystream_bytes[64];
        for (int i = 0; i < 16; i++) {
            store32_le(keystream_bytes + i * 4, keystream[i]);
        }
        
        size_t block_size = (*output_length - offset) < 64 ? (*output_length - offset) : 64;
        for (size_t i = 0; i < block_size; i++) {
            output[offset + i] = ciphertext[offset + i] ^ keystream_bytes[i];
        }
        
        offset += block_size;
        state[12]++; // increment counter
    }
    
    return output;
}

// custom stream processing functions (fixed variable types)
unsigned char* chacha_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // convert to size_t for internal processing
    size_t data_len = (size_t)data_length;
    size_t out_len = 0;
    unsigned char* result = chacha_custom_encrypt(context, data, data_len, key, &out_len);
    if (output_length) *output_length = (int)out_len;
    return result;
}

unsigned char* chacha_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // convert to size_t for internal processing
    size_t data_len = (size_t)data_length;
    size_t out_len = 0;
    unsigned char* result = chacha_custom_decrypt(context, data, data_len, key, &out_len);
    if (output_length) *output_length = (int)out_len;
    return result;
}

 