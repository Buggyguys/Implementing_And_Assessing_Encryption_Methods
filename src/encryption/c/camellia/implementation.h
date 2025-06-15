#ifndef CAMELLIA_IMPLEMENTATION_H
#define CAMELLIA_IMPLEMENTATION_H

#include "../c_core.h"
#include <stdint.h>
#include <stddef.h>

// context structure
typedef struct {
    unsigned char* key;
    int key_length;
    int key_size;  // in bits (128, 192, 256)
    unsigned char* iv;
    int iv_length;
    char mode[16];  // ECB, CBC, CFB, OFB, etc.
    int is_custom;  // 0 for standard, 1 for custom
} camellia_context_t;

// main implementation functions
void* camellia_init(void);
void* camellia_custom_init(void);
void camellia_cleanup(void* context);
void camellia_custom_cleanup(void* context);

unsigned char* camellia_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* camellia_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

unsigned char* camellia_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* camellia_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// key generation
unsigned char* camellia_generate_key(void* context, int* key_length);
unsigned char* camellia_custom_generate_key(void* context, int* key_length);

// stream functions
unsigned char* camellia_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* camellia_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// internal block cipher functions
void camellia_key_schedule_128(const uint8_t* key, uint64_t subkeys[26]);
void camellia_encrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]);
void camellia_decrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]);

// mode-specific implementations
// cbc
unsigned char* camellia_cbc_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* camellia_cbc_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// cfb
unsigned char* camellia_cfb_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* camellia_cfb_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// ofb
unsigned char* camellia_ofb_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* camellia_ofb_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// ecb
unsigned char* camellia_ecb_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* camellia_ecb_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

#endif /* CAMELLIA_IMPLEMENTATION_H */ 