#ifndef CHACHA_COMMON_H
#define CHACHA_COMMON_H

#include "implementation.h"

// Common ChaCha20 initialization and cleanup functions
void* chacha_init(void);
void chacha_cleanup(void* context);
void* chacha_custom_init(void);
void chacha_custom_cleanup(void* context);

// High-level encryption/decryption functions
unsigned char* chacha_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* chacha_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* chacha_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* chacha_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);

// Stream processing functions
unsigned char* chacha_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* chacha_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* chacha_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* chacha_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

#endif /* CHACHA_COMMON_H */ 