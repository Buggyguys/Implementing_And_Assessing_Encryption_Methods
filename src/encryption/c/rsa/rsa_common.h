#ifndef RSA_COMMON_H
#define RSA_COMMON_H

#include "implementation.h"

// Common RSA initialization and cleanup functions
void* rsa_init(void);
void rsa_cleanup(void* context);
void* rsa_custom_init(void);
void rsa_custom_cleanup(void* context);

// High-level encryption/decryption functions
unsigned char* rsa_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* rsa_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* rsa_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* rsa_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);

// Stream processing functions
unsigned char* rsa_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* rsa_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* rsa_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* rsa_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Utility functions for internal use
int rsa_get_max_data_size(rsa_context_t* context);
int rsa_encrypt_block(rsa_context_t* context, const unsigned char* data, int data_length, unsigned char* output, RSA* key);
int rsa_decrypt_block(rsa_context_t* context, const unsigned char* data, int data_length, unsigned char* output, RSA* key);

#endif /* RSA_COMMON_H */ 