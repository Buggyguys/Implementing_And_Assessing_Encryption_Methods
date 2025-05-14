#ifndef AES_COMMON_H
#define AES_COMMON_H

#include "implementation.h"
#include "aes_key.h"
#include "aes_cbc.h"
#include "aes_ctr.h"
#include "aes_gcm.h"
#include "aes_ecb.h"

// Common AES initialization and cleanup functions
void* aes_init(void);
void aes_cleanup(void* context);
void* aes_custom_init(void);
void aes_custom_cleanup(void* context);

// High-level encryption/decryption function that delegates to specific mode implementations
unsigned char* aes_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* aes_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* aes_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* aes_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);

// Stream processing functions
unsigned char* aes_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* aes_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

#endif /* AES_COMMON_H */ 