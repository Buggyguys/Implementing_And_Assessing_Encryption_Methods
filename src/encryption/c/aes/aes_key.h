#ifndef AES_KEY_H
#define AES_KEY_H

#include "implementation.h"

// Key generation functions
unsigned char* aes_generate_key(void* context, int* key_length);
unsigned char* aes_custom_generate_key(void* context, int* key_length);

// Standard library implementations (when available)
#ifdef USE_OPENSSL
unsigned char* aes_openssl_generate_key(void* context, int* key_length);
unsigned char* aes_openssl_generate_key_128(void* context, int* key_length);
unsigned char* aes_openssl_generate_key_192(void* context, int* key_length);
unsigned char* aes_openssl_generate_key_256(void* context, int* key_length);
#endif

// Key size specific functions
unsigned char* aes_generate_key_128(void* context, int* key_length);
unsigned char* aes_generate_key_192(void* context, int* key_length);
unsigned char* aes_generate_key_256(void* context, int* key_length);

// Custom key size specific functions
unsigned char* aes_custom_generate_key_128(void* context, int* key_length);
unsigned char* aes_custom_generate_key_192(void* context, int* key_length);
unsigned char* aes_custom_generate_key_256(void* context, int* key_length);

#endif /* AES_KEY_H */ 