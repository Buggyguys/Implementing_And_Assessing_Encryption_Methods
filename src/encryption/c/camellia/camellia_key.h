#ifndef CAMELLIA_KEY_H
#define CAMELLIA_KEY_H

#include "implementation.h"

// key generation functions
unsigned char* camellia_generate_key(void* context, int* key_length);
unsigned char* camellia_custom_generate_key(void* context, int* key_length);

#ifdef USE_OPENSSL
unsigned char* camellia_openssl_generate_key(void* context, int* key_length);
#endif

// Note: Key size specific functions are handled internally by the main generate_key function

#endif /* CAMELLIA_KEY_H */ 