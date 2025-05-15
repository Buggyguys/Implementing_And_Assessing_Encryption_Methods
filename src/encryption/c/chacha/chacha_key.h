#ifndef CHACHA_KEY_H
#define CHACHA_KEY_H

#include "implementation.h"

// Key generation functions
unsigned char* chacha_generate_key(void* context, int* key_length);
unsigned char* chacha_custom_generate_key(void* context, int* key_length);

// Standard library implementation (when available)
#ifdef USE_OPENSSL
unsigned char* chacha_openssl_generate_key(void* context, int* key_length);
#endif

#endif /* CHACHA_KEY_H */ 