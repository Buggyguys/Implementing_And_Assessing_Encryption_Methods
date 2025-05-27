#ifndef CHACHA_KEY_H
#define CHACHA_KEY_H

#include "implementation.h"

// Key generation functions
unsigned char* chacha_generate_key(void* context, int* key_length);
unsigned char* chacha_custom_generate_key(void* context, int* key_length);

// Note: ChaCha20 key generation is handled by the main generate_key function

#endif /* CHACHA_KEY_H */ 