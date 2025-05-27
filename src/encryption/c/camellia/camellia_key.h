#ifndef CAMELLIA_KEY_H
#define CAMELLIA_KEY_H

#include "implementation.h"

// Key generation functions
unsigned char* camellia_generate_key(void* context, int* key_length);
unsigned char* camellia_custom_generate_key(void* context, int* key_length);

// Note: Key size specific functions are handled internally by the main generate_key function

#endif /* CAMELLIA_KEY_H */ 