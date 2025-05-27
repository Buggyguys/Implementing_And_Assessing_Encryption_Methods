#ifndef AES_KEY_H
#define AES_KEY_H

#include "implementation.h"

// Key generation functions
unsigned char* aes_generate_key(void* context, int* key_length);
unsigned char* aes_custom_generate_key(void* context, int* key_length);

// Note: Key size specific functions are handled internally by the main generate_key function

#endif /* AES_KEY_H */ 