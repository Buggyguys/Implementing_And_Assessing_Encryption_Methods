#ifndef AES_KEY_H
#define AES_KEY_H

#include "implementation.h"

// key generation functions
unsigned char* aes_generate_key(void* context, int* key_length);
unsigned char* aes_custom_generate_key(void* context, int* key_length);

#endif 