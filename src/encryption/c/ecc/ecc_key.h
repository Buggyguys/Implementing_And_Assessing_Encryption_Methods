#ifndef ECC_KEY_H
#define ECC_KEY_H

#include "ecc_common.h"

// Key generation functions
unsigned char* ecc_generate_key(void* context, int* key_length);
unsigned char* ecc_custom_generate_key(void* context, int* key_length);

#endif // ECC_KEY_H 