#ifndef CAMELLIA_CFB_H
#define CAMELLIA_CFB_H

#include "implementation.h"

// encryption and decryption functions
unsigned char* camellia_cfb_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* camellia_cfb_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// custom functions
unsigned char* camellia_cfb_custom_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* camellia_cfb_custom_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

#endif /* CAMELLIA_CFB_H */ 