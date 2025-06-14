#ifndef CAMELLIA_CFB_H
#define CAMELLIA_CFB_H

#include "camellia_common.h"

// Function declarations for Camellia-CFB mode
unsigned char* camellia_cfb_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_cfb_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_cfb_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_cfb_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif 