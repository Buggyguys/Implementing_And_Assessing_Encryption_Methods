#ifndef CAMELLIA_OFB_H
#define CAMELLIA_OFB_H

#include "camellia_common.h"

// Function declarations for Camellia-OFB mode
unsigned char* camellia_ofb_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ofb_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ofb_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ofb_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif 