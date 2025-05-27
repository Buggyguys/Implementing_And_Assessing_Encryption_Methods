#ifndef CAMELLIA_ECB_H
#define CAMELLIA_ECB_H

#include "implementation.h"

// Camellia-ECB encryption and decryption functions
unsigned char* camellia_ecb_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ecb_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Custom Camellia-ECB encryption and decryption functions
unsigned char* camellia_ecb_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ecb_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif /* CAMELLIA_ECB_H */ 