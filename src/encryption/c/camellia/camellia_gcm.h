#ifndef CAMELLIA_GCM_H
#define CAMELLIA_GCM_H

#include "implementation.h"

// Camellia-GCM encryption and decryption functions
unsigned char* camellia_gcm_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_gcm_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Custom Camellia-GCM encryption and decryption functions
unsigned char* camellia_gcm_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_gcm_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif /* CAMELLIA_GCM_H */ 