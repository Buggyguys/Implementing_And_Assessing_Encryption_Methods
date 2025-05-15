#ifndef CAMELLIA_CTR_H
#define CAMELLIA_CTR_H

#include "implementation.h"

// Camellia-CTR encryption and decryption functions
unsigned char* camellia_ctr_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ctr_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Custom Camellia-CTR encryption and decryption functions
unsigned char* camellia_ctr_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ctr_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// OpenSSL Camellia-CTR encryption and decryption functions (when available)
#ifdef USE_OPENSSL
unsigned char* camellia_ctr_openssl_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_ctr_openssl_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
#endif

#endif /* CAMELLIA_CTR_H */ 