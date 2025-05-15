#ifndef CAMELLIA_CBC_H
#define CAMELLIA_CBC_H

#include "implementation.h"

// Camellia-CBC encryption and decryption functions
unsigned char* camellia_cbc_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_cbc_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Custom Camellia-CBC encryption and decryption functions
unsigned char* camellia_cbc_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_cbc_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);

// OpenSSL Camellia-CBC encryption and decryption functions (when available)
#ifdef USE_OPENSSL
unsigned char* camellia_cbc_openssl_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* camellia_cbc_openssl_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length);
#endif

#endif /* CAMELLIA_CBC_H */ 