#ifndef AES_CFB_H
#define AES_CFB_H

#include "aes_common.h"

// Function declarations for AES-CFB mode

// Standard library-based implementations
unsigned char* aes_cfb_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_cfb_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// Custom implementations
unsigned char* aes_cfb_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_cfb_custom_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// OpenSSL-based implementations  
unsigned char* aes_cfb_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_cfb_openssl_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

#endif 