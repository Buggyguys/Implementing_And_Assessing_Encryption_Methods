#ifndef AES_CBC_H
#define AES_CBC_H

#include "implementation.h"

// AES-CBC implementation functions
unsigned char* aes_cbc_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_cbc_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Custom AES-CBC implementation
unsigned char* aes_cbc_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_cbc_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif /* AES_CBC_H */ 