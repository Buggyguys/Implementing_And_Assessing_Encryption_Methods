#ifndef AES_ECB_H
#define AES_ECB_H

#include "implementation.h"

// AES-ECB implementation functions
unsigned char* aes_ecb_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_ecb_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Custom AES-ECB implementation
unsigned char* aes_ecb_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_ecb_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif /* AES_ECB_H */ 