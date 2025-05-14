#ifndef AES_CTR_H
#define AES_CTR_H

#include "implementation.h"

// AES-CTR implementation functions
unsigned char* aes_ctr_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_ctr_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);

// Custom AES-CTR implementation
unsigned char* aes_ctr_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);
unsigned char* aes_ctr_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length);

#endif /* AES_CTR_H */ 