#ifndef AES_GCM_H
#define AES_GCM_H

#include "implementation.h"

// AES-GCM implementation functions
unsigned char* aes_gcm_encrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* aes_gcm_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

// Custom AES-GCM implementation
unsigned char* aes_gcm_custom_encrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);
unsigned char* aes_gcm_custom_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length);

#endif /* AES_GCM_H */ 