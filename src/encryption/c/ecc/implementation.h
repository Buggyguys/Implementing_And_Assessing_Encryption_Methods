#ifndef ECC_IMPLEMENTATION_H
#define ECC_IMPLEMENTATION_H

#include "../c_core.h"

// Standard implementation functions
void* ecc_init(void);
void ecc_cleanup(void* context);
unsigned char* ecc_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* ecc_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* ecc_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* ecc_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Custom implementation functions
void* ecc_custom_init(void);
void ecc_custom_cleanup(void* context);
unsigned char* ecc_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* ecc_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length);
unsigned char* ecc_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* ecc_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Register ECC implementations in the registry
void register_ecc_implementations(implementation_registry_t* registry);

#endif /* ECC_IMPLEMENTATION_H */ 