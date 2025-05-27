#ifndef RSA_KEY_H
#define RSA_KEY_H

#include "implementation.h"

// Key generation functions
unsigned char* rsa_generate_key(void* context, int* key_length);
unsigned char* rsa_custom_generate_key(void* context, int* key_length);

// Key management functions
RSA* rsa_generate_new_key(int key_size);
int rsa_set_key_size(rsa_context_t* context, int key_size);
int rsa_set_padding(rsa_context_t* context, rsa_padding_type_t padding_type);

// Key serialization functions
unsigned char* rsa_export_public_key(RSA* key, int* length);
unsigned char* rsa_export_private_key(RSA* key, int* length);
RSA* rsa_import_public_key(const unsigned char* data, int length);
RSA* rsa_import_private_key(const unsigned char* data, int length);

#endif /* RSA_KEY_H */ 