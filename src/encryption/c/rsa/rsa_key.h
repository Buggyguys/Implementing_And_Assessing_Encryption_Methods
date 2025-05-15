#ifndef RSA_KEY_H
#define RSA_KEY_H

#include "implementation.h"

// Key generation functions
unsigned char* rsa_generate_key(void* context, int* key_length);
unsigned char* rsa_custom_generate_key(void* context, int* key_length);

// Key management functions
RSA* rsa_generate_new_key(int key_size);
void rsa_free_key(rsa_key_t* key);
rsa_key_t* rsa_create_key_from_rsa(RSA* rsa_key);
int rsa_set_key_size(rsa_context_t* context, int key_size);
int rsa_set_padding(rsa_context_t* context, rsa_padding_type_t padding_type);
int rsa_set_key_reuse(rsa_context_t* context, int key_reuse, int key_count);

// Key selection functions for key reuse
RSA* rsa_get_current_key(rsa_context_t* context);
rsa_key_t* rsa_get_current_key_struct(rsa_context_t* context);
int rsa_move_to_next_key(rsa_context_t* context);

// Key serialization functions
unsigned char* rsa_export_public_key(RSA* key, int* length);
unsigned char* rsa_export_private_key(RSA* key, int* length);
RSA* rsa_import_public_key(const unsigned char* data, int length);
RSA* rsa_import_private_key(const unsigned char* data, int length);

#endif /* RSA_KEY_H */ 