#ifndef ECC_KEY_H
#define ECC_KEY_H

#include "ecc_common.h"

// Key generation functions
unsigned char* ecc_generate_key(void* context, int* key_length);
unsigned char* ecc_custom_generate_key(void* context, int* key_length);

// ECDH shared secret computation
int ecc_compute_shared_secret(ecc_context_t* context, const unsigned char* peer_public_key, int peer_public_key_length, unsigned char** shared_secret);

// Functions for ECDSA (digital signatures)
unsigned char* ecc_sign_data(ecc_context_t* context, const unsigned char* data, int data_length, int* signature_length);
int ecc_verify_signature(ecc_context_t* context, const unsigned char* data, int data_length, const unsigned char* signature, int signature_length);

#endif // ECC_KEY_H 