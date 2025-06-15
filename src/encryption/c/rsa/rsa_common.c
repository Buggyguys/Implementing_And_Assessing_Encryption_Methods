#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "implementation.h"
#include "rsa_common.h"

#ifdef USE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

// calculate maximum data size that can be encrypted in one rsa block
int rsa_get_max_data_size(rsa_context_t* context) {
    if (!context) return 0;
    
#ifdef USE_OPENSSL
    if (!context->rsa_keypair) {
        return 0;
    }
    
    int rsa_size = RSA_size(context->rsa_keypair);
    
    // maximum data size depends on padding mode
    if (context->padding_type == PADDING_OAEP) {
        // for oaep: key_size - 2 * hash_size - 2 (using sha-1, 20 bytes)
        return rsa_size - 2 * 20 - 2;
    } else {
        // for pkcs#1 v1.5: key_size - 11
        return rsa_size - 11;
    }
#else
    // for custom implementation, use the calculated values
    return context->max_chunk_size;
#endif
}

// encrypt a block of data with rsa
int rsa_encrypt_block(rsa_context_t* context, const unsigned char* data, int data_length, unsigned char* output, RSA* key) {
    if (!context || !data || data_length <= 0 || !output) {
        return -1;
    }
    
#ifdef USE_OPENSSL
    if (!key) return -1;
    
    // get maximum data size for this key and padding
    int max_size = rsa_get_max_data_size(context);
    if (data_length > max_size) {
        fprintf(stderr, "Warning: Data size %d exceeds maximum for RSA encryption (%d)\n", 
                data_length, max_size);
        data_length = max_size;
    }
    
    // choose padding based on context
    int padding = (context->padding_type == PADDING_OAEP) ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
    
    // encrypt the data
    int result = RSA_public_encrypt(data_length, data, output, key, padding);
    if (result < 0) {
        fprintf(stderr, "Error: RSA encryption failed\n");
        char* err_string = ERR_error_string(ERR_get_error(), NULL);
        if (err_string) {
            fprintf(stderr, "OpenSSL error: %s\n", err_string);
        }
        return -1;
    }
    
    return result;
#else
    return -1; // openssl required
#endif
}

// decrypt a block of data with rsa
int rsa_decrypt_block(rsa_context_t* context, const unsigned char* data, int data_length, unsigned char* output, RSA* key) {
    if (!context || !data || data_length <= 0 || !output) {
        return -1;
    }
    
#ifdef USE_OPENSSL
    if (!key) return -1;
    
    // choose padding based on context
    int padding = (context->padding_type == PADDING_OAEP) ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
    
    // decrypt the data
    int result = RSA_private_decrypt(data_length, data, output, key, padding);
    if (result < 0) {
        // don't print error here, as we might be trying multiple keys
        return -1;
    }
    
    return result;
#else
    return -1; // openssl required
#endif
} 