#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "implementation.h"
#include "rsa_common.h"

// Calculate the maximum data size that can be encrypted in one RSA block
int rsa_get_max_data_size(rsa_context_t* context) {
    if (!context) return 0;
    
    RSA* rsa_key = context->rsa;
    if (!rsa_key) {
        return 0;
    }
    
    int rsa_size = RSA_size(rsa_key);
    
    // For RSA encryption, the maximum data size depends on the padding mode
    if (context->padding_type == PADDING_OAEP) {
        // For OAEP, the maximum is key size - 2 * hash size - 2
        // Using SHA-1 as the hash (20 bytes)
        return rsa_size - 2 * 20 - 2;
    } else {
        // For PKCS#1 v1.5, the maximum is key size - 11
        return rsa_size - 11;
    }
}



// Encrypt a block of data with RSA
int rsa_encrypt_block(rsa_context_t* context, const unsigned char* data, int data_length, unsigned char* output, RSA* key) {
    if (!context || !data || data_length <= 0 || !output || !key) {
        return -1;
    }
    
    // Get the maximum data size for this key and padding
    int max_size = rsa_get_max_data_size(context);
    if (data_length > max_size) {
        fprintf(stderr, "Warning: Data size %d exceeds maximum for RSA encryption (%d)\n", 
                data_length, max_size);
        data_length = max_size;
    }
    
    // Choose padding based on context
    int padding;
    if (context->padding_type == PADDING_OAEP) {
        padding = RSA_PKCS1_OAEP_PADDING;
    } else {
        padding = RSA_PKCS1_PADDING;
    }
    
    // Encrypt the data
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
}

// Decrypt a block of data with RSA
int rsa_decrypt_block(rsa_context_t* context, const unsigned char* data, int data_length, unsigned char* output, RSA* key) {
    if (!context || !data || data_length <= 0 || !output || !key) {
        return -1;
    }
    
    // Choose padding based on context
    int padding;
    if (context->padding_type == PADDING_OAEP) {
        padding = RSA_PKCS1_OAEP_PADDING;
    } else {
        padding = RSA_PKCS1_PADDING;
    }
    
    // Decrypt the data
    int result = RSA_private_decrypt(data_length, data, output, key, padding);
    if (result < 0) {
        // Don't print an error here, as we might be trying multiple keys in key reuse mode
        return -1;
    }
    
    return result;
} 