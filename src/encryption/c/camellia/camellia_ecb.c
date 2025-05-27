#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "camellia_common.h"
#include "camellia_ecb.h"

#define AUTH_TAG_SIZE 16 // 16 bytes (128 bits) for authentication tag

// Camellia-ECB encryption function with authentication
unsigned char* camellia_ecb_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Calculate the output length (data + tag)
    // In ECB mode, we need to pad the data to a multiple of the block size
    int block_size = CAMELLIA_BLOCK_SIZE;
    int padded_length = ((data_length + block_size - 1) / block_size) * block_size;
    *output_length = padded_length + tag_size;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB encryption output\n");
        return NULL;
    }
    
    // Structure of output: Ciphertext + Tag
    
    // For this placeholder, we'll just XOR the data with the key as a simple "encryption"
    // In a real implementation, you would use the Camellia cipher in ECB mode
    for (int i = 0; i < data_length; i++) {
        output[i] = data[i] ^ context->key[i % context->key_length];
    }
    
    // Pad the remaining bytes (if any)
    for (int i = data_length; i < padded_length; i++) {
        unsigned char padding_byte = padded_length - data_length;
        output[i] = padding_byte ^ context->key[i % context->key_length];
    }
    
    // Generate authentication tag for the encrypted data
    unsigned char* ciphertext = output;
    unsigned char* tag = output + padded_length;
    
    if (!crypto_generate_authentication_tag(tag, tag_size, ciphertext, padded_length, 
                                           context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, *output_length);
        return NULL;
    }
    
    return output;
}

// Camellia-ECB decryption function with authentication verification
unsigned char* camellia_ecb_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Check if the data is large enough to contain at least one block plus tag
    if (data_length < CAMELLIA_BLOCK_SIZE + tag_size) {
        fprintf(stderr, "Error: Invalid Camellia-ECB ciphertext length\n");
        return NULL;
    }
    
    // Calculate the ciphertext length (excluding tag)
    int ciphertext_length = data_length - tag_size;
    
    // Check if the ciphertext length is a multiple of the block size
    if (ciphertext_length % CAMELLIA_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Invalid Camellia-ECB ciphertext length (not a multiple of block size)\n");
        return NULL;
    }
    
    // Extract ciphertext and tag
    const unsigned char* ciphertext = data;
    const unsigned char* tag = data + ciphertext_length;
    
    // Verify the authentication tag first
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, ciphertext_length, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(ciphertext_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB decryption output\n");
        return NULL;
    }
    
    // For this placeholder, we'll just XOR the data with the key as a simple "decryption"
    // In a real implementation, you would use the Camellia cipher in ECB mode
    for (int i = 0; i < ciphertext_length; i++) {
        plaintext[i] = ciphertext[i] ^ context->key[i % context->key_length];
    }
    
    // Check for and remove padding
    unsigned char padding_byte = plaintext[ciphertext_length - 1];
    if (padding_byte > 0 && padding_byte <= CAMELLIA_BLOCK_SIZE) {
        // Verify padding
        int valid_padding = 1;
        for (int i = ciphertext_length - padding_byte; i < ciphertext_length; i++) {
            if (plaintext[i] != padding_byte) {
                valid_padding = 0;
                break;
            }
        }
        
        if (valid_padding) {
            ciphertext_length -= padding_byte;
        }
    }
    
    *output_length = ciphertext_length;
    
    return plaintext;
}

// Custom Camellia-ECB encryption function
unsigned char* camellia_ecb_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    // For now, the custom implementation just calls the standard one
    return camellia_ecb_encrypt(context, data, data_length, output_length);
}

// Custom Camellia-ECB decryption function
unsigned char* camellia_ecb_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    // For now, the custom implementation just calls the standard one
    return camellia_ecb_decrypt(context, data, data_length, output_length);
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL Camellia-ECB encryption function
unsigned char* camellia_ecb_openssl_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char *ciphertext;
    
    // Calculate the output length (data + padding)
    int block_size = CAMELLIA_BLOCK_SIZE;
    int padded_length = ((data_length + block_size - 1) / block_size) * block_size;
    *output_length = padded_length;
    
    // Allocate memory for the output
    ciphertext = (unsigned char*)malloc(*output_length);
    if (!ciphertext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB encryption output\n");
        return NULL;
    }
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(ciphertext);
        return NULL;
    }
    
    // Initialize the encryption operation
    const EVP_CIPHER *cipher = NULL;
    switch(context->key_size) {
        case 128:
            cipher = EVP_camellia_128_ecb();
            break;
        case 192:
            cipher = EVP_camellia_192_ecb();
            break;
        case 256:
            cipher = EVP_camellia_256_ecb();
            break;
        default:
            fprintf(stderr, "Error: Invalid Camellia key size %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(ciphertext);
            return NULL;
    }
    
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, NULL)) {
        fprintf(stderr, "Error: Could not initialize OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    
    // Provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len = len;
    
    // Finalize the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Update the output length
    *output_length = ciphertext_len;
    
    return ciphertext;
}

// OpenSSL Camellia-ECB decryption function
unsigned char* camellia_ecb_openssl_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char *plaintext;
    
    // Check if the data length is a multiple of the block size
    if (data_length % CAMELLIA_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Invalid Camellia-ECB ciphertext length\n");
        return NULL;
    }
    
    // Allocate memory for the plaintext
    plaintext = (unsigned char*)malloc(data_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB decryption output\n");
        return NULL;
    }
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(plaintext);
        return NULL;
    }
    
    // Initialize the decryption operation
    const EVP_CIPHER *cipher = NULL;
    switch(context->key_size) {
        case 128:
            cipher = EVP_camellia_128_ecb();
            break;
        case 192:
            cipher = EVP_camellia_192_ecb();
            break;
        case 256:
            cipher = EVP_camellia_256_ecb();
            break;
        default:
            fprintf(stderr, "Error: Invalid Camellia key size %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            return NULL;
    }
    
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, NULL)) {
        fprintf(stderr, "Error: Could not initialize OpenSSL decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    
    // Provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    plaintext_len = len;
    
    // Finalize the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL decryption (padding error)\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    plaintext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Update the output length
    *output_length = plaintext_len;
    
    return plaintext;
}
#endif 