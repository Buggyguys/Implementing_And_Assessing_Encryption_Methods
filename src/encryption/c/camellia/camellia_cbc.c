#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "camellia_common.h"
#include "camellia_cbc.h"

#define AUTH_TAG_SIZE 16 // 16 bytes (128 bits) for authentication tag

// Camellia-CBC encryption function with authentication
unsigned char* camellia_cbc_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate the output length (data + IV + tag)
    // In CBC mode, we need to pad the data to a multiple of the block size
    int block_size = CAMELLIA_BLOCK_SIZE;
    int padded_length = ((data_length + block_size - 1) / block_size) * block_size;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CBC"); // 16 bytes
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Total output = IV + padded data + tag
    *output_length = context->iv_length + padded_length + tag_size;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CBC encryption output\n");
        return NULL;
    }
    
    // Structure of output: IV + Ciphertext + Tag
    
    // Copy the IV to the output
    memcpy(output, context->iv, context->iv_length);
    
    // For this placeholder, we'll just XOR the data with the key as a simple "encryption"
    // In a real implementation, you would use the Camellia cipher in CBC mode
    unsigned char prev_block[CAMELLIA_BLOCK_SIZE];
    memcpy(prev_block, context->iv, CAMELLIA_BLOCK_SIZE);
    
    for (int i = 0; i < data_length; i++) {
        // XOR with previous ciphertext block (or IV for the first block)
        unsigned char xored = data[i] ^ prev_block[i % CAMELLIA_BLOCK_SIZE];
        
        // XOR with key (simple substitution for placeholder)
        output[context->iv_length + i] = xored ^ context->key[i % context->key_length];
        
        // Update previous block for next iteration
        prev_block[i % CAMELLIA_BLOCK_SIZE] = output[context->iv_length + i];
    }
    
    // Pad the remaining bytes (if any)
    for (int i = data_length; i < padded_length; i++) {
        unsigned char padding_byte = padded_length - data_length;
        
        // XOR with previous ciphertext block
        unsigned char xored = padding_byte ^ prev_block[i % CAMELLIA_BLOCK_SIZE];
        
        // XOR with key (simple substitution for placeholder)
        output[context->iv_length + i] = xored ^ context->key[i % context->key_length];
        
        // Update previous block for next iteration
        prev_block[i % CAMELLIA_BLOCK_SIZE] = output[context->iv_length + i];
    }
    
    // Generate authentication tag for the encrypted data
    unsigned char* ciphertext = output + context->iv_length;
    unsigned char* tag = output + context->iv_length + padded_length;
    
    if (!crypto_generate_authentication_tag(tag, tag_size, ciphertext, padded_length, 
                                           context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, *output_length);
        return NULL;
    }
    
    return output;
}

// Camellia-CBC decryption function with authentication verification
unsigned char* camellia_cbc_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CBC"); // 16 bytes
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Check if the data is large enough to contain the IV and tag
    if (data_length < context->iv_length + tag_size) {
        fprintf(stderr, "Error: Invalid Camellia-CBC ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length (including padding)
    int padded_length = data_length - context->iv_length - tag_size;
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(padded_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CBC decryption output\n");
        return NULL;
    }
    
    // Extract the IV, ciphertext and tag from the input data
    const unsigned char* iv = data;
    const unsigned char* ciphertext = data + context->iv_length;
    const unsigned char* tag = data + context->iv_length + padded_length;
    
    // Verify the authentication tag first
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, padded_length, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(plaintext, padded_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // For this placeholder, we'll just XOR the data with the key as a simple "decryption"
    // In a real implementation, you would use the Camellia cipher in CBC mode
    for (int i = 0; i < padded_length; i++) {
        // XOR with key (simple substitution for placeholder)
        unsigned char xored = ciphertext[i] ^ context->key[i % context->key_length];
        
        // XOR with previous ciphertext block (or IV for the first block)
        if (i < CAMELLIA_BLOCK_SIZE) {
            plaintext[i] = xored ^ iv[i];
        } else {
            plaintext[i] = xored ^ ciphertext[i - CAMELLIA_BLOCK_SIZE];
        }
    }
    
    // Check for and remove padding
    unsigned char padding_byte = plaintext[padded_length - 1];
    if (padding_byte > 0 && padding_byte <= CAMELLIA_BLOCK_SIZE) {
        // Verify padding
        int valid_padding = 1;
        for (int i = padded_length - padding_byte; i < padded_length; i++) {
            if (plaintext[i] != padding_byte) {
                valid_padding = 0;
                break;
            }
        }
        
        if (valid_padding) {
            padded_length -= padding_byte;
        }
    }
    
    *output_length = padded_length;
    
    return plaintext;
}

// Custom Camellia-CBC encryption function
unsigned char* camellia_cbc_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    // For now, the custom implementation just calls the standard one
    return camellia_cbc_encrypt(context, data, data_length, output_length);
}

// Custom Camellia-CBC decryption function
unsigned char* camellia_cbc_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    // For now, the custom implementation just calls the standard one
    return camellia_cbc_decrypt(context, data, data_length, output_length);
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL Camellia-CBC encryption function
unsigned char* camellia_cbc_openssl_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char *ciphertext;
    
    // Calculate the output length (data + IV + padding)
    int block_size = CAMELLIA_BLOCK_SIZE;
    int padded_length = ((data_length + block_size - 1) / block_size) * block_size;
    *output_length = padded_length + context->iv_length;
    
    // Allocate memory for the output
    ciphertext = (unsigned char*)malloc(*output_length);
    if (!ciphertext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CBC encryption output\n");
        return NULL;
    }
    
    // Copy the IV to the output
    memcpy(ciphertext, context->iv, context->iv_length);
    
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
            cipher = EVP_camellia_128_cbc();
            break;
        case 192:
            cipher = EVP_camellia_192_cbc();
            break;
        case 256:
            cipher = EVP_camellia_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid Camellia key size %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(ciphertext);
            return NULL;
    }
    
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    
    // Provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext + context->iv_length, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len = len;
    
    // Finalize the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + context->iv_length + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Update the output length
    *output_length = context->iv_length + ciphertext_len;
    
    return ciphertext;
}

// OpenSSL Camellia-CBC decryption function
unsigned char* camellia_cbc_openssl_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char *plaintext;
    
    // Check if the data is large enough to contain the IV
    if (data_length < context->iv_length) {
        fprintf(stderr, "Error: Invalid Camellia-CBC ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length (including padding)
    int padded_length = data_length - context->iv_length;
    
    // Allocate memory for the plaintext
    plaintext = (unsigned char*)malloc(padded_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CBC decryption output\n");
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
            cipher = EVP_camellia_128_cbc();
            break;
        case 192:
            cipher = EVP_camellia_192_cbc();
            break;
        case 256:
            cipher = EVP_camellia_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid Camellia key size %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            return NULL;
    }
    
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, data)) {
        fprintf(stderr, "Error: Could not initialize OpenSSL decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    
    // Provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, data + context->iv_length, padded_length)) {
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