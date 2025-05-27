#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "camellia_common.h"
#include "camellia_ctr.h"

#define AUTH_TAG_SIZE 16 // 16 bytes (128 bits) for authentication tag

// Camellia-CTR encryption function with authentication
unsigned char* camellia_ctr_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CTR"); // 16 bytes
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Calculate the output length (data + IV + tag)
    // CTR mode doesn't require padding, so the output length is the same as the input length
    *output_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CTR encryption output\n");
        return NULL;
    }
    
    // Structure of output: IV + Ciphertext + Tag
    
    // Copy the IV to the output
    memcpy(output, context->iv, context->iv_length);
    
    // For this placeholder, we'll create a simple counter and XOR with the data
    unsigned char counter[CAMELLIA_BLOCK_SIZE];
    memcpy(counter, context->iv, CAMELLIA_BLOCK_SIZE);
    
    for (int i = 0; i < data_length; i++) {
        // Increment counter for each byte (in a real implementation, you'd increment per block)
        if (i > 0 && i % CAMELLIA_BLOCK_SIZE == 0) {
            // Increment the counter (big-endian)
            for (int j = CAMELLIA_BLOCK_SIZE - 1; j >= 0; j--) {
                if (++counter[j] != 0) break;
            }
        }
        
        // XOR data with counter and key
        output[context->iv_length + i] = data[i] ^ counter[i % CAMELLIA_BLOCK_SIZE] ^ context->key[i % context->key_length];
    }
    
    // Generate authentication tag for the encrypted data
    unsigned char* ciphertext = output + context->iv_length;
    unsigned char* tag = output + context->iv_length + data_length;
    
    if (!crypto_generate_authentication_tag(tag, tag_size, ciphertext, data_length, 
                                           context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, *output_length);
        return NULL;
    }
    
    return output;
}

// Camellia-CTR decryption function with authentication verification
unsigned char* camellia_ctr_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CTR"); // 16 bytes
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Check if the data is large enough to contain the IV and tag
    if (data_length < context->iv_length + tag_size) {
        fprintf(stderr, "Error: Invalid Camellia-CTR ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length
    int plaintext_length = data_length - context->iv_length - tag_size;
    *output_length = plaintext_length;
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(plaintext_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CTR decryption output\n");
        return NULL;
    }
    
    // Extract the IV, ciphertext and tag from the input data
    const unsigned char* iv = data;
    const unsigned char* ciphertext = data + context->iv_length;
    const unsigned char* tag = data + context->iv_length + plaintext_length;
    
    // Verify the authentication tag first
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_length, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(plaintext, plaintext_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // Initialize counter from the IV
    unsigned char counter[CAMELLIA_BLOCK_SIZE];
    memcpy(counter, iv, CAMELLIA_BLOCK_SIZE);
    
    // CTR mode decryption is identical to encryption
    for (int i = 0; i < plaintext_length; i++) {
        // Increment counter for each byte (in a real implementation, you'd increment per block)
        if (i > 0 && i % CAMELLIA_BLOCK_SIZE == 0) {
            // Increment the counter (big-endian)
            for (int j = CAMELLIA_BLOCK_SIZE - 1; j >= 0; j--) {
                if (++counter[j] != 0) break;
            }
        }
        
        // XOR ciphertext with counter and key
        plaintext[i] = ciphertext[i] ^ counter[i % CAMELLIA_BLOCK_SIZE] ^ context->key[i % context->key_length];
    }
    
    return plaintext;
}

// Custom Camellia-CTR encryption function
unsigned char* camellia_ctr_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    // For now, the custom implementation just calls the standard one
    return camellia_ctr_encrypt(context, data, data_length, output_length);
}

// Custom Camellia-CTR decryption function
unsigned char* camellia_ctr_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    // For now, the custom implementation just calls the standard one
    return camellia_ctr_decrypt(context, data, data_length, output_length);
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL Camellia-CTR encryption function
unsigned char* camellia_ctr_openssl_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char *ciphertext;
    
    // Calculate the output length (data + IV)
    *output_length = data_length + context->iv_length;
    
    // Allocate memory for the output
    ciphertext = (unsigned char*)malloc(*output_length);
    if (!ciphertext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CTR encryption output\n");
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
            cipher = EVP_camellia_128_ctr();
            break;
        case 192:
            cipher = EVP_camellia_192_ctr();
            break;
        case 256:
            cipher = EVP_camellia_256_ctr();
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

// OpenSSL Camellia-CTR decryption function
unsigned char* camellia_ctr_openssl_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char *plaintext;
    
    // Check if the data is large enough to contain the IV
    if (data_length < context->iv_length) {
        fprintf(stderr, "Error: Invalid Camellia-CTR ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length
    *output_length = data_length - context->iv_length;
    
    // Allocate memory for the plaintext
    plaintext = (unsigned char*)malloc(*output_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CTR decryption output\n");
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
            cipher = EVP_camellia_128_ctr();
            break;
        case 192:
            cipher = EVP_camellia_192_ctr();
            break;
        case 256:
            cipher = EVP_camellia_256_ctr();
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
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, data + context->iv_length, *output_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    plaintext_len = len;
    
    // Finalize the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL decryption\n");
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