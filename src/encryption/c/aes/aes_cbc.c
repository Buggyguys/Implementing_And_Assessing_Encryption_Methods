#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "aes_cbc.h"

// Standard AES-CBC implementation (simple for now)
unsigned char* aes_cbc_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll implement a simple CBC mode
    // In a real implementation, this would use a proper AES-CBC mode
    
    // Calculate output size (original + IV)
    int total_length = data_length + context->iv_length;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Simple CBC encryption with key and IV
    unsigned char prev_block[16] = {0};
    memcpy(prev_block, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < data_length; i++) {
        // XOR with previous cipher block (CBC mode)
        unsigned char xored = data[i] ^ prev_block[i % 16];
        // Encrypt with key
        output[context->iv_length + i] = xored ^ context->key[i % context->key_length];
        // Update previous block for next iteration
        prev_block[i % 16] = output[context->iv_length + i];
    }
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_cbc_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll implement a simple CBC decryption
    // In a real implementation, this would use a proper AES-CBC mode
    
    // Ensure we have enough data (at least for the IV)
    if (data_length <= context->iv_length) {
        fprintf(stderr, "Error: Not enough data for CBC decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CBC IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV)
    int plaintext_len = data_length - context->iv_length;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Simple CBC decryption with key and IV
    unsigned char prev_block[16] = {0};
    memcpy(prev_block, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < plaintext_len; i++) {
        // Decrypt with key
        unsigned char decrypted = data[context->iv_length + i] ^ context->key[i % context->key_length];
        // XOR with previous cipher block (CBC mode)
        output[i] = decrypted ^ prev_block[i % 16];
        // Update previous block for next iteration
        prev_block[i % 16] = data[context->iv_length + i];
    }
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// Custom AES-CBC implementation
unsigned char* aes_cbc_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll implement a custom CBC mode with a different approach
    
    // Calculate output size (original + IV)
    int total_length = data_length + context->iv_length;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Custom CBC encryption with rotated key
    unsigned char prev_block[16] = {0};
    memcpy(prev_block, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    // Create a rotated key for a different pattern
    unsigned char* rotated_key = (unsigned char*)malloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        free(output);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 2 bytes
    if (context->key_length > 2) {
        unsigned char temp[2];
        memcpy(temp, rotated_key, 2);
        memmove(rotated_key, rotated_key + 2, context->key_length - 2);
        memcpy(rotated_key + context->key_length - 2, temp, 2);
    }
    
    for (int i = 0; i < data_length; i++) {
        // First XOR with previous block (CBC mode)
        unsigned char block_xor = data[i] ^ prev_block[i % 16];
        // Second XOR with rotated key
        output[context->iv_length + i] = block_xor ^ rotated_key[i % context->key_length];
        // Update previous block with current output
        prev_block[i % 16] = output[context->iv_length + i];
        // Extra XOR with i for more complexity
        output[context->iv_length + i] ^= (i % 256);
    }
    
    free(rotated_key);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_cbc_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Ensure we have enough data (at least for the IV)
    if (data_length <= context->iv_length) {
        fprintf(stderr, "Error: Not enough data for CBC decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CBC IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV)
    int plaintext_len = data_length - context->iv_length;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Custom CBC decryption - reverse the custom encryption
    unsigned char prev_block[16] = {0};
    memcpy(prev_block, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    // Create a rotated key for a different pattern (same as in encryption)
    unsigned char* rotated_key = (unsigned char*)malloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        free(output);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 2 bytes
    if (context->key_length > 2) {
        unsigned char temp[2];
        memcpy(temp, rotated_key, 2);
        memmove(rotated_key, rotated_key + 2, context->key_length - 2);
        memcpy(rotated_key + context->key_length - 2, temp, 2);
    }
    
    for (int i = 0; i < plaintext_len; i++) {
        // Un-XOR with i
        unsigned char block = data[context->iv_length + i] ^ (i % 256);
        // Un-XOR with rotated key
        unsigned char decrypted = block ^ rotated_key[i % context->key_length];
        // Un-XOR with previous cipher block (CBC mode)
        output[i] = decrypted ^ prev_block[i % 16];
        // Update previous block for next iteration
        prev_block[i % 16] = block;
    }
    
    free(rotated_key);
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL AES-CBC implementation
unsigned char* aes_cbc_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, ciphertext_len = 0;
    int block_size = 16; // AES block size is 16 bytes
    
    // Calculate output size (original + IV + padding)
    // In CBC mode, the output is padded to a multiple of the block size
    int padding_len = block_size - (data_length % block_size);
    int total_length = data_length + padding_len + context->iv_length;
    
    // Allocate memory for output
    output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // Select the appropriate cipher based on key size
    const EVP_CIPHER *cipher = NULL;
    switch (context->key_size) {
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-CBC: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, output + context->iv_length, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    ciphertext_len = len;
    
    // Finalize the encryption (add padding)
    if (1 != EVP_EncryptFinal_ex(ctx, output + context->iv_length + len, &len)) {
        fprintf(stderr, "Error: Could not finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    ciphertext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Set the output length
    if (output_length) {
        *output_length = context->iv_length + ciphertext_len;
    }
    
    return output;
}

unsigned char* aes_cbc_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, plaintext_len = 0;
    
    // Ensure we have enough data (at least for the IV)
    if (data_length <= context->iv_length) {
        fprintf(stderr, "Error: Not enough data for CBC decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CBC IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate ciphertext length (data without IV)
    int ciphertext_len = data_length - context->iv_length;
    
    // Allocate memory for output (maximum possible size)
    output = (unsigned char*)malloc(ciphertext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // Select the appropriate cipher based on key size
    const EVP_CIPHER *cipher = NULL;
    switch (context->key_size) {
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-CBC: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + context->iv_length, ciphertext_len)) {
        fprintf(stderr, "Error: Could not decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len = len;
    
    // Finalize the decryption (remove padding)
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        fprintf(stderr, "Error: Padding verification failed. Data may be corrupted.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}
#endif 