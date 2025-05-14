#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "aes_ecb.h"

// Standard AES-ECB implementation (simple for now)
unsigned char* aes_ecb_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll implement a simple ECB mode
    // In a real implementation, this would use a proper AES-ECB mode
    
    // Calculate block padding (ECB operates on fixed block sizes)
    int block_size = 16; // AES block size is 16 bytes
    int padding_len = block_size - (data_length % block_size);
    if (padding_len == 0) padding_len = block_size; // Full block of padding if data is already aligned
    
    // Calculate output size (original + padding)
    int total_length = data_length + padding_len;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy data to output buffer
    memcpy(output, data, data_length);
    
    // Add PKCS#7 padding
    memset(output + data_length, padding_len, padding_len);
    
    // Simple ECB encryption with key (process each block independently)
    for (int i = 0; i < total_length; i += block_size) {
        // Process each block
        for (int j = 0; j < block_size; j++) {
            // Simple XOR encryption with key
            output[i + j] ^= context->key[(i + j) % context->key_length];
        }
    }
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ecb_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll implement a simple ECB decryption
    // In a real implementation, this would use a proper AES-ECB mode
    
    int block_size = 16; // AES block size is 16 bytes
    
    // Check if data length is a multiple of block size
    if (data_length % block_size != 0) {
        fprintf(stderr, "Error: Invalid data length for ECB decryption\n");
        return NULL;
    }
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(data_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Simple ECB decryption with key (process each block independently)
    for (int i = 0; i < data_length; i += block_size) {
        // Process each block
        for (int j = 0; j < block_size; j++) {
            // Simple XOR decryption with key (same as encryption for XOR)
            output[i + j] = data[i + j] ^ context->key[(i + j) % context->key_length];
        }
    }
    
    // Check and remove PKCS#7 padding
    unsigned char padding_value = output[data_length - 1];
    if (padding_value > 0 && padding_value <= block_size) {
        // Verify padding
        int valid_padding = 1;
        for (int i = 0; i < padding_value; i++) {
            if (output[data_length - 1 - i] != padding_value) {
                valid_padding = 0;
                break;
            }
        }
        
        if (valid_padding) {
            // Set the actual output length
            if (output_length) {
                *output_length = data_length - padding_value;
            }
            return output;
        }
    }
    
    // If we got here, padding is invalid or not present
    if (output_length) {
        *output_length = data_length;
    }
    
    return output;
}

// Custom AES-ECB implementation
unsigned char* aes_ecb_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll implement a custom ECB mode with a modified approach
    
    // Calculate block padding (ECB operates on fixed block sizes)
    int block_size = 16; // AES block size is 16 bytes
    int padding_len = block_size - (data_length % block_size);
    if (padding_len == 0) padding_len = block_size; // Full block of padding if data is already aligned
    
    // Calculate output size (original + padding)
    int total_length = data_length + padding_len;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy data to output buffer
    memcpy(output, data, data_length);
    
    // Add PKCS#7 padding
    memset(output + data_length, padding_len, padding_len);
    
    // Create a rotated key for a different pattern
    unsigned char* rotated_key = (unsigned char*)malloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        free(output);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 1 byte for a different pattern
    if (context->key_length > 1) {
        unsigned char temp = rotated_key[0];
        memmove(rotated_key, rotated_key + 1, context->key_length - 1);
        rotated_key[context->key_length - 1] = temp;
    }
    
    // Custom ECB encryption with block scrambling
    for (int i = 0; i < total_length; i += block_size) {
        // First pass: XOR with rotated key
        for (int j = 0; j < block_size; j++) {
            output[i + j] ^= rotated_key[j % context->key_length];
        }
        
        // Second pass: Scramble the block by rotating bytes
        if (i + block_size <= total_length) {
            // Save first byte
            unsigned char temp = output[i];
            // Shift each byte in the block
            memmove(output + i, output + i + 1, block_size - 1);
            // Move first byte to end
            output[i + block_size - 1] = temp;
        }
        
        // Third pass: XOR with block index to make each block unique
        for (int j = 0; j < block_size; j++) {
            output[i + j] ^= (i / block_size) % 256;
        }
    }
    
    free(rotated_key);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ecb_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    int block_size = 16; // AES block size is 16 bytes
    
    // Check if data length is a multiple of block size
    if (data_length % block_size != 0) {
        fprintf(stderr, "Error: Invalid data length for ECB decryption\n");
        return NULL;
    }
    
    // Allocate memory for output and working copy
    unsigned char* output = (unsigned char*)malloc(data_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Create working copy to avoid modifying original data
    memcpy(output, data, data_length);
    
    // Create a rotated key for a different pattern (same as in encryption)
    unsigned char* rotated_key = (unsigned char*)malloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        free(output);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 1 byte for a different pattern
    if (context->key_length > 1) {
        unsigned char temp = rotated_key[0];
        memmove(rotated_key, rotated_key + 1, context->key_length - 1);
        rotated_key[context->key_length - 1] = temp;
    }
    
    // Custom ECB decryption (reverse the encryption steps)
    for (int i = 0; i < data_length; i += block_size) {
        // First pass: Undo the block index XOR
        for (int j = 0; j < block_size; j++) {
            output[i + j] ^= (i / block_size) % 256;
        }
        
        // Second pass: Unscramble the block by rotating bytes back
        if (i + block_size <= data_length) {
            // Save last byte
            unsigned char temp = output[i + block_size - 1];
            // Shift each byte in the block
            memmove(output + i + 1, output + i, block_size - 1);
            // Move last byte to beginning
            output[i] = temp;
        }
        
        // Third pass: Undo the XOR with rotated key
        for (int j = 0; j < block_size; j++) {
            output[i + j] ^= rotated_key[j % context->key_length];
        }
    }
    
    free(rotated_key);
    
    // Check and remove PKCS#7 padding
    unsigned char padding_value = output[data_length - 1];
    if (padding_value > 0 && padding_value <= block_size) {
        // Verify padding
        int valid_padding = 1;
        for (int i = 0; i < padding_value; i++) {
            if (output[data_length - 1 - i] != padding_value) {
                valid_padding = 0;
                break;
            }
        }
        
        if (valid_padding) {
            // Set the actual output length
            if (output_length) {
                *output_length = data_length - padding_value;
            }
            return output;
        }
    }
    
    // If we got here, padding is invalid or not present
    if (output_length) {
        *output_length = data_length;
    }
    
    return output;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL AES-ECB implementation
unsigned char* aes_ecb_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, ciphertext_len = 0;
    int block_size = 16; // AES block size is 16 bytes
    
    // Calculate padding (PKCS#7 padding will be added by OpenSSL)
    int padding_len = block_size - (data_length % block_size);
    if (padding_len == 0) padding_len = block_size; // Full block of padding if data is already aligned
    
    // Allocate memory for output (with padding)
    int total_length = data_length + padding_len;
    output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
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
            cipher = EVP_aes_128_ecb();
            break;
        case 192:
            cipher = EVP_aes_192_ecb();
            break;
        case 256:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-ECB: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the encryption operation (ECB doesn't use IV)
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, NULL)) {
        fprintf(stderr, "Error: Could not initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, output, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    ciphertext_len = len;
    
    // Finalize the encryption (add padding)
    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) {
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
        *output_length = ciphertext_len;
    }
    
    return output;
}

unsigned char* aes_ecb_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, plaintext_len = 0;
    
    // Check if data length is a multiple of block size
    if (data_length % 16 != 0) {
        fprintf(stderr, "Error: Invalid data length for ECB decryption\n");
        return NULL;
    }
    
    // Allocate memory for output (maximum possible size)
    output = (unsigned char*)malloc(data_length);
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
            cipher = EVP_aes_128_ecb();
            break;
        case 192:
            cipher = EVP_aes_192_ecb();
            break;
        case 256:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-ECB: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the decryption operation (ECB doesn't use IV)
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, NULL)) {
        fprintf(stderr, "Error: Could not initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data, data_length)) {
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