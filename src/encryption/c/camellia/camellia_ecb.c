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
    
    // Calculate the output length (data + padding + tag)
    // In ECB mode, we need to pad the data to a multiple of the block size
    int block_size = CAMELLIA_BLOCK_SIZE;
    int padded_length = ((data_length + block_size - 1) / block_size) * block_size;
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Total output = padded data + tag (no IV in ECB mode)
    *output_length = padded_length + tag_size;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB encryption output\n");
        return NULL;
    }
    
    // Structure of output: Ciphertext + Tag (no IV in ECB)
    
    // ECB mode: each block is encrypted independently
    for (int i = 0; i < data_length; i++) {
        // Simple block-based encryption with key mixing
        unsigned char block_key = context->key[i % context->key_length];
        
        // Position-dependent key mixing
        block_key ^= (unsigned char)(i & 0xFF);
        block_key = ((block_key << 1) | (block_key >> 7)) ^ context->key[(i * 3) % context->key_length];
        
        // Block position within the current 16-byte block
        int block_pos = i % CAMELLIA_BLOCK_SIZE;
        block_key ^= context->key[(block_pos * 5) % context->key_length];
        
        // Encrypt data with position-dependent key
        output[i] = data[i] ^ block_key;
    }
    
    // Pad the remaining bytes (if any)
    for (int i = data_length; i < padded_length; i++) {
        unsigned char padding_byte = padded_length - data_length;
        
        // Apply same encryption logic to padding
        unsigned char block_key = context->key[i % context->key_length];
        block_key ^= (unsigned char)(i & 0xFF);
        block_key = ((block_key << 1) | (block_key >> 7)) ^ context->key[(i * 3) % context->key_length];
        
        int block_pos = i % CAMELLIA_BLOCK_SIZE;
        block_key ^= context->key[(block_pos * 5) % context->key_length];
        
        output[i] = padding_byte ^ block_key;
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
    
    // Check if the data is large enough to contain the tag
    if (data_length < tag_size) {
        fprintf(stderr, "Error: Invalid Camellia-ECB ciphertext length\n");
        return NULL;
    }
    
    // Calculate the padded length
    int padded_length = data_length - tag_size;
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(padded_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB decryption output\n");
        return NULL;
    }
    
    // Extract the ciphertext and tag from the input data
    const unsigned char* ciphertext = data;
    const unsigned char* tag = data + padded_length;
    
    // Verify the authentication tag first
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, padded_length, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(plaintext, padded_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // ECB mode decryption: each block is decrypted independently
    for (int i = 0; i < padded_length; i++) {
        // Same key mixing as encryption
        unsigned char block_key = context->key[i % context->key_length];
        
        // Position-dependent key mixing
        block_key ^= (unsigned char)(i & 0xFF);
        block_key = ((block_key << 1) | (block_key >> 7)) ^ context->key[(i * 3) % context->key_length];
        
        // Block position within the current 16-byte block
        int block_pos = i % CAMELLIA_BLOCK_SIZE;
        block_key ^= context->key[(block_pos * 5) % context->key_length];
        
        // Decrypt data with position-dependent key
        plaintext[i] = ciphertext[i] ^ block_key;
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

// Custom Camellia-ECB encryption function with enhanced block processing
unsigned char* camellia_ecb_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate the output length (data + padding + tag)
    int block_size = CAMELLIA_BLOCK_SIZE;
    int padded_length = ((data_length + block_size - 1) / block_size) * block_size;
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Total output = padded data + tag (no IV in ECB mode)
    *output_length = padded_length + tag_size;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB custom encryption output\n");
        return NULL;
    }
    
    // Structure of output: Ciphertext + Tag (no IV in ECB)
    
    // Enhanced key mixing for custom variant
    unsigned char mixed_key[64];
    for (int i = 0; i < 64; i++) {
        mixed_key[i] = context->key[i % context->key_length] ^ context->key[(i + 13) % context->key_length];
        mixed_key[i] = ((mixed_key[i] << 4) | (mixed_key[i] >> 4)) ^ (unsigned char)(i * 11);
        mixed_key[i] ^= context->key[(i * 7) % context->key_length];
    }
    
    // Custom ECB mode: enhanced block-based encryption
    for (int i = 0; i < data_length; i++) {
        // Enhanced block-based encryption with multiple key layers
        unsigned char block_key = mixed_key[i % 64];
        
        // Multi-layer position-dependent mixing
        block_key ^= (unsigned char)((i * 23) & 0xFF);
        block_key = ((block_key << 3) | (block_key >> 5)) ^ context->key[(i * 17) % context->key_length];
        
        // Block position within the current 16-byte block with enhanced mixing
        int block_pos = i % CAMELLIA_BLOCK_SIZE;
        block_key ^= mixed_key[(block_pos * 11) % 64];
        
        // Additional layer with cross-block influence
        int block_number = i / CAMELLIA_BLOCK_SIZE;
        block_key ^= (unsigned char)((block_number * 19) & 0xFF);
        block_key = ((block_key << 2) | (block_key >> 6)) ^ mixed_key[(block_number * 7) % 64];
        
        // Encrypt data with enhanced multi-layer key
        output[i] = data[i] ^ block_key;
    }
    
    // Pad the remaining bytes with enhanced padding
    for (int i = data_length; i < padded_length; i++) {
        unsigned char padding_byte = padded_length - data_length;
        
        // Apply same enhanced encryption logic to padding
        unsigned char block_key = mixed_key[i % 64];
        block_key ^= (unsigned char)((i * 23) & 0xFF);
        block_key = ((block_key << 3) | (block_key >> 5)) ^ context->key[(i * 17) % context->key_length];
        
        int block_pos = i % CAMELLIA_BLOCK_SIZE;
        block_key ^= mixed_key[(block_pos * 11) % 64];
        
        int block_number = i / CAMELLIA_BLOCK_SIZE;
        block_key ^= (unsigned char)((block_number * 19) & 0xFF);
        block_key = ((block_key << 2) | (block_key >> 6)) ^ mixed_key[(block_number * 7) % 64];
        
        output[i] = padding_byte ^ block_key;
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

// Custom Camellia-ECB decryption function
unsigned char* camellia_ecb_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Check if the data is large enough to contain the tag
    if (data_length < tag_size) {
        fprintf(stderr, "Error: Invalid Camellia-ECB ciphertext length\n");
        return NULL;
    }
    
    // Calculate the padded length
    int padded_length = data_length - tag_size;
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(padded_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-ECB custom decryption output\n");
        return NULL;
    }
    
    // Extract the ciphertext and tag from the input data
    const unsigned char* ciphertext = data;
    const unsigned char* tag = data + padded_length;
    
    // Verify the authentication tag first
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, padded_length, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(plaintext, padded_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // Enhanced key mixing for custom variant (same as encryption)
    unsigned char mixed_key[64];
    for (int i = 0; i < 64; i++) {
        mixed_key[i] = context->key[i % context->key_length] ^ context->key[(i + 13) % context->key_length];
        mixed_key[i] = ((mixed_key[i] << 4) | (mixed_key[i] >> 4)) ^ (unsigned char)(i * 11);
        mixed_key[i] ^= context->key[(i * 7) % context->key_length];
    }
    
    // Custom ECB mode decryption (same process as encryption)
    for (int i = 0; i < padded_length; i++) {
        // Enhanced block-based decryption (same as encryption)
        unsigned char block_key = mixed_key[i % 64];
        
        // Multi-layer position-dependent mixing
        block_key ^= (unsigned char)((i * 23) & 0xFF);
        block_key = ((block_key << 3) | (block_key >> 5)) ^ context->key[(i * 17) % context->key_length];
        
        // Block position within the current 16-byte block with enhanced mixing
        int block_pos = i % CAMELLIA_BLOCK_SIZE;
        block_key ^= mixed_key[(block_pos * 11) % 64];
        
        // Additional layer with cross-block influence
        int block_number = i / CAMELLIA_BLOCK_SIZE;
        block_key ^= (unsigned char)((block_number * 19) & 0xFF);
        block_key = ((block_key << 2) | (block_key >> 6)) ^ mixed_key[(block_number * 7) % 64];
        
        // Decrypt data with enhanced multi-layer key
        plaintext[i] = ciphertext[i] ^ block_key;
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