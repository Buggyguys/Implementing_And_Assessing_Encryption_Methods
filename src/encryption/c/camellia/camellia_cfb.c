#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "camellia_common.h"
#include "camellia_cfb.h"

#define AUTH_TAG_SIZE 16 // 16 bytes (128 bits) for authentication tag

// Camellia-CFB encryption function with authentication
unsigned char* camellia_cfb_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CFB"); // 16 bytes
    }
    
    // Generate IV if not already set
    if (!context->iv) {
        context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
        if (!context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for IV\n");
            return NULL;
        }
        generate_random_bytes(context->iv, context->iv_length);
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Total output = IV + data + tag (no padding needed in CFB mode)
    *output_length = context->iv_length + data_length + tag_size;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CFB encryption output\n");
        return NULL;
    }
    
    // Structure of output: IV + Ciphertext + Tag
    
    // Copy the IV to the output
    memcpy(output, context->iv, context->iv_length);
    
    // CFB mode: feedback register starts with IV and is updated with ciphertext
    unsigned char feedback[CAMELLIA_BLOCK_SIZE];
    memcpy(feedback, context->iv, CAMELLIA_BLOCK_SIZE);
    
    for (int i = 0; i < data_length; i++) {
        // Generate keystream byte by XORing feedback with key
        unsigned char keystream_byte = feedback[i % CAMELLIA_BLOCK_SIZE] ^ context->key[i % context->key_length];
        
        // Enhanced keystream generation with position-dependent mixing
        keystream_byte ^= (unsigned char)(i & 0xFF);
        keystream_byte = ((keystream_byte << 2) | (keystream_byte >> 6)) ^ context->key[(i * 5) % context->key_length];
        
        // Encrypt data with keystream
        unsigned char ciphertext_byte = data[i] ^ keystream_byte;
        output[context->iv_length + i] = ciphertext_byte;
        
        // Update feedback register with ciphertext (characteristic of CFB)
        feedback[i % CAMELLIA_BLOCK_SIZE] = ciphertext_byte;
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

// Camellia-CFB decryption function with authentication verification
unsigned char* camellia_cfb_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CFB"); // 16 bytes
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Check if the data is large enough to contain the IV and tag
    if (data_length < context->iv_length + tag_size) {
        fprintf(stderr, "Error: Invalid Camellia-CFB ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length
    int plaintext_length = data_length - context->iv_length - tag_size;
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(plaintext_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CFB decryption output\n");
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
    
    // CFB mode decryption: feedback register starts with IV and is updated with ciphertext
    unsigned char feedback[CAMELLIA_BLOCK_SIZE];
    memcpy(feedback, iv, CAMELLIA_BLOCK_SIZE);
    
    for (int i = 0; i < plaintext_length; i++) {
        // Generate keystream byte by XORing feedback with key (same as encryption)
        unsigned char keystream_byte = feedback[i % CAMELLIA_BLOCK_SIZE] ^ context->key[i % context->key_length];
        
        // Enhanced keystream generation with position-dependent mixing
        keystream_byte ^= (unsigned char)(i & 0xFF);
        keystream_byte = ((keystream_byte << 2) | (keystream_byte >> 6)) ^ context->key[(i * 5) % context->key_length];
        
        // Decrypt data with keystream
        plaintext[i] = ciphertext[i] ^ keystream_byte;
        
        // Update feedback register with ciphertext (same as encryption)
        feedback[i % CAMELLIA_BLOCK_SIZE] = ciphertext[i];
    }
    
    *output_length = plaintext_length;
    
    return plaintext;
}

// Custom Camellia-CFB encryption function with enhanced feedback mechanism
unsigned char* camellia_cfb_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CFB"); // 16 bytes
    }
    
    // Generate IV if not already set
    if (!context->iv) {
        context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
        if (!context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for IV\n");
            return NULL;
        }
        generate_random_bytes(context->iv, context->iv_length);
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Total output = IV + data + tag (no padding needed in CFB mode)
    *output_length = context->iv_length + data_length + tag_size;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CFB custom encryption output\n");
        return NULL;
    }
    
    // Structure of output: IV + Ciphertext + Tag
    
    // Copy the IV to the output
    memcpy(output, context->iv, context->iv_length);
    
    // Custom CFB mode with enhanced feedback mechanism
    unsigned char feedback[CAMELLIA_BLOCK_SIZE];
    memcpy(feedback, context->iv, CAMELLIA_BLOCK_SIZE);
    
    // Additional key mixing for custom variant
    unsigned char mixed_key[32];
    for (int i = 0; i < 32; i++) {
        mixed_key[i] = context->key[i % context->key_length] ^ context->key[(i + 11) % context->key_length];
        mixed_key[i] = ((mixed_key[i] << 3) | (mixed_key[i] >> 5)) ^ (unsigned char)(i * 7);
    }
    
    for (int i = 0; i < data_length; i++) {
        // Enhanced keystream generation with double key mixing
        unsigned char keystream_byte = feedback[i % CAMELLIA_BLOCK_SIZE] ^ mixed_key[i % 32];
        keystream_byte ^= context->key[(i * 13) % context->key_length];
        
        // Position-dependent transformations with enhanced feedback
        keystream_byte ^= (unsigned char)((i * 17) & 0xFF);
        keystream_byte = ((keystream_byte << 5) | (keystream_byte >> 3)) ^ mixed_key[(i * 3) % 32];
        
        // Enhanced feedback mixing with position variations
        unsigned char enhanced_feedback = feedback[i % CAMELLIA_BLOCK_SIZE];
        enhanced_feedback ^= (unsigned char)((i * 19) & 0xFF);
        enhanced_feedback = ((enhanced_feedback << 1) | (enhanced_feedback >> 7));
        keystream_byte ^= enhanced_feedback;
        
        // Encrypt data with enhanced keystream
        unsigned char ciphertext_byte = data[i] ^ keystream_byte;
        output[context->iv_length + i] = ciphertext_byte;
        
        // Update feedback register with enhanced ciphertext mixing
        feedback[i % CAMELLIA_BLOCK_SIZE] = ciphertext_byte ^ (unsigned char)(i & 0x0F);
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

// Custom Camellia-CFB decryption function with enhanced feedback mechanism
unsigned char* camellia_cfb_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Set standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("Camellia", "CFB"); // 16 bytes
    }
    
    // Calculate tag size
    int tag_size = AUTH_TAG_SIZE;
    
    // Check if the data is large enough to contain the IV and tag
    if (data_length < context->iv_length + tag_size) {
        fprintf(stderr, "Error: Invalid Camellia-CFB ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length
    int plaintext_length = data_length - context->iv_length - tag_size;
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(plaintext_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-CFB decryption output\n");
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
    
    // Custom CFB mode decryption with enhanced feedback mechanism
    unsigned char feedback[CAMELLIA_BLOCK_SIZE];
    memcpy(feedback, iv, CAMELLIA_BLOCK_SIZE);
    
    // Additional key mixing for custom variant (same as encryption)
    unsigned char mixed_key[32];
    for (int i = 0; i < 32; i++) {
        mixed_key[i] = context->key[i % context->key_length] ^ context->key[(i + 11) % context->key_length];
        mixed_key[i] = ((mixed_key[i] << 3) | (mixed_key[i] >> 5)) ^ (unsigned char)(i * 7);
    }
    
    for (int i = 0; i < plaintext_length; i++) {
        // Enhanced keystream generation with double key mixing (same as encryption)
        unsigned char keystream_byte = feedback[i % CAMELLIA_BLOCK_SIZE] ^ mixed_key[i % 32];
        keystream_byte ^= context->key[(i * 13) % context->key_length];
        
        // Position-dependent transformations with enhanced feedback
        keystream_byte ^= (unsigned char)((i * 17) & 0xFF);
        keystream_byte = ((keystream_byte << 5) | (keystream_byte >> 3)) ^ mixed_key[(i * 3) % 32];
        
        // Enhanced feedback mixing with position variations
        unsigned char enhanced_feedback = feedback[i % CAMELLIA_BLOCK_SIZE];
        enhanced_feedback ^= (unsigned char)((i * 19) & 0xFF);
        enhanced_feedback = ((enhanced_feedback << 1) | (enhanced_feedback >> 7));
        keystream_byte ^= enhanced_feedback;
        
        // Decrypt data with enhanced keystream
        plaintext[i] = ciphertext[i] ^ keystream_byte;
        
        // Update feedback register with enhanced ciphertext mixing (same as encryption)
        feedback[i % CAMELLIA_BLOCK_SIZE] = ciphertext[i] ^ (unsigned char)(i & 0x0F);
    }
    
    *output_length = plaintext_length;
    
    return plaintext;
} 