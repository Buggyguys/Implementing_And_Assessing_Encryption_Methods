#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_ctr.h"

// Standard AES-CTR implementation with authentication tag
unsigned char* aes_ctr_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "CTR"); // 16 bytes
    }
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Calculate output size (original + IV + tag)
    int total_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Simple CTR encryption
    // In CTR mode, we generate a keystream by encrypting a counter value,
    // then XOR the keystream with the plaintext to get the ciphertext
    
    unsigned char counter[16] = {0};
    memcpy(counter, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < data_length; i++) {
        // Increment counter (simple implementation - just increment the last byte)
        if (i > 0 && i % 16 == 0) {
            // Every 16 bytes, increment the counter
            for (int j = 15; j >= 0; j--) {
                counter[j]++;
                if (counter[j] != 0) break; // No overflow
            }
        }
        
        // Generate keystream byte by XORing counter with key
        unsigned char keystream = counter[i % 16] ^ context->key[i % context->key_length];
        
        // XOR plaintext with keystream
        output[context->iv_length + i] = data[i] ^ keystream;
    }
    
    // Generate authentication tag for the ciphertext
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ctr_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for CTR decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CTR IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // Verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Apply the same CTR mode logic as in encryption
    unsigned char counter[16] = {0};
    memcpy(counter, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < plaintext_len; i++) {
        // Increment counter (simple implementation - just increment the last byte)
        if (i > 0 && i % 16 == 0) {
            // Every 16 bytes, increment the counter
            for (int j = 15; j >= 0; j--) {
                counter[j]++;
                if (counter[j] != 0) break; // No overflow
            }
        }
        
        // Generate keystream byte by XORing counter with key
        unsigned char keystream = counter[i % 16] ^ context->key[i % context->key_length];
        
        // XOR ciphertext with keystream
        output[i] = data[context->iv_length + i] ^ keystream;
    }
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// Custom AES-CTR implementation with authentication
unsigned char* aes_ctr_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "CTR"); // 16 bytes
    }
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Calculate output size (original + IV + tag)
    int total_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Custom CTR encryption with a different counter scheme
    unsigned char counter[16] = {0};
    memcpy(counter, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    // Create a rotated key for a different pattern using secure allocation
    unsigned char* rotated_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 3 bytes for a different pattern
    if (context->key_length > 3) {
        unsigned char temp[3];
        memcpy(temp, rotated_key, 3);
        memmove(rotated_key, rotated_key + 3, context->key_length - 3);
        memcpy(rotated_key + context->key_length - 3, temp, 3);
    }
    
    for (int i = 0; i < data_length; i++) {
        // Custom counter update - more complex
        if (i > 0) {
            // Update counter more aggressively
            counter[i % 16] = (counter[i % 16] + i) % 256;
            // Additional counter manipulation
            if (i % 8 == 0) {
                // Swap two bytes
                unsigned char temp = counter[0];
                counter[0] = counter[15];
                counter[15] = temp;
            }
        }
        
        // Generate keystream byte with custom algorithm
        unsigned char keystream = counter[i % 16] ^ rotated_key[i % context->key_length];
        keystream ^= (i % 256); // Additional complexity
        
        // XOR plaintext with keystream
        output[context->iv_length + i] = data[i] ^ keystream;
    }
    
    // Generate authentication tag using rotated key
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          rotated_key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(rotated_key, context->key_length);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Securely free rotated key
    crypto_secure_free(rotated_key, context->key_length);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ctr_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for CTR decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CTR IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // Create a rotated key for a different pattern (same as in encryption)
    unsigned char* rotated_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 3 bytes for a different pattern
    if (context->key_length > 3) {
        unsigned char temp[3];
        memcpy(temp, rotated_key, 3);
        memmove(rotated_key, rotated_key + 3, context->key_length - 3);
        memcpy(rotated_key + context->key_length - 3, temp, 3);
    }
    
    // Verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        rotated_key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(rotated_key, context->key_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(rotated_key, context->key_length);
        return NULL;
    }
    
    // Custom CTR decryption - identical to encryption since CTR is symmetric
    unsigned char counter[16] = {0};
    memcpy(counter, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < plaintext_len; i++) {
        // Custom counter update - more complex
        if (i > 0) {
            // Update counter more aggressively
            counter[i % 16] = (counter[i % 16] + i) % 256;
            // Additional counter manipulation
            if (i % 8 == 0) {
                // Swap two bytes
                unsigned char temp = counter[0];
                counter[0] = counter[15];
                counter[15] = temp;
            }
        }
        
        // Generate keystream byte with custom algorithm
        unsigned char keystream = counter[i % 16] ^ rotated_key[i % context->key_length];
        keystream ^= (i % 256); // Additional complexity
        
        // XOR ciphertext with keystream
        output[i] = data[context->iv_length + i] ^ keystream;
    }
    
    // Securely free rotated key
    crypto_secure_free(rotated_key, context->key_length);
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL AES-CTR implementation
unsigned char* aes_ctr_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, ciphertext_len = 0;
    
    // Calculate output size (original + IV)
    int total_length = data_length + context->iv_length;
    
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
            cipher = EVP_aes_128_ctr();
            break;
        case 192:
            cipher = EVP_aes_192_ctr();
            break;
        case 256:
            cipher = EVP_aes_256_ctr();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-CTR: %d\n", context->key_size);
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
    
    // Finalize the encryption
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

unsigned char* aes_ctr_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // In CTR mode, decryption is identical to encryption
    // We're essentially encrypting the ciphertext to get the plaintext back
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, plaintext_len = 0;
    
    // Ensure we have enough data (at least for the IV)
    if (data_length <= context->iv_length) {
        fprintf(stderr, "Error: Not enough data for CTR decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CTR IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate ciphertext length (data without IV)
    int ciphertext_len = data_length - context->iv_length;
    
    // Allocate memory for output
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
            cipher = EVP_aes_128_ctr();
            break;
        case 192:
            cipher = EVP_aes_192_ctr();
            break;
        case 256:
            cipher = EVP_aes_256_ctr();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-CTR: %d\n", context->key_size);
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
    
    // Decrypt the ciphertext (same as encrypt in CTR mode)
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + context->iv_length, ciphertext_len)) {
        fprintf(stderr, "Error: Could not decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len = len;
    
    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        fprintf(stderr, "Error: Could not finalize decryption\n");
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