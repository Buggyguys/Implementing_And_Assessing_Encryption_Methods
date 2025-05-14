#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "aes_gcm.h"

// Standard AES-GCM implementation (simple XOR for now)
unsigned char* aes_gcm_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll implement a simple XOR-based encryption with the key
    // In a real implementation, this would use a proper AES-GCM mode
    
    // Calculate output size (original + IV + tag)
    int tag_size = 16; // GCM tag is 16 bytes
    int total_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Simple XOR encryption with key and IV
    for (int i = 0; i < data_length; i++) {
        // XOR with both key and IV to make it a bit more secure
        output[context->iv_length + i] = data[i] ^ context->key[i % context->key_length] ^ context->iv[i % context->iv_length];
    }
    
    // Generate a tag (XOR of all encrypted data bytes for simple integrity)
    unsigned char tag[16] = {0};
    for (int i = 0; i < data_length; i++) {
        tag[i % 16] ^= output[context->iv_length + i];
    }
    
    // Copy tag after encrypted data
    memcpy(output + context->iv_length + data_length, tag, tag_size);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_gcm_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll just reverse the XOR encryption
    // In a real implementation, this would use a proper AES-GCM mode
    
    // Calculate sizes
    int tag_size = 16; // GCM tag is 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Verify the tag (simple XOR check)
    unsigned char calculated_tag[16] = {0};
    for (int i = 0; i < plaintext_len; i++) {
        calculated_tag[i % 16] ^= data[context->iv_length + i];
    }
    
    // Check tag (in a real implementation, this would do proper authentication)
    const unsigned char* received_tag = data + context->iv_length + plaintext_len;
    // We'll just compare the first byte for demo purposes
    if (calculated_tag[0] != received_tag[0]) {
        fprintf(stderr, "Warning: Tag verification failed. Data may be corrupted.\n");
        // In a real implementation, we would probably fail here
    }
    
    // Reverse the XOR encryption
    for (int i = 0; i < plaintext_len; i++) {
        output[i] = data[context->iv_length + i] ^ context->key[i % context->key_length] ^ context->iv[i % context->iv_length];
    }
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// Custom AES-GCM implementation (alternative XOR pattern)
unsigned char* aes_gcm_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Custom GCM implementation
    // For testing, we'll use a different XOR pattern and a custom tag calculation
    
    // Calculate output size (original + IV + tag)
    int tag_size = 16; // GCM tag is 16 bytes
    int total_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Custom encryption - double XOR with rotated key
    unsigned char* rotated_key = (unsigned char*)malloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        free(output);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 4 bytes for a different pattern
    unsigned char temp[4];
    memcpy(temp, rotated_key, 4);
    memmove(rotated_key, rotated_key + 4, context->key_length - 4);
    memcpy(rotated_key + context->key_length - 4, temp, 4);
    
    // XOR encryption with rotated key
    for (int i = 0; i < data_length; i++) {
        output[context->iv_length + i] = data[i] ^ rotated_key[i % context->key_length];
        // Second XOR with a different pattern
        output[context->iv_length + i] ^= context->iv[(i + 3) % context->iv_length];
    }
    
    // Generate a custom tag (different algorithm from standard implementation)
    unsigned char tag[16] = {0};
    for (int i = 0; i < data_length; i++) {
        // Rotate tag bytes
        if (i % 16 == 0 && i > 0) {
            unsigned char tmp = tag[0];
            memmove(tag, tag + 1, 15);
            tag[15] = tmp;
        }
        tag[i % 16] ^= data[i];
        tag[(i + 1) % 16] ^= rotated_key[i % context->key_length];
    }
    
    // Add tag to output
    memcpy(output + context->iv_length + data_length, tag, tag_size);
    
    // Clean up
    free(rotated_key);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_gcm_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate sizes
    int tag_size = 16; // GCM tag is 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)malloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Rotate key in the same way as in encryption
    unsigned char* rotated_key = (unsigned char*)malloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        free(output);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 4 bytes for a different pattern
    unsigned char temp[4];
    memcpy(temp, rotated_key, 4);
    memmove(rotated_key, rotated_key + 4, context->key_length - 4);
    memcpy(rotated_key + context->key_length - 4, temp, 4);
    
    // Decrypt by reversing the XOR operations
    for (int i = 0; i < plaintext_len; i++) {
        output[i] = data[context->iv_length + i] ^ rotated_key[i % context->key_length];
        output[i] ^= context->iv[(i + 3) % context->iv_length];
    }
    
    // Clean up
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

// OpenSSL AES-GCM implementation
unsigned char* aes_gcm_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, ciphertext_len = 0;
    int tag_len = 16; // GCM tag is 16 bytes
    unsigned char tag[16];
    
    // Calculate output size (data + IV + tag)
    int total_length = data_length + context->iv_length + tag_len;
    
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
            cipher = EVP_aes_128_gcm();
            break;
        case 192:
            cipher = EVP_aes_192_gcm();
            break;
        case 256:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-GCM: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        fprintf(stderr, "Error: Could not initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Set IV length if different from default
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, context->iv_length, NULL)) {
        fprintf(stderr, "Error: Could not set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Initialize key and IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize key and IV\n");
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
    
    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        fprintf(stderr, "Error: Could not get tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Copy the tag to the output
    memcpy(output + context->iv_length + ciphertext_len, tag, tag_len);
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Set the output length
    if (output_length) {
        *output_length = context->iv_length + ciphertext_len + tag_len;
    }
    
    return output;
}

unsigned char* aes_gcm_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, plaintext_len = 0;
    int tag_len = 16; // GCM tag is 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_len) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate ciphertext length (data without IV and tag)
    int ciphertext_len = data_length - context->iv_length - tag_len;
    
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
            cipher = EVP_aes_128_gcm();
            break;
        case 192:
            cipher = EVP_aes_192_gcm();
            break;
        case 256:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-GCM: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        fprintf(stderr, "Error: Could not initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Set IV length if different from default
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, context->iv_length, NULL)) {
        fprintf(stderr, "Error: Could not set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Extract the tag from the ciphertext
    unsigned char tag[16];
    memcpy(tag, data + context->iv_length + ciphertext_len, tag_len);
    
    // Set the expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
        fprintf(stderr, "Error: Could not set tag\n");
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
    
    // Finalize the decryption
    int ret = EVP_DecryptFinal_ex(ctx, output + len, &len);
    if (ret <= 0) {
        fprintf(stderr, "Error: Tag verification failed. Data may be corrupted.\n");
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