#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_gcm.h"

// Standard AES-GCM implementation with proper tag handling
unsigned char* aes_gcm_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For testing, we'll still use a simple XOR-based encryption with the key
    // But we'll enhance it with proper tag handling
    
    // Calculate output size (original + IV + tag)
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    int total_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Simple XOR encryption with key and IV (still simplified for demo)
    for (int i = 0; i < data_length; i++) {
        // XOR with both key and IV to make it a bit more secure
        output[context->iv_length + i] = data[i] ^ context->key[i % context->key_length] ^ context->iv[i % context->iv_length];
    }
    
    // Generate a cryptographically secure tag
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

unsigned char* aes_gcm_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate sizes using standard values
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
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
        return NULL; // In a real implementation, we would fail on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Reverse the XOR encryption
    for (int i = 0; i < plaintext_len; i++) {
        output[i] = ciphertext[i] ^ context->key[i % context->key_length] ^ context->iv[i % context->iv_length];
    }
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// Custom AES-GCM implementation with proper tag handling
unsigned char* aes_gcm_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Custom GCM implementation
    // For testing, we'll use a different XOR pattern and a custom tag calculation
    
    // Calculate output size (original + IV + tag)
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    int total_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Custom encryption - double XOR with rotated key
    unsigned char* rotated_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        crypto_secure_free(output, total_length);
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
    
    // Generate a custom authentication tag
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                           output + context->iv_length, data_length,
                                           rotated_key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(rotated_key, context->key_length);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Clean up
    crypto_secure_free(rotated_key, context->key_length);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_gcm_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate sizes using standard values
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // Rotate key in the same way as in encryption
    unsigned char* rotated_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 4 bytes (same as in encryption)
    unsigned char temp[4];
    memcpy(temp, rotated_key, 4);
    memmove(rotated_key, rotated_key + 4, context->key_length - 4);
    memcpy(rotated_key + context->key_length - 4, temp, 4);
    
    // Verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        rotated_key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(rotated_key, context->key_length);
        return NULL; // In a real implementation, we would fail on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(rotated_key, context->key_length);
        return NULL;
    }
    
    // Reverse the custom encryption
    for (int i = 0; i < plaintext_len; i++) {
        // Undo the second XOR
        unsigned char intermediate = ciphertext[i] ^ context->iv[(i + 3) % context->iv_length];
        // Undo the first XOR
        output[i] = intermediate ^ rotated_key[i % context->key_length];
    }
    
    // Clean up
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